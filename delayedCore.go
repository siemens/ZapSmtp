/*
* ZapSmtp, a Zap (Golang) logger extension for sending urgent log messages via SMTP
*
* Copyright (c) Siemens AG, 2021.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package ZapSmtp

import (
	"fmt"
	"go.uber.org/multierr"
	"go.uber.org/zap/buffer"
	"go.uber.org/zap/zapcore"
	"sync"
	"time"
)

type DelayedCore struct {
	// Required to fulfill core interface
	zapcore.LevelEnabler
	enc zapcore.Encoder
	out zapcore.WriteSyncer

	// Internal attributes of the delayed core
	priority         zapcore.LevelEnabler
	messages         []*buffer.Buffer // Log messages queued for writing
	messagesPriority []*buffer.Buffer // Log messages queued for priority writing
	delay            time.Duration
	delayPriority    time.Duration

	mutex          sync.Mutex  // Mutex to control access to messages
	timer          *time.Timer // Timer triggering the writeSyncer after exceeding
	timerStartedAt time.Time   // Marker of when the timer started
	errCh          chan error  // Channel for asynchronous Sync calls to notify about errors
}

// NewDelayedCore creates a zapcore.Core that writes logs after a given amount of time.
// It will write the logs quicker if a received entry satisfies the priority LevelEnabler.
// By calling Sync directly an immediate write of the messages can be forced.
func NewDelayedCore(
	enabler zapcore.LevelEnabler,
	enc zapcore.Encoder,
	out zapcore.WriteSyncer,

	priority zapcore.LevelEnabler,
	delay time.Duration,
	delayPriority time.Duration,
) (*DelayedCore, error) {

	// Validate input to avoid accidental misconfiguration
	if delay < delayPriority {
		return nil, fmt.Errorf("priority delay lower than standard delay")
	}

	// Return delayed core
	return &DelayedCore{
		LevelEnabler:     enabler,
		priority:         priority,
		enc:              enc,
		out:              out,
		delay:            delay,
		delayPriority:    delayPriority,
		messages:         make([]*buffer.Buffer, 0, 5),
		messagesPriority: make([]*buffer.Buffer, 0, 5),
		errCh:            make(chan error, 2),
	}, nil
}

// With is a reimplementation of ioCore.With because ioCore is not exported
func (c *DelayedCore) With(fields []zapcore.Field) zapcore.Core {
	clone := c.clone()
	addFields(clone.enc, fields)
	return clone
}

// addFields is a reimplementation of ioCore.addFields because ioCore is not exported
func addFields(enc zapcore.ObjectEncoder, fields []zapcore.Field) {
	for i := range fields {
		fields[i].AddTo(enc)
	}
}

// Check determines whether the supplied Entry should be logged. If the entry
// should be logged, the Core adds itself to the CheckedEntry and returns
// the result.
//
// Callers must use Check before calling Write.
func (c *DelayedCore) Check(ent zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(ent.Level) || c.priority.Enabled(ent.Level) {
		return ce.AddCore(ent, c)
	}
	return ce
}

// Write serializes the entry and any fields and adds them to the log buffer.
// Buffered logs are not yet written, they will be written in bulks on Sync().
//
// If called, it should not replicate the logic of Check(), but always add the message.
func (c *DelayedCore) Write(ent zapcore.Entry, fields []zapcore.Field) error {

	// Encode the message
	buf, errEncode := c.enc.EncodeEntry(ent, fields)
	if errEncode != nil {
		return errEncode
	}

	// Request mutex to avoid sending partial messages
	c.mutex.Lock()

	// Start timer on first message
	startRoutine := false
	if len(c.messages) == 0 && len(c.messagesPriority) == 0 {

		// Start timer with the default (non priority) duration
		c.timerStartedAt = time.Now()
		c.timer = time.NewTimer(c.delay)
		startRoutine = true
	}

	// Check whether timer needs to execute sooner
	if len(c.messages)+len(c.messagesPriority) >= 1000 {

		// Cached messages are getting too much, SMTP delivery might not be guaranteed anymore, send messages now.
		// A negative duration leads to the timer firing immediately.
		c.timer.Reset(-1)

	} else if c.priority.Enabled(ent.Level) && len(c.messagesPriority) == 0 {

		// Update the timer duration if this is the first entry with a priority level. In case the timer has already
		// expired, we would reset it to a negative duration, because it is enforced that the priority delay is smaller
		// than the regular delay. A negative duration leads to the timer firing immediately.
		remainingDuration := c.delayPriority - time.Since(c.timerStartedAt)
		c.timer.Reset(remainingDuration)
	}

	// Add message to queue
	if c.priority.Enabled(ent.Level) {
		c.messagesPriority = append(c.messagesPriority, buf)
	} else if c.Enabled(ent.Level) {
		c.messages = append(c.messages, buf)
	}

	// At this point we're not accessing the message buffer anymore
	c.mutex.Unlock()

	// Since we may be crashing the program, sync the output. Ignore Sync
	// errors, pending a clean solution to issue #370.
	// https://github.com/uber-go/zap/issues/500
	if ent.Level > zapcore.ErrorLevel {
		errSync := c.Sync()
		if errSync != nil {
			return errSync
		}
	}

	// Start a new goroutine for syncing after the timer expired.
	if startRoutine {
		go func() {
			<-c.timer.C

			errSync := c.Sync()
			if errSync != nil {
				c.errCh <- errSync
			}
		}()
	}

	// Return nil as everything went fine
	return nil
}

// Sync flushes buffered logs (if any). Will create and send the message to the writer.
func (c *DelayedCore) Sync() error {

	// Request mutex to avoid changes to messages while resetting everything
	c.mutex.Lock()

	// Return if there are no buffered messages, in case of race conditions
	if len(c.messagesPriority) == 0 && len(c.messages) == 0 {
		c.mutex.Unlock()
		return nil
	}

	// Combine the priority and standard messages prepended with a nice header
	msg := make([]byte, 0, 1024*(len(c.messagesPriority)+len(c.messages))) // Assume a default log size of 1 KiB

	// Append Priority messages
	if len(c.messagesPriority) > 0 {
		msg = append(msg, []byte("=== Priority Log ===\n")...)
		for _, buf := range c.messagesPriority {
			msg = append(msg, buf.Bytes()...)
			buf.Free()
		}

		msg = append(msg, []byte("\n")...)
		msg = append(msg, []byte("\n")...)
	}

	// Append standard messages
	if len(c.messages) > 0 {
		msg = append(msg, []byte("=== Standard Log ===\n")...)
		for _, buf := range c.messages {
			msg = append(msg, buf.Bytes()...)
			buf.Free()
		}
	}

	// Write message
	_, errWrite := c.out.Write(msg)
	if errWrite != nil {
		c.mutex.Unlock()
		return errWrite
	}

	// Sync out to make sure messages are written (might be an empty function depending on writeSyncer)
	errSync := c.out.Sync()
	if errSync != nil {
		c.mutex.Unlock()
		return errSync
	}

	// Clear the slice after a successful write but keep the allocated memory
	c.messagesPriority = c.messagesPriority[:0]
	c.messages = c.messages[:0]

	// At this point we're not accessing the message buffer anymore
	c.mutex.Unlock()

	// Check if previous timed sync runs (asynchronous) had errors
	var errSyncTimed error
loop:
	for {
		select {
		case e := <-c.errCh:
			errSyncTimed = multierr.Append(errSyncTimed, e)
		default:
			break loop
		}
	}
	if errSyncTimed != nil {
		return errSyncTimed
	}

	// Return nil if everything went fine
	return nil
}

func (c *DelayedCore) clone() *DelayedCore {
	return &DelayedCore{
		LevelEnabler: c.LevelEnabler,
		priority:     c.priority,
		enc:          c.enc.Clone(),
		out:          c.out,
	}
}
