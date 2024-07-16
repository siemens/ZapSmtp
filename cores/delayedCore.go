/*
* ZapSmtp, a Zap (Golang) logger extension for sending urgent log messages via SMTP
*
* Copyright (c) Siemens AG, 2021.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package cores

import (
	"fmt"
	"go.uber.org/multierr"
	"go.uber.org/zap/buffer"
	"go.uber.org/zap/zapcore"
	"sync"
	"time"
)

type delayedCore struct {
	zapcore.LevelEnabler
	enc zapcore.Encoder
	out zapcore.WriteSyncer

	priority           zapcore.LevelEnabler
	delay              time.Duration
	delayPriority      time.Duration
	entriesBuf         []*buffer.Buffer
	entriesPriorityBuf []*buffer.Buffer
	mutex              sync.Mutex
	timer              *time.Timer
	timeStart          time.Time
	errCh              chan error
}

// NewDelayedCore creates a zapcore.Core that writes logs after a given amount of time. It will write the
// logs quicker if it receives an entry satisfies the priority LevelEnabler. By calling Sync directly an immediate write
// of the messages can be forced.
func NewDelayedCore(
	enab zapcore.LevelEnabler,
	enc zapcore.Encoder,
	out zapcore.WriteSyncer,

	priority zapcore.LevelEnabler,
	delay time.Duration,
	delayPriority time.Duration,
) (zapcore.Core, error) {

	// Validate input to avoid accidental misconfiguration
	if delay < delayPriority {
		return nil, fmt.Errorf("priority delay lower than standard delay")
	}

	return &delayedCore{
		LevelEnabler:       enab,
		priority:           priority,
		enc:                enc,
		out:                out,
		delay:              delay,
		delayPriority:      delayPriority,
		entriesBuf:         make([]*buffer.Buffer, 0, 5),
		entriesPriorityBuf: make([]*buffer.Buffer, 0, 5),
		errCh:              make(chan error, 2),
	}, nil
}

// With is a reimplementation of ioCore.With because ioCore is not exported
func (c *delayedCore) With(fields []zapcore.Field) zapcore.Core {
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

func (c *delayedCore) Check(ent zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(ent.Level) || c.priority.Enabled(ent.Level) {
		return ce.AddCore(ent, c)
	}
	return ce
}

func (c *delayedCore) Write(ent zapcore.Entry, fields []zapcore.Field) error {

	// Encode the message
	buf, err := c.enc.EncodeEntry(ent, fields)
	if err != nil {
		return err
	}

	// Request mutex to avoid sending out partial messages
	c.mutex.Lock()

	// Start timer on first message
	startRoutine := false
	if len(c.entriesBuf) == 0 && len(c.entriesPriorityBuf) == 0 {
		// Start timer with the default (non priority) duration
		c.timeStart = time.Now()
		c.timer = time.NewTimer(c.delay)

		startRoutine = true
	}

	// Update the timer duration if this is the first entry with a priority level. In case the timer has already
	// expired, we would reset the it to a negative duration, because it is enforced that the priority delay is smaller
	// than the regular delay. A negative duration leads to the timer firing immediately.
	if c.priority.Enabled(ent.Level) && len(c.entriesPriorityBuf) == 0 {
		remainingDuration := c.delayPriority - time.Since(c.timeStart)
		c.timer.Reset(remainingDuration)
	}

	// Add message to queue
	if c.priority.Enabled(ent.Level) {
		c.entriesPriorityBuf = append(c.entriesPriorityBuf, buf)
	} else if c.Enabled(ent.Level) {
		c.entriesBuf = append(c.entriesBuf, buf)
	}

	// At this point we're not accessing the message slices anymore
	c.mutex.Unlock()

	// Since we may be crashing the program, sync the output. Ignore Sync
	// errors, pending a clean solution to issue #370.
	if ent.Level > zapcore.ErrorLevel {
		err := c.Sync()
		if err != nil {
			return err
		}
	}

	// Start a new goroutine for syncing after the timer expired
	if startRoutine {
		go func() {
			<-c.timer.C

			err := c.Sync()
			if err != nil {
				c.errCh <- err
			}
		}()
	}

	// Check if there are errors of a previous sync routines
	var errs error
loop:
	for {
		select {
		case err := <-c.errCh:
			errs = multierr.Append(errs, err)
		default:
			break loop
		}
	}

	return errs
}

// Sync will create and send the message to the writer
func (c *delayedCore) Sync() error {

	// Request mutex to avoid changes to messages while resetting everything
	c.mutex.Lock()

	// Combine the priority and standard messages and prepend a nice header.
	msg := make([]byte, 0, 1024*(len(c.entriesPriorityBuf)+len(c.entriesBuf))) // Assume a default log size of 1 KiB
	if len(c.entriesPriorityBuf) > 0 {
		msg = append(msg, []byte("=== Priority Log ===\n")...)
		for _, buf := range c.entriesPriorityBuf {
			msg = append(msg, buf.Bytes()...)
			buf.Free()
		}

		msg = append(msg, []byte("\n")...)
		msg = append(msg, []byte("\n")...)

		// Clear the slice but keep the allocated memory
		c.entriesPriorityBuf = c.entriesPriorityBuf[:0]
	}

	if len(c.entriesBuf) > 0 {
		msg = append(msg, []byte("=== Standard Log ===\n")...)
		for _, buf := range c.entriesBuf {
			msg = append(msg, buf.Bytes()...)
			buf.Free()
		}

		// Clear the slice but keep the allocated memory
		c.entriesBuf = c.entriesBuf[:0]
	}

	// At this point we're not accessing the message slices anymore
	c.mutex.Unlock()

	_, err := c.out.Write(msg)

	if err != nil {
		// Store message to be picked up by next call to core's Write method
		return err
	}

	return c.out.Sync()
}

func (c *delayedCore) clone() *delayedCore {
	return &delayedCore{
		LevelEnabler: c.LevelEnabler,
		priority:     c.priority,
		enc:          c.enc.Clone(),
		out:          c.out,
	}
}
