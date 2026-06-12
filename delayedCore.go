/*
* ZapSmtp, a Zap (Golang) logger extension for sending urgent log messages via SMTP
*
* Copyright (c) Siemens AG, 2021-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package ZapSmtp

import (
	"fmt"
	"time"

	"go.uber.org/zap/buffer"
	"go.uber.org/zap/zapcore"
)

// signal is sent from Write to the background goroutine to deliver a log message or request a flush.
type signal struct {
	entryEncoded  *buffer.Buffer // Encoded log message to queue
	entryPriority bool           // Whether the message satisfies the priority LevelEnabler
	chFlushResult chan<- error   // If not nil, an immediate flush is requested and the result is sent back
}

// DelayedCore is a zapcore.Core that collects log messages and writes them in bulk after a configurable delay.
// Messages satisfying a priority LevelEnabler shorten the delay so that critical logs are delivered sooner.
type DelayedCore struct {

	// Required to fulfill core interface
	zapcore.LevelEnabler
	encoder     zapcore.Encoder
	writeSyncer zapcore.WriteSyncer

	// Internal attributes of the delayed core
	levelEnablerPriority zapcore.LevelEnabler
	delay                time.Duration
	delayPriority        time.Duration

	chSignal chan signal // Channel to deliver log messages and flush requests to the background goroutine
}

// NewDelayedCore creates a zapcore.Core that writes logs after a given amount of time.
// It will write the logs quicker if a received entry satisfies the priority LevelEnabler.
// By calling Sync directly an immediate write of the messages can be forced.
func NewDelayedCore(
	level zapcore.LevelEnabler,
	encoder zapcore.Encoder,
	writeSyncer zapcore.WriteSyncer,
	levelPriority zapcore.LevelEnabler,
	delay time.Duration,
	delayPriority time.Duration,
) (*DelayedCore, error) {

	// Validate input to avoid accidental misconfiguration
	if delay < delayPriority {
		return nil, fmt.Errorf("priority delay lower than standard delay")
	}

	// Initialize delayed core
	core := &DelayedCore{
		LevelEnabler:         level,
		levelEnablerPriority: levelPriority,
		encoder:              encoder,
		writeSyncer:          writeSyncer,
		delay:                delay,
		delayPriority:        delayPriority,
		chSignal:             make(chan signal, 64),
	}

	// Start background goroutine that owns all timer and sync logic
	go core.run()

	// Return nil as everything went fine
	return core, nil
}

// run is the background goroutine that owns all timer, queue, and flush logic. It waits for signals from Write
// and Sync, manages the flush timer, and retries failed flushes with a short backoff.
func (c *DelayedCore) run() {

	// Message queues are owned exclusively by this goroutine, no mutex needed
	var messages []*buffer.Buffer
	var messagesPriority []*buffer.Buffer

	// Timer state is owned exclusively by this goroutine, no mutex needed
	var timer *time.Timer
	var timerStartedAt time.Time
	var hasPriority = false

	// Prepare channel for the timer signal.
	// As long as this channel is nil, no timer is active and no sync is planned
	var chTimer <-chan time.Time

	// flush writes all queued messages to the output and clears the queues.
	flush := func() error {

		// Return if there are no buffered messages
		if len(messagesPriority) == 0 && len(messages) == 0 {
			return nil
		}

		// Combine the priority and standard messages prepended with a nice header
		msg := make([]byte, 0, 1024*(len(messagesPriority)+len(messages)))

		// Append priority messages
		if len(messagesPriority) > 0 {
			msg = append(msg, []byte("=== Priority Log ===\n")...)
			for _, buf := range messagesPriority {
				msg = append(msg, buf.Bytes()...)
			}
			msg = append(msg, []byte("\n")...)
			msg = append(msg, []byte("\n")...)
		}

		// Append standard messages
		if len(messages) > 0 {
			msg = append(msg, []byte("=== Standard Log ===\n")...)
			for _, buf := range messages {
				msg = append(msg, buf.Bytes()...)
			}
		}

		// Write message
		_, errWrite := c.writeSyncer.Write(msg)
		if errWrite != nil {
			return errWrite
		}

		// Sync out to make sure messages are written (might be an empty function depending on writeSyncer)
		errSync := c.writeSyncer.Sync()
		if errSync != nil {
			return errSync
		}

		// Free buffers only after a successful write
		for _, buf := range messagesPriority {
			buf.Free()
		}
		for _, buf := range messages {
			buf.Free()
		}

		// Clear the slices after a successful write but keep the allocated memory
		messagesPriority = messagesPriority[:0]
		messages = messages[:0]

		// Return nil as everything went fine
		return nil
	}

	// Keep looping to observe messages and handle timed syncs
	for {
		select {
		case sig := <-c.chSignal:

			// Queue the message if one was delivered
			if sig.entryEncoded != nil {
				if sig.entryPriority {
					messagesPriority = append(messagesPriority, sig.entryEncoded)
				} else {
					messages = append(messages, sig.entryEncoded)
				}
			}

			// Handle immediate flush requests (from Sync or critical log levels)
			if sig.chFlushResult != nil {

				// Flush
				errFlush := flush()

				// Return flush result to the caller
				sig.chFlushResult <- errFlush

				// Reset the timer state on success.
				// Keep it otherwise, so that retries are handled by the expiring timer.
				if errFlush == nil {
					hasPriority = false
					timerStartedAt = time.Time{}
					if timer != nil {
						timer.Stop()
						chTimer = nil
					}
				}

				// Listen for next case
				continue
			}

			// Flush immediately if SMTP delivery might not be guaranteed anymore
			if len(messages)+len(messagesPriority) >= 5000 {

				// Flush
				errFlush := flush()

				// Reset the timer state on success.
				// Keep it otherwise, so that retries are handled by the expiring timer.
				if errFlush == nil {
					hasPriority = false
					timerStartedAt = time.Time{}
					if timer != nil {
						timer.Stop()
						chTimer = nil
					}
				}

				// Listen for next case
				continue
			}

			// Shorten a remaining delay if this is the first priority message while a timer is already running.
			// A negative remaining duration is clamped to zero to trigger immediately.
			if chTimer != nil && !hasPriority && sig.entryPriority {

				// Set priority mode
				hasPriority = true

				// Shorten timer if it has more time remaining than delayPriority
				remaining := timerStartedAt.Add(c.delay).Sub(time.Now())
				if remaining > c.delayPriority {
					timer.Reset(c.delayPriority)
				}

				// Listen for next case
				continue
			}

			// Start a new timer if none is running
			if chTimer == nil {

				// Set timer start timestamp
				timerStartedAt = time.Now()

				// Set priority mode if necessary
				hasPriority = sig.entryPriority

				// Decide timer duration
				duration := c.delay
				if hasPriority {
					duration = c.delayPriority
				}

				// Create or set timer.
				// The timer is reused, it only needs to be set the first time
				if timer == nil {
					timer = time.NewTimer(duration)
				} else {
					timer.Reset(duration)
				}

				// Set the timer channel to trigger syncs
				chTimer = timer.C

				// Listen for next case
				continue
			}

		case <-chTimer:

			// Flush all queued messages
			errFlush := flush()

			// In case of error retry after some delay
			if errFlush != nil {

				// Reset timer
				timerStartedAt = time.Now()
				timer.Reset(c.delayPriority)

				// Listen for next case
				continue
			}

			// Reset state, because we just flushed successfully
			hasPriority = false
			timerStartedAt = time.Time{}
			chTimer = nil
		}
	}
}

// Write serializes the entry and any fields and adds them to the log buffer.
// Buffered logs are not yet written, they will be written in bulk when the timer fires or Sync() is called.
//
// If called, it should not replicate the logic of Check(), but always add the message.
func (c *DelayedCore) Write(entry zapcore.Entry, fields []zapcore.Field) error {

	// Encode the message
	entryEncoded, errEntryEncoded := c.encoder.EncodeEntry(entry, fields)
	if errEntryEncoded != nil {
		return errEntryEncoded
	}

	// Determine priority
	priority := c.levelEnablerPriority.Enabled(entry.Level)

	// For critical log levels (DPanic, Panic, Fatal), flush immediately and wait for the result,
	// because the program may be about to crash. https://github.com/uber-go/zap/issues/500
	if entry.Level > zapcore.ErrorLevel {
		chFlushResult := make(chan error, 1)
		c.chSignal <- signal{entryEncoded: entryEncoded, entryPriority: priority, chFlushResult: chFlushResult}
		return <-chFlushResult
	}

	// Send the encoded message to the background goroutine for queuing
	c.chSignal <- signal{entryEncoded: entryEncoded, entryPriority: priority}

	// Return nil as everything went fine
	return nil
}

// Sync flushes buffered logs (if any). Blocks until all queued messages have been written.
func (c *DelayedCore) Sync() error {

	// Signal the background goroutine to flush and wait for the result
	chFlushResult := make(chan error, 1)
	c.chSignal <- signal{chFlushResult: chFlushResult}

	return <-chFlushResult
}

// Check determines whether the supplied Entry should be logged. If the entry
// should be logged, the Core adds itself to the CheckedEntry and returns
// the result.
//
// Callers must use Check before calling Write.
func (c *DelayedCore) Check(ent zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(ent.Level) || c.levelEnablerPriority.Enabled(ent.Level) {
		return ce.AddCore(ent, c)
	}
	return ce
}

// With is a reimplementation of ioCore.With because ioCore is not exported
func (c *DelayedCore) With(fields []zapcore.Field) zapcore.Core {

	// Clone the core and add the fields to the cloned encoder
	clone := c.clone()
	for i := range fields {
		fields[i].AddTo(clone.encoder)
	}

	return clone
}

// clone creates a shallow copy of the DelayedCore sharing the same output writer and signal channel.
func (c *DelayedCore) clone() *DelayedCore {
	return &DelayedCore{
		LevelEnabler:         c.LevelEnabler,
		levelEnablerPriority: c.levelEnablerPriority,
		encoder:              c.encoder.Clone(),
		writeSyncer:          c.writeSyncer,
		chSignal:             c.chSignal,
	}
}
