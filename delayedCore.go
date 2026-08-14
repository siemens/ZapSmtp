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
	"io"
	"os"
	"time"

	"go.uber.org/zap/buffer"
	"go.uber.org/zap/zapcore"
)

const maxBufferedEntries = 5000         // Maximum number of retained log entries
const errorReportInterval = time.Minute // Minimum interval between local background error reports

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

	// Reject non-positive durations because they would create immediate retry loops
	if delay <= 0 || delayPriority <= 0 {
		return nil, fmt.Errorf("delays must be greater than zero")
	}

	// Keep priority delivery at least as fast as standard delivery
	if delay < delayPriority {
		return nil, fmt.Errorf("priority delay must not exceed standard delay")
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

// run serializes every queue, timer, and flush transition for all cores sharing chSignal.
// A successful flush releases the complete batch and stops the timer. A failed flush retains the complete batch and
// schedules one next attempt; later failures can continue retrying, but only one timer is active at any time.
func (c *DelayedCore) run() {

	// Keep priority and standard entries separate so the output remains grouped by urgency
	var messagesStandard []*buffer.Buffer
	var messagesPriority []*buffer.Buffer

	// Keep a disabled select channel when no delivery is scheduled
	var timer *time.Timer
	var chTimer <-chan time.Time
	var timerDeadline time.Time

	// Rate-limit the two independent classes of local background warnings
	var lastFlushErrorReport time.Time
	var lastCacheErrorReport time.Time

	// Disable future delivery after a successful flush
	// Go 1.23 guarantees that Stop leaves no stale timer value available to receive.
	stopTimer := func() {
		if timer != nil {
			_ = timer.Stop()
		}
		chTimer = nil
		timerDeadline = time.Time{}
	}

	// Start or move the single timer used for initial delivery and retries
	// Go 1.23 permits Reset on an active, stopped, or expired timer without first draining its channel.
	scheduleTimer := func(duration time.Duration) {
		deadline := time.Now().Add(duration)
		if timer == nil {
			timer = time.NewTimer(duration)
		} else {
			_ = timer.Reset(duration)
		}
		chTimer = timer.C
		timerDeadline = deadline
	}

	// Report background failures locally without recursively using the affected logger
	reportError := func(lastReport *time.Time, message string, err error) {
		now := time.Now()
		if !lastReport.IsZero() && now.Sub(*lastReport) < errorReportInterval {
			return
		}
		*lastReport = now
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "ZapSMTP: %s: %q\n", message, err.Error())
			return
		}
		_, _ = fmt.Fprintf(os.Stderr, "ZapSMTP: %s\n", message)
	}

	// Count retained entries without duplicating queue state
	messageCount := func() int {
		return len(messagesPriority) + len(messagesStandard)
	}

	// Drop the newest non-priority entry first so a critical entry can remain retryable
	dropNewestBuffered := func() {
		if len(messagesStandard) > 0 {
			last := len(messagesStandard) - 1
			messagesStandard[last].Free()
			messagesStandard[last] = nil
			messagesStandard = messagesStandard[:last]
			return
		}
		last := len(messagesPriority) - 1
		messagesPriority[last].Free()
		messagesPriority[last] = nil
		messagesPriority = messagesPriority[:last]
	}

	// Flush the complete batch while retaining ownership of every buffer until Write and Sync both succeed
	flush := func() error {

		// Return if there are no buffered messages
		if len(messagesPriority) == 0 && len(messagesStandard) == 0 {
			return nil
		}

		// Combine the priority and standard messages prepended with a nice header
		payload := make([]byte, 0, 1024*(len(messagesPriority)+len(messagesStandard)))

		// Append priority messages
		if len(messagesPriority) > 0 {
			payload = append(payload, []byte("=== Priority Log ===\n")...)
			for _, buf := range messagesPriority {
				payload = append(payload, buf.Bytes()...)
			}
			payload = append(payload, []byte("\n\n")...)
		}

		// Append standard messages
		if len(messagesStandard) > 0 {
			payload = append(payload, []byte("=== Standard Log ===\n")...)
			for _, buf := range messagesStandard {
				payload = append(payload, buf.Bytes()...)
			}
		}

		// Write the aggregate and reject incomplete writer contracts
		written, errWrite := c.writeSyncer.Write(payload)
		if errWrite != nil {
			return errWrite
		}
		if written != len(payload) {
			return io.ErrShortWrite
		}

		// Sync out to make sure messages are written (might be an empty function depending on writeSyncer)
		errSync := c.writeSyncer.Sync()
		if errSync != nil {
			return errSync
		}

		// Free buffers only after a successful write
		for i, buf := range messagesPriority {
			buf.Free()
			messagesPriority[i] = nil
		}
		for i, buf := range messagesStandard {
			buf.Free()
			messagesStandard[i] = nil
		}

		// Clear the slices without retaining references to buffers returned to zap's pool
		messagesPriority = messagesPriority[:0]
		messagesStandard = messagesStandard[:0]

		// Return nil as everything went fine
		return nil
	}

	// Apply the same timer invariant after every explicit, threshold, or timed flush attempt
	finishFlush := func(errFlush error, reportBackgroundError bool) {
		if errFlush == nil {
			stopTimer()
			return
		}
		if reportBackgroundError {
			reportError(&lastFlushErrorReport, "Could not flush delayed logs", errFlush)
		}
		scheduleTimer(c.delayPriority)
	}

	// Keep looping to observe messages and handle timed syncs
	for {
		select {
		case sig := <-c.chSignal:

			// Distinguish pure queueing, explicit Sync, and critical entries requesting an immediate flush
			flushRequested := sig.chFlushResult != nil
			criticalEntry := sig.entryEncoded != nil && flushRequested

			// Queue the message while enforcing a hard entry limit
			entryQueued := false
			if sig.entryEncoded != nil {
				if messageCount() >= maxBufferedEntries && criticalEntry {
					dropNewestBuffered()
					reportError(&lastCacheErrorReport, "Delayed log cache is full. Dropping newest buffered entry to retain a critical entry.", nil)
				}
				if messageCount() >= maxBufferedEntries {
					sig.entryEncoded.Free()
					reportError(&lastCacheErrorReport, "Delayed log cache is full. Dropping newest entry.", nil)
				} else if sig.entryPriority {
					messagesPriority = append(messagesPriority, sig.entryEncoded)
					entryQueued = true
				} else {
					messagesStandard = append(messagesStandard, sig.entryEncoded)
					entryQueued = true
				}
			}

			// Handle immediate flush requests (from Sync or critical log levels)
			if flushRequested {

				// Flush and complete the timer transition before unblocking the caller
				errFlush := flush()
				finishFlush(errFlush, false)
				sig.chFlushResult <- errFlush

				// Listen for next case
				continue
			}

			// Flush at the hard cache limit instead of retaining a larger batch
			if entryQueued && messageCount() == maxBufferedEntries {

				// Flush once and retain one retry timer if delivery is unavailable
				errFlush := flush()
				finishFlush(errFlush, true)

				// Listen for next case
				continue
			}

			// Let a priority entry shorten an active delivery or retry deadline, but never postpone it
			if entryQueued && chTimer != nil && sig.entryPriority {

				// Shorten the current deadline without postponing an earlier retry
				priorityDeadline := time.Now().Add(c.delayPriority)
				if priorityDeadline.Before(timerDeadline) {
					scheduleTimer(c.delayPriority)
				}

				// Listen for next case
				continue
			}

			// Start a new timer if none is running
			if entryQueued && chTimer == nil {

				// Decide timer duration
				duration := c.delay
				if sig.entryPriority {
					duration = c.delayPriority
				}

				// Schedule the initial delivery
				scheduleTimer(duration)

				// Listen for next case
				continue
			}

		case <-chTimer:

			// Flush all queued messages and preserve the one-timer invariant for any retry
			errFlush := flush()
			finishFlush(errFlush, true)
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
