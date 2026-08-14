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
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
	. "go.uber.org/zap/zapcore"
)

// Syncer is a spy for the Sync portion of zapcore.WriteSyncer.
type Syncer struct {
	err    error
	called atomic.Bool
}

// SetError sets the error that the Sync method will return.
func (s *Syncer) SetError(err error) {
	s.err = err
}

// Sync records that it was called, then returns the user-supplied error (if any).
func (s *Syncer) Sync() error {
	s.called.Store(true)

	// Return the configured synchronization error
	return s.err
}

// Called reports whether the Sync method was called.
func (s *Syncer) Called() bool {
	return s.called.Load()
}

// Discarder sends all writes to io.Discard.
type Discarder struct{ Syncer }

// Write implements io.Writer.
func (d *Discarder) Write(b []byte) (int, error) {
	return io.Discard.Write(b)
}

// OneTimeFailWriter is a WriteSyncer that returns an error on the first write.
type OneTimeFailWriter struct {
	Syncer
	sync.Once
	chSuccess chan struct{}
}

// Write implements io.Writer.
func (w *OneTimeFailWriter) Write(b []byte) (int, error) {

	var errWrite error
	w.Do(func() { errWrite = fmt.Errorf("failed") })
	if errWrite == nil && w.chSuccess != nil {
		select {
		case w.chSuccess <- struct{}{}:
		default:
		}
	}

	// Return the processed byte count and transient error
	return len(b), errWrite
}

// ControlledWriter records writes and returns an error while failure mode is enabled.
type ControlledWriter struct {
	Syncer
	fail       atomic.Bool
	writeCount atomic.Int64
	mutex      sync.Mutex
	lastWrite  []byte
	chWrite    chan []byte
}

// SetFail controls whether writes return an error.
func (writer *ControlledWriter) SetFail(fail bool) {
	writer.fail.Store(fail)
}

// Write records the payload and returns the configured result.
func (writer *ControlledWriter) Write(payload []byte) (int, error) {

	// Record the call and retain an isolated copy for assertions
	writer.writeCount.Add(1)
	payloadCopy := append([]byte(nil), payload...)
	writer.mutex.Lock()
	writer.lastWrite = append(writer.lastWrite[:0], payloadCopy...)
	writer.mutex.Unlock()
	if writer.chWrite != nil {
		select {
		case writer.chWrite <- payloadCopy:
		default:
		}
	}

	// Return a deterministic delivery error while failure mode is active
	if writer.fail.Load() {
		return 0, fmt.Errorf("delivery unavailable")
	}

	// Return the processed payload length
	return len(payload), nil
}

// WriteCount returns the number of attempted writes.
func (writer *ControlledWriter) WriteCount() int64 {
	return writer.writeCount.Load()
}

// LastWrite returns an isolated copy of the most recent payload.
func (writer *ControlledWriter) LastWrite() []byte {

	// Copy the payload while holding the writer lock
	writer.mutex.Lock()
	defer writer.mutex.Unlock()

	// Return an isolated value for assertions
	return append([]byte(nil), writer.lastWrite...)
}

// BlockingOnceWriter holds the first write past a timer deadline and reports every later write.
type BlockingOnceWriter struct {
	Syncer
	writeCount atomic.Int64
	chStarted  chan struct{}
	chRelease  <-chan struct{}
	chWrite    chan []byte
}

// Write blocks the first attempt until released so tests can expire a timer while the worker is flushing.
func (writer *BlockingOnceWriter) Write(payload []byte) (int, error) {

	// Hold only the first write and tell the test exactly when the worker becomes blocked
	if writer.writeCount.Add(1) == 1 {
		close(writer.chStarted)
		<-writer.chRelease
	} else {
		writer.chWrite <- append([]byte(nil), payload...)
	}

	// Accept the complete payload after any deliberate block
	return len(payload), nil
}

// ShortWriteOnceWriter reports one short write before accepting the same payload completely.
type ShortWriteOnceWriter struct {
	Syncer
	writeCount atomic.Int64
	mutex      sync.Mutex
	payloads   [][]byte
	chSuccess  chan struct{}
}

// Write records every payload and reports a short first attempt without an explicit error.
func (writer *ShortWriteOnceWriter) Write(payload []byte) (int, error) {

	// Retain independent payload copies so the retry can be compared with the first attempt
	payloadCopy := append([]byte(nil), payload...)
	writer.mutex.Lock()
	writer.payloads = append(writer.payloads, payloadCopy)
	writer.mutex.Unlock()

	// Simulate an incomplete writer contract on the first attempt
	if writer.writeCount.Add(1) == 1 {
		return len(payload) - 1, nil
	}

	// Notify the test after the retained batch is accepted completely
	select {
	case writer.chSuccess <- struct{}{}:
	default:
	}

	// Return the complete payload length
	return len(payload), nil
}

// Payloads returns isolated copies of every attempted payload.
func (writer *ShortWriteOnceWriter) Payloads() [][]byte {

	// Copy all recorded attempts while holding the writer lock
	writer.mutex.Lock()
	defer writer.mutex.Unlock()
	payloads := make([][]byte, len(writer.payloads))
	for i, payload := range writer.payloads {
		payloads[i] = append([]byte(nil), payload...)
	}

	// Return the isolated attempt history
	return payloads
}

// OneTimeFailSyncWriter accepts every write but fails its first synchronization.
type OneTimeFailSyncWriter struct {
	writeCount atomic.Int64
	syncCount  atomic.Int64
	mutex      sync.Mutex
	payloads   [][]byte
	chSuccess  chan struct{}
}

// Write records the payload as accepted before synchronization is attempted.
func (writer *OneTimeFailSyncWriter) Write(payload []byte) (int, error) {

	// Retain an isolated attempt history for retry assertions
	writer.writeCount.Add(1)
	writer.mutex.Lock()
	writer.payloads = append(writer.payloads, append([]byte(nil), payload...))
	writer.mutex.Unlock()

	// Report a complete write
	return len(payload), nil
}

// Sync fails once and then reports the successful retry to the test.
func (writer *OneTimeFailSyncWriter) Sync() error {

	// Preserve the first synchronization failure that keeps the batch retryable
	if writer.syncCount.Add(1) == 1 {
		return fmt.Errorf("sync unavailable")
	}

	// Notify the test after a later synchronization succeeds
	select {
	case writer.chSuccess <- struct{}{}:
	default:
	}

	// Return nil after recovery
	return nil
}

// Payloads returns isolated copies of every write preceding synchronization.
func (writer *OneTimeFailSyncWriter) Payloads() [][]byte {

	// Copy all recorded attempts while holding the writer lock
	writer.mutex.Lock()
	defer writer.mutex.Unlock()
	payloads := make([][]byte, len(writer.payloads))
	for i, payload := range writer.payloads {
		payloads[i] = append([]byte(nil), payload...)
	}

	// Return the isolated attempt history
	return payloads
}

// testEncoderConfig returns a JSON encoder config suitable for test assertions.
func testEncoderConfig() EncoderConfig {
	return EncoderConfig{
		MessageKey:     "msg",
		LevelKey:       "level",
		NameKey:        "name",
		TimeKey:        "ts",
		CallerKey:      "caller",
		FunctionKey:    "func",
		StacktraceKey:  "stacktrace",
		LineEnding:     "\n",
		EncodeTime:     EpochTimeEncoder,
		EncodeLevel:    LowercaseLevelEncoder,
		EncodeDuration: SecondsDurationEncoder,
		EncodeCaller:   ShortCallerEncoder,
	}
}

// makeInt64Field creates a zap Field with the given key and integer value.
func makeInt64Field(key string, val int) Field {
	return Field{Type: Int64Type, Integer: int64(val), Key: key}
}

// TestDelayedCore_WithClonedCore_WritesGroupedOutput verifies that messages written via a cloned core produce
// grouped output with priority and standard sections
func TestDelayedCore_WithClonedCore_WritesGroupedOutput(t *testing.T) {

	// Drop timestamps for simpler assertions (timestamp encoding is tested elsewhere)
	cfg := testEncoderConfig()
	cfg.TimeKey = ""

	// Prepare out, which is a simple temporary file
	tmpOut, errTmpOut := os.CreateTemp("", "zap-test-delayed-core-*")
	if errTmpOut != nil {
		t.Errorf("os.CreateTemp() error = '%v', want = nil", errTmpOut)
		return
	}
	defer func() {
		_ = tmpOut.Close()
		_ = os.Remove(tmpOut.Name())
	}()

	// Prepare core
	delayedCore, errDelayedCore := NewDelayedCore(
		InfoLevel,
		NewJSONEncoder(cfg),
		tmpOut,
		WarnLevel,
		time.Second*4,
		time.Second*2,
	)
	if errDelayedCore != nil {
		t.Errorf("NewDelayedCore() error = '%v', want = nil", errDelayedCore)
		return
	}

	// Clone the core with baked-in fields
	delayedCoreWith := delayedCore.With([]Field{makeInt64Field("k", 1)})

	// Verify that Sync on an idle core succeeds
	errSync := delayedCore.Sync()
	if errSync != nil {
		t.Errorf("Sync() error = '%v', want = nil", errSync)
		return
	}

	// Write test messages via the cloned core (which has the "k":1 field baked in)
	if ce := delayedCoreWith.Check(Entry{Level: DebugLevel, Message: "debug"}, nil); ce != nil {
		ce.Write(makeInt64Field("k", 2))
	}
	if ce := delayedCoreWith.Check(Entry{Level: InfoLevel, Message: "info"}, nil); ce != nil {
		ce.Write(makeInt64Field("k", 3))
	}
	if ce := delayedCoreWith.Check(Entry{Level: WarnLevel, Message: "warn"}, nil); ce != nil {
		ce.Write(makeInt64Field("k", 4))
	}

	// Flush deterministically after all writes reached the shared worker
	errSync = delayedCore.Sync()
	if errSync != nil {
		t.Errorf("Sync() error = '%v', want = nil", errSync)
		return
	}

	// Define wanted output
	want := []byte("=== Priority Log ===\n" +
		`{"level":"warn","msg":"warn","k":1,"k":4}` + "\n" +
		"\n\n" +
		"=== Standard Log ===\n" +
		`{"level":"info","msg":"info","k":1,"k":3}` + "\n")

	// Verify logged output matches expected grouped format
	logged, errRead := os.ReadFile(tmpOut.Name())
	if errRead != nil {
		t.Errorf("os.ReadFile() error = '%v', want = nil", errRead)
		return
	}
	if !bytes.Equal(logged, want) {
		t.Errorf("output:\ngot:\n%s\nwant:\n%s", logged, want)
		return
	}
}

// TestDelayedCore_Sync_ReturnsSyncerError verifies that Sync propagates errors from the underlying WriteSyncer
func TestDelayedCore_Sync_ReturnsSyncerError(t *testing.T) {

	// Define test error
	errTest := fmt.Errorf("failed")

	// Prepare out, which just discards messages
	out := &Discarder{}
	out.SetError(errTest)

	// Prepare core
	delayedCore, errDelayedCore := NewDelayedCore(
		DebugLevel,
		NewJSONEncoder(testEncoderConfig()),
		out,
		WarnLevel,
		time.Second*4,
		time.Second*2,
	)
	if errDelayedCore != nil {
		t.Errorf("NewDelayedCore() error = '%v', want = nil", errDelayedCore)
		return
	}
	defer func() {
		out.SetError(nil)
		_ = delayedCore.Sync()
	}()

	// Add log message otherwise Sync would return immediately
	errWrite := delayedCore.Write(Entry{Level: WarnLevel}, nil)
	if errWrite != nil {
		t.Errorf("Write() error = '%v', want = nil", errWrite)
		return
	}

	// Verify that Sync returns the underlying syncer error
	errSync := delayedCore.Sync()
	if !errors.Is(errSync, errTest) {
		t.Errorf("Sync() error = '%v', want = '%v'", errSync, errTest)
		return
	}

	// Recover the syncer and clear the retained batch so this test leaves no active retry loop
	out.SetError(nil)
	errSyncRecovered := delayedCore.Sync()
	if errSyncRecovered != nil {
		t.Errorf("Sync() recovery error = '%v', want = nil", errSyncRecovered)
		return
	}
}

// TestDelayedCore_CriticalLevel_FlushesImmediately verifies that log entries above ErrorLevel trigger an immediate sync
func TestDelayedCore_CriticalLevel_FlushesImmediately(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name       string
		entry      Entry
		shouldSync bool
	}{
		{"debug-no-sync", Entry{Level: DebugLevel}, false},
		{"info-no-sync", Entry{Level: InfoLevel}, false},
		{"warn-no-sync", Entry{Level: WarnLevel}, false},
		{"error-no-sync", Entry{Level: ErrorLevel}, false},
		{"dpanic-immediate-sync", Entry{Level: DPanicLevel}, true},
		{"panic-immediate-sync", Entry{Level: PanicLevel}, true},
		{"fatal-immediate-sync", Entry{Level: FatalLevel}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Prepare out, which just discards messages
			out := &Discarder{}

			// Prepare core
			delayedCore, errDelayedCore := NewDelayedCore(
				DebugLevel,
				NewJSONEncoder(testEncoderConfig()),
				out,
				ErrorLevel,
				time.Minute*10, // Very long delay, so only panic and fatal lvl will be synced
				time.Minute*10, // Very long delay, so only panic and fatal lvl will be synced
			)
			if errDelayedCore != nil {
				t.Errorf("NewDelayedCore() error = '%v', want = nil", errDelayedCore)
				return
			}

			// Write entry
			_ = delayedCore.Write(tt.entry, nil)

			// Verify that Sync was called as expected
			if tt.shouldSync != out.Called() {
				t.Errorf("Syncer.Called() = '%v', want = '%v'", out.Called(), tt.shouldSync)
				return
			}

			// Clear any non-critical batch and stop its long-running timer before the subtest exits
			if errSync := delayedCore.Sync(); errSync != nil {
				t.Errorf("Sync() cleanup error = '%v', want = nil", errSync)
				return
			}
		})
	}
}

// TestDelayedCore_DelayedSync_FlushesAfterDelay verifies the delayed syncing triggered by a Write
func TestDelayedCore_DelayedSync_FlushesAfterDelay(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name       string
		entries    []Entry
		delay      time.Duration
		shouldSync bool
	}{
		{
			"info-after-standard-delay-syncs",
			[]Entry{{Level: InfoLevel}},
			time.Second * 4,
			true,
		}, // Log level is not checked by the write function
		{
			"debug-before-standard-delay-no-sync",
			[]Entry{{Level: DebugLevel}},
			time.Second,
			false,
		},
		{
			"debug-after-standard-delay-syncs",
			[]Entry{{Level: DebugLevel}},
			time.Second * 4,
			true,
		},
		{
			"warn-before-priority-delay-no-sync",
			[]Entry{{Level: WarnLevel}},
			time.Second,
			false,
		},
		{
			"warn-after-priority-delay-syncs",
			[]Entry{{Level: WarnLevel}},
			time.Second * 2,
			true,
		},
		{
			"debug-then-warn-before-priority-delay-no-sync",
			[]Entry{{Level: DebugLevel}, {Level: WarnLevel}},
			time.Second,
			false,
		},
		{
			"debug-then-warn-after-priority-delay-syncs",
			[]Entry{{Level: DebugLevel}, {Level: WarnLevel}},
			time.Second * 2,
			true,
		},
		{
			"warn-then-debug-before-priority-delay-no-sync",
			[]Entry{{Level: WarnLevel}, {Level: DebugLevel}},
			time.Second,
			false,
		},
		{
			"warn-then-debug-after-priority-delay-syncs",
			[]Entry{{Level: WarnLevel}, {Level: DebugLevel}},
			time.Second * 2,
			true,
		},
		{
			"two-warn-before-priority-delay-no-sync",
			[]Entry{{Level: WarnLevel}, {Level: WarnLevel}},
			time.Second,
			false,
		},
		{
			"two-warn-after-priority-delay-syncs",
			[]Entry{{Level: WarnLevel}, {Level: WarnLevel}},
			time.Second * 2,
			true,
		},
		{
			"two-debug-before-standard-delay-no-sync",
			[]Entry{{Level: DebugLevel}, {Level: DebugLevel}},
			time.Second * 2,
			false,
		},
		{
			"two-debug-after-standard-delay-syncs",
			[]Entry{{Level: DebugLevel}, {Level: DebugLevel}},
			time.Second * 4,
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Allow tests to run in parallel to save time on the hardcoded wait times
			t.Parallel()

			// Prepare out, which just discards messages
			out := &Discarder{}

			// Prepare core
			delayedCore, errDelayedCore := NewDelayedCore(
				DebugLevel,
				NewJSONEncoder(testEncoderConfig()),
				out,
				WarnLevel,
				time.Second*4,
				time.Second*2,
			)
			if errDelayedCore != nil {
				t.Errorf("NewDelayedCore() error = '%v', want = nil", errDelayedCore)
				return
			}

			// Write entries
			for _, entry := range tt.entries {
				_ = delayedCore.Write(entry, nil)
			}

			// Keep a broad scheduling margin on both sides of the configured two- and four-second deadlines
			time.Sleep(tt.delay + time.Millisecond*500)

			// Verify that Sync was called as expected
			if tt.shouldSync != out.Called() {
				t.Errorf("Syncer.Called() = '%v', want = '%v'", out.Called(), tt.shouldSync)
			}

			// Clear any batch whose timer intentionally had not expired during the assertion window
			if errSync := delayedCore.Sync(); errSync != nil {
				t.Errorf("Sync() cleanup error = '%v', want = nil", errSync)
				return
			}
		})
	}
}

// TestDelayedCore_InvalidDelay_ReturnsError verifies that NewDelayedCore rejects non-positive and inverted delays
func TestDelayedCore_InvalidDelay_ReturnsError(t *testing.T) {

	// Prepare and run invalid delay configurations
	tests := []struct {
		name          string
		delay         time.Duration
		delayPriority time.Duration
	}{
		{name: "standard-shorter-than-priority", delay: time.Second, delayPriority: time.Second * 2},
		{name: "zero-delays", delay: 0, delayPriority: 0},
		{name: "negative-delays", delay: -time.Second, delayPriority: -time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Construct a core with the invalid delay pair
			_, errDelayedCore := NewDelayedCore(
				DebugLevel,
				NewJSONEncoder(testEncoderConfig()),
				&Discarder{},
				WarnLevel,
				tt.delay,
				tt.delayPriority,
			)

			// Verify invalid retry timing cannot create a tight loop
			if errDelayedCore == nil {
				t.Errorf("NewDelayedCore() error = nil, want error for delay '%v' and priority delay '%v'", tt.delay, tt.delayPriority)
				return
			}
		})
	}
}

// TestDelayedCore_SyncEmpty_ReturnsNil verifies that Sync on an empty queue returns nil
func TestDelayedCore_SyncEmpty_ReturnsNil(t *testing.T) {

	// Prepare core
	out := &ControlledWriter{}
	delayedCore, errDelayedCore := NewDelayedCore(
		DebugLevel,
		NewJSONEncoder(testEncoderConfig()),
		out,
		WarnLevel,
		time.Second*4,
		time.Second*2,
	)
	if errDelayedCore != nil {
		t.Errorf("NewDelayedCore() error = '%v', want = nil", errDelayedCore)
		return
	}

	// Verify that Sync returns nil when no messages are queued
	errSync := delayedCore.Sync()
	if errSync != nil {
		t.Errorf("Sync() error = '%v', want = nil", errSync)
		return
	}
	if writeCount := out.WriteCount(); writeCount != 0 {
		t.Errorf("WriteSyncer.Write() call count = '%d', want = '0'", writeCount)
		return
	}
	if out.Called() {
		t.Error("WriteSyncer.Sync() called = true, want = false")
		return
	}
}

// TestDelayedCore_Check_RejectsDisabledLevel verifies that Check does not add the core for levels below both enablers
func TestDelayedCore_Check_RejectsDisabledLevel(t *testing.T) {

	// Prepare core with InfoLevel as standard and WarnLevel as priority
	delayedCore, errDelayedCore := NewDelayedCore(
		InfoLevel,
		NewJSONEncoder(testEncoderConfig()),
		&Discarder{},
		WarnLevel,
		time.Second*4,
		time.Second*2,
	)
	if errDelayedCore != nil {
		t.Errorf("NewDelayedCore() error = '%v', want = nil", errDelayedCore)
		return
	}

	// Verify that DebugLevel is rejected by Check (below both enablers)
	ce := delayedCore.Check(Entry{Level: DebugLevel, Message: "debug"}, nil)
	if ce != nil {
		t.Error("Check() returned non-nil CheckedEntry for DebugLevel, want nil")
		return
	}
}

// TestDelayedCore_Check_AcceptsPriorityOnlyLevel verifies that Check adds the core when the level
// satisfies only the priority enabler but not the standard enabler
func TestDelayedCore_Check_AcceptsPriorityOnlyLevel(t *testing.T) {

	// Prepare core with ErrorLevel as standard and InfoLevel as priority
	delayedCore, errDelayedCore := NewDelayedCore(
		ErrorLevel,
		NewJSONEncoder(testEncoderConfig()),
		&Discarder{},
		InfoLevel,
		time.Second*4,
		time.Second*2,
	)
	if errDelayedCore != nil {
		t.Errorf("NewDelayedCore() error = '%v', want = nil", errDelayedCore)
		return
	}

	// Verify that WarnLevel is accepted (below standard ErrorLevel but above priority InfoLevel)
	ce := delayedCore.Check(Entry{Level: WarnLevel, Message: "warn"}, nil)
	if ce == nil {
		t.Error("Check() returned nil for WarnLevel, want non-nil (priority enabler should accept)")
		return
	}
}

// TestDelayedCore_OnlyStandardMessages_OmitsPrioritySection verifies output format when no priority messages exist
func TestDelayedCore_OnlyStandardMessages_OmitsPrioritySection(t *testing.T) {

	// Drop timestamps for simpler assertions
	cfg := testEncoderConfig()
	cfg.TimeKey = ""

	// Prepare out, which is a simple temporary file
	tmpOut, errTmpOut := os.CreateTemp("", "zap-test-delayed-core-*")
	if errTmpOut != nil {
		t.Errorf("os.CreateTemp() error = '%v', want = nil", errTmpOut)
		return
	}
	defer func() {
		_ = tmpOut.Close()
		_ = os.Remove(tmpOut.Name())
	}()

	// Prepare core with WarnLevel as priority (only InfoLevel messages will be written)
	delayedCore, errDelayedCore := NewDelayedCore(
		InfoLevel,
		NewJSONEncoder(cfg),
		tmpOut,
		WarnLevel,
		time.Second*4,
		time.Second*2,
	)
	if errDelayedCore != nil {
		t.Errorf("NewDelayedCore() error = '%v', want = nil", errDelayedCore)
		return
	}

	// Write only a standard-level message
	errWrite := delayedCore.Write(Entry{Level: InfoLevel, Message: "info-only"}, nil)
	if errWrite != nil {
		t.Errorf("Write() error = '%v', want = nil", errWrite)
		return
	}

	// Flush immediately
	errSync := delayedCore.Sync()
	if errSync != nil {
		t.Errorf("Sync() error = '%v', want = nil", errSync)
		return
	}

	// Define wanted output (no priority section)
	want := []byte("=== Standard Log ===\n" +
		`{"level":"info","msg":"info-only"}` + "\n")

	// Verify output contains only the standard section
	logged, errRead := os.ReadFile(tmpOut.Name())
	if errRead != nil {
		t.Errorf("os.ReadFile() error = '%v', want = nil", errRead)
		return
	}
	if !bytes.Equal(logged, want) {
		t.Errorf("output:\ngot:\n%s\nwant:\n%s", logged, want)
		return
	}
}

// TestDelayedCore_OnlyPriorityMessages_OmitsStandardSection verifies output format when no standard messages exist
func TestDelayedCore_OnlyPriorityMessages_OmitsStandardSection(t *testing.T) {

	// Drop timestamps for simpler assertions
	cfg := testEncoderConfig()
	cfg.TimeKey = ""

	// Prepare out, which is a simple temporary file
	tmpOut, errTmpOut := os.CreateTemp("", "zap-test-delayed-core-*")
	if errTmpOut != nil {
		t.Errorf("os.CreateTemp() error = '%v', want = nil", errTmpOut)
		return
	}
	defer func() {
		_ = tmpOut.Close()
		_ = os.Remove(tmpOut.Name())
	}()

	// Prepare core with InfoLevel as priority (WarnLevel satisfies both standard and priority)
	delayedCore, errDelayedCore := NewDelayedCore(
		WarnLevel,
		NewJSONEncoder(cfg),
		tmpOut,
		InfoLevel,
		time.Second*4,
		time.Second*2,
	)
	if errDelayedCore != nil {
		t.Errorf("NewDelayedCore() error = '%v', want = nil", errDelayedCore)
		return
	}

	// Write only a priority-level message
	errWrite := delayedCore.Write(Entry{Level: WarnLevel, Message: "warn-only"}, nil)
	if errWrite != nil {
		t.Errorf("Write() error = '%v', want = nil", errWrite)
		return
	}

	// Flush immediately
	errSync := delayedCore.Sync()
	if errSync != nil {
		t.Errorf("Sync() error = '%v', want = nil", errSync)
		return
	}

	// Define wanted output (no standard section, with trailing newlines after priority)
	want := []byte("=== Priority Log ===\n" +
		`{"level":"warn","msg":"warn-only"}` + "\n" +
		"\n\n")

	// Verify output contains only the priority section
	logged, errRead := os.ReadFile(tmpOut.Name())
	if errRead != nil {
		t.Errorf("os.ReadFile() error = '%v', want = nil", errRead)
		return
	}
	if !bytes.Equal(logged, want) {
		t.Errorf("output:\ngot:\n%s\nwant:\n%s", logged, want)
		return
	}
}

// TestDelayedCore_WriteFailure_RetriesSuccessfully verifies that a transient write failure is retried successfully
func TestDelayedCore_WriteFailure_RetriesSuccessfully(t *testing.T) {

	// Prepare out, which reports when a retry succeeds
	chSuccess := make(chan struct{}, 1)
	out := Lock(&OneTimeFailWriter{chSuccess: chSuccess})

	// Prepare core
	delayedCore, errDelayedCore := NewDelayedCore(
		zap.LevelEnablerFunc(func(lvl Level) bool { return true }),
		NewJSONEncoder(testEncoderConfig()),
		out,
		zap.LevelEnablerFunc(func(lvl Level) bool { return true }),
		time.Millisecond*40,
		time.Millisecond*20,
	)
	if errDelayedCore != nil {
		t.Errorf("NewDelayedCore() error = '%v', want = nil", errDelayedCore)
		return
	}

	// Verify that Sync returns nil when no Write was called yet
	errSync1 := delayedCore.Sync()
	if errSync1 != nil {
		t.Errorf("Sync() error = '%v', want = nil", errSync1)
		return
	}

	// Write a message whose first timed delivery attempt will fail
	// The first write fails, then the background goroutine retries after delayPriority and succeeds.
	errWrite := delayedCore.Write(Entry{}, nil)
	if errWrite != nil {
		t.Errorf("Write() error = '%v', want = nil", errWrite)
		return
	}

	// Verify the background retry succeeds without an explicit Sync call
	select {
	case <-chSuccess:
	case <-time.After(time.Second):
		t.Error("Write() retry did not succeed within one second")
		return
	}

	// Verify that Sync succeeds after retry with no queued messages
	errSync2 := delayedCore.Sync()
	if errSync2 != nil {
		t.Errorf("Sync() error = '%v', want = nil", errSync2)
		return
	}
}

// TestDelayedCore_ShortWrite_RetainsAndRetriesBatch verifies incomplete writes cannot silently clear buffered logs
func TestDelayedCore_ShortWrite_RetainsAndRetriesBatch(t *testing.T) {

	// Prepare a writer that reports one short write before accepting the retry
	chSuccess := make(chan struct{}, 1)
	out := &ShortWriteOnceWriter{chSuccess: chSuccess}
	delayedCore, errDelayedCore := NewDelayedCore(
		DebugLevel,
		NewJSONEncoder(testEncoderConfig()),
		out,
		ErrorLevel,
		time.Millisecond*40,
		time.Millisecond*20,
	)
	if errDelayedCore != nil {
		t.Errorf("NewDelayedCore() error = '%v', want = nil", errDelayedCore)
		return
	}

	// Trigger an immediate critical flush and verify the short write is exposed
	errWrite := delayedCore.Write(Entry{Level: DPanicLevel, Message: "short-write"}, nil)
	if !errors.Is(errWrite, io.ErrShortWrite) {
		t.Errorf("Write() error = '%v', want = '%v'", errWrite, io.ErrShortWrite)
		return
	}

	// Wait for the automatically scheduled retry to accept the retained batch
	select {
	case <-chSuccess:
	case <-time.After(time.Second):
		t.Error("Write() short-write retry did not succeed within one second")
		return
	}

	// Verify retrying preserved the exact payload and then cleared the queue
	payloads := out.Payloads()
	if len(payloads) != 2 || !bytes.Equal(payloads[0], payloads[1]) {
		t.Errorf("WriteSyncer.Write() payload attempts = '%d', want two identical payloads", len(payloads))
		return
	}
	if errSync := delayedCore.Sync(); errSync != nil {
		t.Errorf("Sync() error = '%v', want = nil", errSync)
		return
	}
}

// TestDelayedCore_SyncFailure_RetainsAndRetriesBatch verifies a failed underlying Sync keeps the complete batch
func TestDelayedCore_SyncFailure_RetainsAndRetriesBatch(t *testing.T) {

	// Prepare a writer whose first synchronization fails after accepting the payload
	chSuccess := make(chan struct{}, 1)
	out := &OneTimeFailSyncWriter{chSuccess: chSuccess}
	delayedCore, errDelayedCore := NewDelayedCore(
		DebugLevel,
		NewJSONEncoder(testEncoderConfig()),
		out,
		ErrorLevel,
		time.Millisecond*40,
		time.Millisecond*20,
	)
	if errDelayedCore != nil {
		t.Errorf("NewDelayedCore() error = '%v', want = nil", errDelayedCore)
		return
	}

	// Trigger an immediate critical flush and verify its synchronization error is returned
	errWrite := delayedCore.Write(Entry{Level: DPanicLevel, Message: "sync-retry"}, nil)
	if errWrite == nil {
		t.Error("Write() error = nil, want synchronization error")
		return
	}

	// Wait for the retained batch to be written and synchronized successfully
	select {
	case <-chSuccess:
	case <-time.After(time.Second):
		t.Error("Write() synchronization retry did not succeed within one second")
		return
	}

	// Verify the retry used the same complete payload and left no queued work
	payloads := out.Payloads()
	if len(payloads) != 2 || !bytes.Equal(payloads[0], payloads[1]) {
		t.Errorf("WriteSyncer.Write() payload attempts = '%d', want two identical payloads", len(payloads))
		return
	}
	if errSync := delayedCore.Sync(); errSync != nil {
		t.Errorf("Sync() error = '%v', want = nil", errSync)
		return
	}
}

// TestDelayedCore_CriticalWriteFailure_RetriesAutomatically verifies that the first immediate failure arms a retry
func TestDelayedCore_CriticalWriteFailure_RetriesAutomatically(t *testing.T) {

	// Prepare a writer that fails once and signals the successful retry
	chSuccess := make(chan struct{}, 1)
	out := &OneTimeFailWriter{chSuccess: chSuccess}

	// Prepare a core whose DPanic entry flushes immediately
	delayedCore, errDelayedCore := NewDelayedCore(
		DebugLevel,
		NewJSONEncoder(testEncoderConfig()),
		out,
		ErrorLevel,
		time.Millisecond*40,
		time.Millisecond*20,
	)
	if errDelayedCore != nil {
		t.Errorf("NewDelayedCore() error = '%v', want = nil", errDelayedCore)
		return
	}

	// Verify the immediate failure is returned to the caller
	errWrite := delayedCore.Write(Entry{Level: DPanicLevel, Message: "critical"}, nil)
	if errWrite == nil {
		t.Error("Write() error = nil, want transient delivery error")
		return
	}

	// Verify the retained critical entry is retried without another log or Sync call
	select {
	case <-chSuccess:
	case <-time.After(time.Second):
		t.Error("Write() critical retry did not succeed within one second")
		return
	}
}

// TestDelayedCore_AutomaticErrors_AreRateLimitedOnStderr verifies that timed failures remain locally visible
func TestDelayedCore_AutomaticErrors_AreRateLimitedOnStderr(t *testing.T) {

	// Capture stderr before the background delivery attempt starts
	stderrOriginal := os.Stderr
	stderrReader, stderrWriter, errPipe := os.Pipe()
	if errPipe != nil {
		t.Errorf("os.Pipe() error = '%v', want = nil", errPipe)
		return
	}
	os.Stderr = stderrWriter
	defer func() {
		os.Stderr = stderrOriginal
		_ = stderrReader.Close()
		_ = stderrWriter.Close()
	}()

	// Prepare a writer that fails across multiple short retry intervals
	chWrite := make(chan []byte, 8)
	out := &ControlledWriter{chWrite: chWrite}
	out.SetFail(true)
	delayedCore, errDelayedCore := NewDelayedCore(
		DebugLevel,
		NewJSONEncoder(testEncoderConfig()),
		out,
		WarnLevel,
		time.Millisecond*20,
		time.Millisecond*20,
	)
	if errDelayedCore != nil {
		t.Errorf("NewDelayedCore() error = '%v', want = nil", errDelayedCore)
		return
	}
	defer func() {
		out.SetFail(false)
		_ = delayedCore.Sync()
	}()

	// Trigger automatic attempts within one reporting interval
	errWrite := delayedCore.Write(Entry{Level: WarnLevel, Message: "retry"}, nil)
	if errWrite != nil {
		t.Errorf("Write() error = '%v', want = nil", errWrite)
		return
	}

	// Wait for three actual failures so a single attempt cannot satisfy the rate-limit assertion
	for attempt := 1; attempt <= 3; attempt++ {
		select {
		case <-chWrite:
		case <-time.After(time.Second):
			t.Errorf("WriteSyncer.Write() attempt count < '%d', want at least three attempts", attempt)
			return
		}
	}

	// Stop the retry loop before reading the captured output
	out.SetFail(false)
	errSync := delayedCore.Sync()
	if errSync != nil {
		t.Errorf("Sync() error = '%v', want = nil", errSync)
		return
	}
	os.Stderr = stderrOriginal
	_ = stderrWriter.Close()
	stderrOutput, errStderrOutput := io.ReadAll(stderrReader)
	if errStderrOutput != nil {
		t.Errorf("io.ReadAll() error = '%v', want = nil", errStderrOutput)
		return
	}

	// Verify the repeated failure is reported exactly once during the rate-limit window
	const warning = "ZapSMTP: Could not flush delayed logs"
	if warningCount := strings.Count(string(stderrOutput), warning); warningCount != 1 {
		t.Errorf("stderr warning count = '%d', want = '1'; output = '%s'", warningCount, stderrOutput)
		return
	}
}

// TestDelayedCore_FullCache_DropsNewEntriesWithoutRetryStorm verifies that cache saturation remains bounded
func TestDelayedCore_FullCache_DropsNewEntriesWithoutRetryStorm(t *testing.T) {

	// Capture local cache warnings so repeated drops can be checked independently from flush errors
	stderrOriginal := os.Stderr
	stderrReader, stderrWriter, errPipe := os.Pipe()
	if errPipe != nil {
		t.Errorf("os.Pipe() error = '%v', want = nil", errPipe)
		return
	}
	os.Stderr = stderrWriter
	defer func() {
		os.Stderr = stderrOriginal
		_ = stderrReader.Close()
		_ = stderrWriter.Close()
	}()

	// Prepare a writer that keeps the cache retained until the assertions are ready
	out := &ControlledWriter{}
	out.SetFail(true)
	delayedCore, errDelayedCore := NewDelayedCore(
		DebugLevel,
		NewJSONEncoder(testEncoderConfig()),
		out,
		WarnLevel,
		time.Hour,
		time.Hour,
	)
	if errDelayedCore != nil {
		t.Errorf("NewDelayedCore() error = '%v', want = nil", errDelayedCore)
		return
	}
	defer func() {
		out.SetFail(false)
		_ = delayedCore.Sync()
	}()

	// Fill the cache and add entries that must be dropped instead of triggering repeated writes
	for i := 0; i < maxBufferedEntries+5; i++ {
		errWrite := delayedCore.Write(Entry{Level: WarnLevel, Message: fmt.Sprintf("entry-%d", i)}, nil)
		if errWrite != nil {
			t.Errorf("Write() error = '%v', want = nil", errWrite)
			return
		}
	}

	// Use Sync as a FIFO barrier while retaining the failed batch
	errSyncFailed := delayedCore.Sync()
	if errSyncFailed == nil {
		t.Error("Sync() error = nil, want retained delivery error")
		return
	}
	if writeCount := out.WriteCount(); writeCount != 2 {
		t.Errorf("WriteSyncer.Write() call count = '%d', want = '2'", writeCount)
		return
	}

	// Verify a critical entry displaces a buffered entry instead of being silently lost
	errCritical := delayedCore.Write(Entry{Level: DPanicLevel, Message: "critical-while-full"}, nil)
	if errCritical == nil {
		t.Error("Write() critical error = nil, want retained delivery error")
		return
	}

	// Deliver the retained cache successfully
	out.SetFail(false)
	errSync := delayedCore.Sync()
	if errSync != nil {
		t.Errorf("Sync() error = '%v', want = nil", errSync)
		return
	}

	// Close the capture and verify all repeated normal-entry drops emitted only one local warning
	os.Stderr = stderrOriginal
	_ = stderrWriter.Close()
	stderrOutput, errStderrOutput := io.ReadAll(stderrReader)
	if errStderrOutput != nil {
		t.Errorf("io.ReadAll() error = '%v', want = nil", errStderrOutput)
		return
	}
	const cacheWarning = "ZapSMTP: Delayed log cache is full. Dropping newest entry."
	if warningCount := strings.Count(string(stderrOutput), cacheWarning); warningCount != 1 {
		t.Errorf("stderr cache warning count = '%d', want = '1'; output = '%s'", warningCount, stderrOutput)
		return
	}

	// Verify the bounded cache retained the critical entry and rejected newer non-critical additions
	payload := string(out.LastWrite())
	if !strings.Contains(payload, "critical-while-full") || !strings.Contains(payload, "entry-4998") ||
		strings.Contains(payload, "entry-4999") || strings.Contains(payload, "entry-5000") {
		t.Error("WriteSyncer.Write() payload boundary is invalid, want critical entry retained and newest buffered entries dropped")
		return
	}
}

// TestDelayedCore_FullCache_FlushesExactlyOnce verifies the cache threshold starts a fresh batch after success
func TestDelayedCore_FullCache_FlushesExactlyOnce(t *testing.T) {

	// Prepare a successful writer and a core whose timer cannot race the threshold flush
	out := &ControlledWriter{}
	delayedCore, errDelayedCore := NewDelayedCore(
		DebugLevel,
		NewJSONEncoder(testEncoderConfig()),
		out,
		WarnLevel,
		time.Hour,
		time.Hour,
	)
	if errDelayedCore != nil {
		t.Errorf("NewDelayedCore() error = '%v', want = nil", errDelayedCore)
		return
	}

	// Fill the cache exactly so the final entry triggers one automatic flush
	for i := 0; i < maxBufferedEntries; i++ {
		errWrite := delayedCore.Write(Entry{Level: InfoLevel, Message: fmt.Sprintf("threshold-%d", i)}, nil)
		if errWrite != nil {
			t.Errorf("Write() error = '%v', want = nil", errWrite)
			return
		}
	}

	// Use Sync as a FIFO barrier and verify the threshold flush already emptied the cache
	if errSync := delayedCore.Sync(); errSync != nil {
		t.Errorf("Sync() error = '%v', want = nil", errSync)
		return
	}
	if writeCount := out.WriteCount(); writeCount != 1 {
		t.Errorf("WriteSyncer.Write() call count = '%d', want = '1'", writeCount)
		return
	}

	// Write and flush a new entry to prove successful threshold delivery starts an independent batch
	if errWrite := delayedCore.Write(Entry{Level: InfoLevel, Message: "fresh-batch"}, nil); errWrite != nil {
		t.Errorf("Write() error = '%v', want = nil", errWrite)
		return
	}
	if errSync := delayedCore.Sync(); errSync != nil {
		t.Errorf("Sync() error = '%v', want = nil", errSync)
		return
	}

	// Verify the second write contains only the new batch
	payload := string(out.LastWrite())
	lastThresholdEntry := fmt.Sprintf("threshold-%d", maxBufferedEntries-1)
	if out.WriteCount() != 2 || !strings.Contains(payload, "fresh-batch") || strings.Contains(payload, lastThresholdEntry) {
		t.Error("WriteSyncer.Write() did not start a clean batch after the successful threshold flush")
		return
	}
}

// TestDelayedCore_CriticalEntryAtFullCache_DropsNewestStandard verifies priority data survives cache pressure
func TestDelayedCore_CriticalEntryAtFullCache_DropsNewestStandard(t *testing.T) {

	// Prepare a failing writer so the mixed cache remains available for inspection
	out := &ControlledWriter{}
	out.SetFail(true)
	delayedCore, errDelayedCore := NewDelayedCore(
		DebugLevel,
		NewJSONEncoder(testEncoderConfig()),
		out,
		WarnLevel,
		time.Hour,
		time.Hour,
	)
	if errDelayedCore != nil {
		t.Errorf("NewDelayedCore() error = '%v', want = nil", errDelayedCore)
		return
	}
	defer func() {
		out.SetFail(false)
		_ = delayedCore.Sync()
	}()

	// Fill most of the cache with standard entries and retain one priority entry
	for i := 0; i < maxBufferedEntries-2; i++ {
		if errWrite := delayedCore.Write(Entry{Level: InfoLevel, Message: fmt.Sprintf("standard-%d", i)}, nil); errWrite != nil {
			t.Errorf("Write() error = '%v', want = nil", errWrite)
			return
		}
	}
	if errWrite := delayedCore.Write(Entry{Level: WarnLevel, Message: "priority-retained"}, nil); errWrite != nil {
		t.Errorf("Write() error = '%v', want = nil", errWrite)
		return
	}
	if errWrite := delayedCore.Write(Entry{Level: InfoLevel, Message: "standard-newest"}, nil); errWrite != nil {
		t.Errorf("Write() error = '%v', want = nil", errWrite)
		return
	}

	// Wait until the full-cache flush fails, then add a critical entry while all slots remain occupied
	if errSync := delayedCore.Sync(); errSync == nil {
		t.Error("Sync() error = nil, want retained delivery error")
		return
	}
	if errWrite := delayedCore.Write(Entry{Level: DPanicLevel, Message: "critical-while-full"}, nil); errWrite == nil {
		t.Error("Write() error = nil, want retained delivery error")
		return
	}

	// Recover the writer and deliver the retained bounded cache
	out.SetFail(false)
	if errSync := delayedCore.Sync(); errSync != nil {
		t.Errorf("Sync() error = '%v', want = nil", errSync)
		return
	}

	// Verify the newest standard entry was sacrificed before either priority entry
	payload := string(out.LastWrite())
	lastRetainedStandard := fmt.Sprintf("standard-%d", maxBufferedEntries-3)
	if !strings.Contains(payload, lastRetainedStandard) || !strings.Contains(payload, "priority-retained") ||
		!strings.Contains(payload, "critical-while-full") || strings.Contains(payload, "standard-newest") {
		t.Error("WriteSyncer.Write() did not prefer dropping the newest standard entry from the full cache")
		return
	}
}

// TestDelayedCore_SuccessfulSync_DoesNotLeakOldTimer verifies a stopped timer cannot flush the following batch early
func TestDelayedCore_SuccessfulSync_DoesNotLeakOldTimer(t *testing.T) {

	// Prepare a writer that can keep the worker inside its first flush past the active timer deadline
	const standardDelay = time.Millisecond * 200
	chStarted := make(chan struct{})
	chRelease := make(chan struct{})
	chWrite := make(chan []byte, 1)
	out := &BlockingOnceWriter{chStarted: chStarted, chRelease: chRelease, chWrite: chWrite}
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() { close(chRelease) })
	}
	t.Cleanup(release)

	// Prepare a core using the timer instance that will later be reused for a second batch
	delayedCore, errDelayedCore := NewDelayedCore(
		DebugLevel,
		NewJSONEncoder(testEncoderConfig()),
		out,
		WarnLevel,
		standardDelay,
		standardDelay/2,
	)
	if errDelayedCore != nil {
		t.Errorf("NewDelayedCore() error = '%v', want = nil", errDelayedCore)
		return
	}

	// Start the first timer and request a Sync that blocks inside the underlying writer
	if errWrite := delayedCore.Write(Entry{Level: InfoLevel, Message: "first-batch"}, nil); errWrite != nil {
		t.Errorf("Write() error = '%v', want = nil", errWrite)
		return
	}
	chSyncResult := make(chan error, 1)
	go func() { chSyncResult <- delayedCore.Sync() }()
	select {
	case <-chStarted:
	case <-time.After(time.Second):
		t.Error("Sync() did not reach the blocked first write")
		return
	}

	// Let the original timer expire while run cannot receive from it, then finish the successful Sync
	time.Sleep(standardDelay + time.Millisecond*50)
	release()
	select {
	case errSync := <-chSyncResult:
		if errSync != nil {
			t.Errorf("Sync() error = '%v', want = nil", errSync)
			return
		}
	case <-time.After(time.Second):
		t.Error("Sync() did not finish after releasing the first write")
		return
	}

	// Start a second batch on the reused timer and remember its fresh scheduling point
	secondBatchStarted := time.Now()
	if errWrite := delayedCore.Write(Entry{Level: InfoLevel, Message: "second-batch"}, nil); errWrite != nil {
		t.Errorf("Write() error = '%v', want = nil", errWrite)
		return
	}

	// Verify no expired value from the first schedule can bypass most of the second batch's full delay
	select {
	case payload := <-chWrite:
		if !strings.Contains(string(payload), "second-batch") {
			t.Errorf("WriteSyncer.Write() payload = '%s', want second batch", payload)
			return
		}
		if elapsed := time.Since(secondBatchStarted); elapsed < standardDelay-time.Millisecond*50 {
			t.Errorf("Old timer flushed the second batch after '%v', want at least '%v'", elapsed, standardDelay-time.Millisecond*50)
			return
		}
	case <-time.After(time.Second):
		t.Error("Second batch was not delivered at its fresh timer deadline")
		return
	}
}

// TestDelayedCore_PriorityDuringRetry_DoesNotPostponeRetry verifies new urgent logs retain an earlier retry deadline
func TestDelayedCore_PriorityDuringRetry_DoesNotPostponeRetry(t *testing.T) {

	// Prepare a failing writer whose delivery attempts expose the retry timing
	chWrite := make(chan []byte, 8)
	out := &ControlledWriter{chWrite: chWrite}
	out.SetFail(true)
	delayedCore, errDelayedCore := NewDelayedCore(
		DebugLevel,
		NewJSONEncoder(testEncoderConfig()),
		out,
		WarnLevel,
		time.Second,
		time.Millisecond*500,
	)
	if errDelayedCore != nil {
		t.Errorf("NewDelayedCore() error = '%v', want = nil", errDelayedCore)
		return
	}
	defer func() {
		out.SetFail(false)
		_ = delayedCore.Sync()
	}()

	// Start a priority batch and wait until its first automatic delivery fails
	if errWrite := delayedCore.Write(Entry{Level: WarnLevel, Message: "first-priority"}, nil); errWrite != nil {
		t.Errorf("Write() error = '%v', want = nil", errWrite)
		return
	}
	select {
	case <-chWrite:
	case <-time.After(time.Second):
		t.Error("First priority delivery was not attempted")
		return
	}

	// Add another priority entry after most of the retry delay has elapsed
	time.Sleep(time.Millisecond * 300)
	if errWrite := delayedCore.Write(Entry{Level: WarnLevel, Message: "second-priority"}, nil); errWrite != nil {
		t.Errorf("Write() error = '%v', want = nil", errWrite)
		return
	}

	// Verify the existing retry fires instead of being postponed by a fresh priority delay
	select {
	case payload := <-chWrite:
		if !strings.Contains(string(payload), "first-priority") || !strings.Contains(string(payload), "second-priority") {
			t.Errorf("WriteSyncer.Write() retry payload = '%s', want both priority entries", payload)
			return
		}
	case <-time.After(time.Millisecond * 400):
		t.Error("New priority entry postponed the already scheduled retry")
		return
	}

	// Recover delivery and clear any retained retry state
	out.SetFail(false)
	if errSync := delayedCore.Sync(); errSync != nil {
		t.Errorf("Sync() error = '%v', want = nil", errSync)
		return
	}
}
