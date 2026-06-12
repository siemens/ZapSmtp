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
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	. "go.uber.org/zap/zapcore"
)

// Syncer is a spy for the Sync portion of zapcore.WriteSyncer.
type Syncer struct {
	err    error
	called bool
}

// SetError sets the error that the Sync method will return.
func (s *Syncer) SetError(err error) {
	s.err = err
}

// Sync records that it was called, then returns the user-supplied error (if any).
func (s *Syncer) Sync() error {
	s.called = true
	return s.err
}

// Called reports whether the Sync method was called.
func (s *Syncer) Called() bool {
	return s.called
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
}

// Write implements io.Writer.
func (w *OneTimeFailWriter) Write(b []byte) (int, error) {

	var errWrite error
	w.Once.Do(func() { errWrite = fmt.Errorf("failed") })
	return len(b), errWrite
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
	defer func() { _ = os.Remove(tmpOut.Name()) }()

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

	// Sleep for the priority time so the log actually gets synced
	time.Sleep(time.Second * 2)

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

			// Wait for the specified delay, as the sync will be triggered in a new goroutine we will also add a small
			// additional delay
			time.Sleep(tt.delay + time.Millisecond*100)

			// Verify that Sync was called as expected
			if tt.shouldSync != out.Called() {
				t.Errorf("Syncer.Called() = '%v', want = '%v'", out.Called(), tt.shouldSync)
			}
		})
	}
}

// TestDelayedCore_InvalidDelay_ReturnsError verifies that NewDelayedCore rejects delay < delayPriority
func TestDelayedCore_InvalidDelay_ReturnsError(t *testing.T) {

	// Prepare and run test cases
	_, errDelayedCore := NewDelayedCore(
		DebugLevel,
		NewJSONEncoder(testEncoderConfig()),
		&Discarder{},
		WarnLevel,
		time.Second*1,
		time.Second*2,
	)

	// Verify that an error is returned for invalid delay configuration
	if errDelayedCore == nil {
		t.Error("NewDelayedCore() error = nil, want error for delay < delayPriority")
		return
	}
}

// TestDelayedCore_SyncEmpty_ReturnsNil verifies that Sync on an empty queue returns nil
func TestDelayedCore_SyncEmpty_ReturnsNil(t *testing.T) {

	// Prepare core
	delayedCore, errDelayedCore := NewDelayedCore(
		DebugLevel,
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

	// Verify that Sync returns nil when no messages are queued
	errSync := delayedCore.Sync()
	if errSync != nil {
		t.Errorf("Sync() error = '%v', want = nil", errSync)
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
	defer func() { _ = os.Remove(tmpOut.Name()) }()

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
	defer func() { _ = os.Remove(tmpOut.Name()) }()

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

	// Prepare out, which returns an error after the first write
	out := Lock(&OneTimeFailWriter{})

	// Prepare core
	delayedCore, errDelayedCore := NewDelayedCore(
		zap.LevelEnablerFunc(func(lvl Level) bool { return true }),
		NewJSONEncoder(testEncoderConfig()),
		out,
		zap.LevelEnablerFunc(func(lvl Level) bool { return true }),
		0,
		0,
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

	// Write a message — with delay 0 the background goroutine will attempt to flush immediately.
	// The first write fails (OneTimeFailWriter), but the goroutine retries after delayPriority (0) and succeeds.
	errWrite := delayedCore.Write(Entry{}, nil)
	if errWrite != nil {
		t.Errorf("Write() error = '%v', want = nil", errWrite)
		return
	}

	// Wait for the retry to succeed (delayPriority is 0, so retry is near-instant)
	time.Sleep(time.Millisecond * 500)

	// Verify that Sync succeeds after retry with no queued messages
	errSync2 := delayedCore.Sync()
	if errSync2 != nil {
		t.Errorf("Sync() error = '%v', want = nil", errSync2)
		return
	}
}
