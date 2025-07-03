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
	"bytes"
	"errors"
	"fmt"
	"go.uber.org/multierr"
	"go.uber.org/zap"
	. "go.uber.org/zap/zapcore"
	"io"
	"os"
	"sync"
	"testing"
	"time"
)

// A Syncer is a spy for the Sync portion of zapcore.WriteSyncer.
type Syncer struct {
	err    error
	called bool
}

// SetError sets the error that the Sync method will return.
func (s *Syncer) SetError(err error) {
	s.err = err
}

// Sync records that it was called, then returns the user-supplied error (if
// any).
func (s *Syncer) Sync() error {
	s.called = true
	return s.err
}

// Called reports whether the Sync method was called.
func (s *Syncer) Called() bool {
	return s.called
}

// A Discarder sends all writes to ioutil.Discard.
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
	var err error
	w.Once.Do(func() { err = fmt.Errorf("failed") })
	return len(b), err
}

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

func makeInt64Field(key string, val int) Field {
	return Field{Type: Int64Type, Integer: int64(val), Key: key}
}

func TestDelayedCore(t *testing.T) {

	// Drop timestamps for simpler assertions (timestamp encoding is tested
	// elsewhere).
	cfg := testEncoderConfig()
	cfg.TimeKey = ""

	// Prepare sink, which is a simple temporary file
	sink, errSink := os.CreateTemp("", "zap-test-delayed-core-*")
	if errSink != nil {
		t.Errorf("failed to create temp sink file: %s", errSink)
		return
	}
	defer func() { _ = os.Remove(sink.Name()) }()

	// Prepare core
	core, errCore := NewDelayedCore(
		InfoLevel,
		NewJSONEncoder(cfg),
		sink,
		WarnLevel,
		time.Second*4,
		time.Second*2,
	)
	if errCore != nil {
		t.Errorf("unable to initialize delayed core: %s", errCore)
		return
	}
	core.With([]Field{makeInt64Field("k", 1)})

	// Call Sync on core
	errSync := core.Sync()
	if errSync != nil {
		t.Errorf("Expected Syncing a temp file to succeed.: %s", errSync)
	}

	// Write test messages
	if ce := core.Check(Entry{Level: DebugLevel, Message: "debug"}, nil); ce != nil {
		ce.Write(makeInt64Field("k", 2))
	}
	if ce := core.Check(Entry{Level: InfoLevel, Message: "info"}, nil); ce != nil {
		ce.Write(makeInt64Field("k", 3))
	}
	if ce := core.Check(Entry{Level: WarnLevel, Message: "warn"}, nil); ce != nil {
		ce.Write(makeInt64Field("k", 4))
	}

	// Sleep for the priority time so the log actually gets synced
	time.Sleep(time.Second * 2)

	want := []byte("=== Priority Log ===\n" +
		`{"level":"warn","msg":"warn","k":1,"k":4}` + "\n" +
		"=== Standard Log ===\n" +
		`{"level":"info","msg":"info","k":1,"k":3}` + "\n")

	// Read and check logged test messages
	logged, errRead := os.ReadFile(sink.Name())
	if errRead != nil {
		t.Errorf("failed to read from temp file: %s", errRead)
		return
	}
	if bytes.Equal(logged, want) {
		t.Errorf("unexpected log output: %s\n, want:\n%s\n", logged, want)
		return
	}
}

func TestDelayedCoreSyncFail(t *testing.T) {

	// Define test error
	err := fmt.Errorf("failed")

	// Prepare sink, which just discards messages
	sink := &Discarder{}
	sink.SetError(err)

	// Prepare core
	core, errCore := NewDelayedCore(
		DebugLevel,
		NewJSONEncoder(testEncoderConfig()),
		sink,
		WarnLevel,
		time.Second*4,
		time.Second*2,
	)
	if errCore != nil {
		t.Errorf("unable to initialize delayed core: %s", errCore)
		return
	}

	// Add log message otherwise Sync would return immediately
	errWrite := core.Write(Entry{Level: WarnLevel}, nil)
	if errWrite != nil {
		t.Errorf("could not prepare log messages: %s", errWrite)
		return
	}

	// Call Sync and check result
	errSync := core.Sync()
	if !errors.Is(errSync, err) {
		t.Errorf("expected Sync to return errors from underlying WriteSyncer: got %v, want %v", errSync, err)
		return
	}
}

// TestDelayedCoreSyncsOutput tests for the particular case, where high level log entries (> zapcore.ErrorLevel) will
// trigger an immediate sync
func TestDelayedCoreSyncsOutput(t *testing.T) {
	tests := []struct {
		entry      Entry
		shouldSync bool
	}{
		{Entry{Level: DebugLevel}, false},
		{Entry{Level: InfoLevel}, false},
		{Entry{Level: WarnLevel}, false},
		{Entry{Level: ErrorLevel}, false},
		{Entry{Level: DPanicLevel}, true},
		{Entry{Level: PanicLevel}, true},
		{Entry{Level: FatalLevel}, true},
	}
	for i, tt := range tests {

		// Prepare sink, which just discards messages
		sink := &Discarder{}

		// Prepare core
		core, errCore := NewDelayedCore(
			DebugLevel,
			NewJSONEncoder(testEncoderConfig()),
			sink,
			ErrorLevel,
			time.Minute*10, // Very long delay, so only panic and fatal lvl will be synced
			time.Minute*10, // Very long delay, so only panic and fatal lvl will be synced
		)
		if errCore != nil {
			t.Errorf("unable to initialize delayed core: %s", errCore)
			return
		}

		// Write entry
		_ = core.Write(tt.entry, nil)

		// Check if sink got called
		if tt.shouldSync != sink.Called() {
			t.Errorf("incorrect Sync behavior. %d", i)
			return
		}
	}
}

// TestDelayedCoreDelayedSyncsOutput tests the delayed syncing triggered by a Write
func TestDelayedCoreDelayedSyncsOutput(t *testing.T) {
	tests := []struct {
		name       string
		entries    []Entry
		delay      time.Duration
		shouldSync bool
	}{
		{"1", []Entry{{Level: InfoLevel}}, time.Second * 4, true}, // Log level is not checked by the write function
		{"2", []Entry{{Level: DebugLevel}}, time.Second, false},
		{"3", []Entry{{Level: DebugLevel}}, time.Second * 4, true},
		{"4", []Entry{{Level: WarnLevel}}, time.Second, false},
		{"5", []Entry{{Level: WarnLevel}}, time.Second * 2, true},
		{"6", []Entry{{Level: DebugLevel}, {Level: WarnLevel}}, time.Second, false},
		{"7", []Entry{{Level: DebugLevel}, {Level: WarnLevel}}, time.Second * 2, true},
		{"8", []Entry{{Level: WarnLevel}, {Level: DebugLevel}}, time.Second, false},
		{"9", []Entry{{Level: WarnLevel}, {Level: DebugLevel}}, time.Second * 2, true},
		{"10", []Entry{{Level: WarnLevel}, {Level: WarnLevel}}, time.Second, false},
		{"11", []Entry{{Level: WarnLevel}, {Level: WarnLevel}}, time.Second * 2, true},
		{"12", []Entry{{Level: DebugLevel}, {Level: DebugLevel}}, time.Second * 2, false},
		{"13", []Entry{{Level: DebugLevel}, {Level: DebugLevel}}, time.Second * 4, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Allow tests to run in parallel to save tim on the hardcoded wait times
			t.Parallel()

			// Prepare sink, which just discards messages
			sink := &Discarder{}

			// Prepare core
			core, errCore := NewDelayedCore(
				DebugLevel,
				NewJSONEncoder(testEncoderConfig()),
				sink,
				WarnLevel,
				time.Second*4,
				time.Second*2,
			)
			if errCore != nil {
				t.Errorf("unable to initialize delayed core: %s", errCore)
				return
			}

			// Write entries
			for _, entry := range tt.entries {
				_ = core.Write(entry, nil)
			}

			// Wait for the specified delay, as the sync will be triggered in a new goroutine we will also add a small
			// additional delay
			time.Sleep(tt.delay + time.Millisecond*100)

			// Check if Sync got called correctly
			if tt.shouldSync != sink.Called() {
				t.Error("incorrect delay behavior.")
			}
		})
	}
}

func TestDelayedCoreWriteFailure(t *testing.T) {

	// Prepare sink, which returns an error after the first write
	sink := Lock(&OneTimeFailWriter{})

	// Prepare core
	core, errCore := NewDelayedCore(
		zap.LevelEnablerFunc(func(lvl Level) bool { return true }),
		NewJSONEncoder(testEncoderConfig()),
		sink,
		zap.LevelEnablerFunc(func(lvl Level) bool { return true }),
		0,
		0,
	)
	if errCore != nil {
		t.Errorf("unable to initialize delayed core: %s", errCore)
		return
	}

	// Sync shouldn't return an error yet, because no Write was called yet
	errSync1 := core.Sync()
	if len(multierr.Errors(errSync1)) > 0 {
		t.Errorf("Unexpected Sync error: %s", multierr.Errors(errSync1))
		return
	}

	// The initial write will start a new sync routine. The error might not be immediately retrieved.
	errWrite := core.Write(Entry{}, nil)
	if errWrite != nil {
		t.Errorf("Unexpected Write error: %s", errWrite)
		return
	}

	// Sleep real quick to allow the sync routine to catch up
	time.Sleep(time.Millisecond * 100)

	// Execute Sync call to pickup error generated by previous Write
	errSync2 := core.Sync()

	// A consecutive Sync returns any previous errors caused by Write and it's timed (asynchronous) Sync call
	if len(multierr.Errors(errSync2)) != 1 {
		t.Errorf("Expected exactly one error, got %d", len(multierr.Errors(errSync2)))
		return
	}
}
