/*
* ZapSmtp, a Zap (Golang) logger extension for sending urgent log messages via SMTP
*
* Copyright (c) Siemens AG, 2021-2025.
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

	"go.uber.org/multierr"
	"go.uber.org/zap"
	. "go.uber.org/zap/zapcore"
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

// Sync records that it was called, then returns the user-supplied error (if any).
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

	// Prepare out, which is a simple temporary file
	tmpOut, errTmpOut := os.CreateTemp("", "zap-test-delayed-core-*")
	if errTmpOut != nil {
		t.Errorf("could not create temp out file: %s", errTmpOut)
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
		t.Errorf("could not initialize delayed core: %s", errDelayedCore)
		return
	}
	delayedCore.With([]Field{makeInt64Field("k", 1)})

	// Call Sync on core
	errSync := delayedCore.Sync()
	if errSync != nil {
		t.Errorf("Expected Syncing a temp file to succeed.: %s", errSync)
	}

	// Write test messages
	if ce := delayedCore.Check(Entry{Level: DebugLevel, Message: "debug"}, nil); ce != nil {
		ce.Write(makeInt64Field("k", 2))
	}
	if ce := delayedCore.Check(Entry{Level: InfoLevel, Message: "info"}, nil); ce != nil {
		ce.Write(makeInt64Field("k", 3))
	}
	if ce := delayedCore.Check(Entry{Level: WarnLevel, Message: "warn"}, nil); ce != nil {
		ce.Write(makeInt64Field("k", 4))
	}

	// Sleep for the priority time so the log actually gets synced
	time.Sleep(time.Second * 2)

	// Define wanted output
	want := []byte("=== Priority Log ===\n" +
		`{"level":"warn","msg":"warn","k":1,"k":4}` + "\n" +
		"=== Standard Log ===\n" +
		`{"level":"info","msg":"info","k":1,"k":3}` + "\n")

	// Read and check logged test messages
	logged, errRead := os.ReadFile(tmpOut.Name())
	if errRead != nil {
		t.Errorf("could not read from temp file: %s", errRead)
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

	// Prepare out, which just discards messages
	out := &Discarder{}
	out.SetError(err)

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
		t.Errorf("could not initialize delayed core: %s", errDelayedCore)
		return
	}

	// Add log message otherwise Sync would return immediately
	errWrite := delayedCore.Write(Entry{Level: WarnLevel}, nil)
	if errWrite != nil {
		t.Errorf("could not prepare log messages: %s", errWrite)
		return
	}

	// Call Sync and check result
	errSync := delayedCore.Sync()
	if !errors.Is(errSync, err) {
		t.Errorf("expected Sync to return errors from underlying SmtpSyncer: got %v, want %v", errSync, err)
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
			t.Errorf("could not initialize delayed core: %s", errDelayedCore)
			return
		}

		// Write entry
		_ = delayedCore.Write(tt.entry, nil)

		// Check if out got called
		if tt.shouldSync != out.Called() {
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
				t.Errorf("could not initialize delayed core: %s", errDelayedCore)
				return
			}

			// Write entries
			for _, entry := range tt.entries {
				_ = delayedCore.Write(entry, nil)
			}

			// Wait for the specified delay, as the sync will be triggered in a new goroutine we will also add a small
			// additional delay
			time.Sleep(tt.delay + time.Millisecond*100)

			// Check if Sync got called correctly
			if tt.shouldSync != out.Called() {
				t.Error("incorrect delay behavior.")
			}
		})
	}
}

func TestDelayedCoreWriteFailure(t *testing.T) {

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
		t.Errorf("could not initialize delayed core: %s", errDelayedCore)
		return
	}

	// Sync shouldn't return an error yet, because no Write was called yet
	errSync1 := delayedCore.Sync()
	if len(multierr.Errors(errSync1)) > 0 {
		t.Errorf("Unexpected Sync error: %s", multierr.Errors(errSync1))
		return
	}

	// The initial write will start a new sync routine. The error might not be immediately retrieved.
	errWrite := delayedCore.Write(Entry{}, nil)
	if errWrite != nil {
		t.Errorf("Unexpected Write error: %s", errWrite)
		return
	}

	// Sleep real quick to allow the sync routine to catch up
	time.Sleep(time.Millisecond * 100)

	// Execute Sync call to pickup error generated by previous Write
	errSync2 := delayedCore.Sync()

	// A consecutive Sync returns any previous errors caused by Write and it's timed (asynchronous) Sync call
	if len(multierr.Errors(errSync2)) != 1 {
		t.Errorf("Expected exactly one error, got %d", len(multierr.Errors(errSync2)))
		return
	}
}
