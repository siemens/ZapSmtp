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
	"fmt"
	"go.uber.org/multierr"
	"go.uber.org/zap"
	. "go.uber.org/zap/zapcore"
	"io/ioutil"
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
	return ioutil.Discard.Write(b)
}

// OneTimeFailWriter is a WriteSyncer that returns an error on the first write.
type OneTimeFailWriter struct {
	Syncer
	sync.Once
}

// Write implements io.Writer.
func (w OneTimeFailWriter) Write(b []byte) (int, error) {
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
	temp, errFile := ioutil.TempFile("", "zap-test-delayed-core")
	if errFile != nil {
		t.Errorf("failed to create temp file: %s", errFile)
		return
	}
	defer os.Remove(temp.Name())

	// Drop timestamps for simpler assertions (timestamp encoding is tested
	// elsewhere).
	cfg := testEncoderConfig()
	cfg.TimeKey = ""

	core, errCore := NewDelayedCore(
		InfoLevel,
		NewJSONEncoder(cfg),
		temp,
		WarnLevel,
		time.Second*4,
		time.Second*2,
	)
	if errCore != nil {
		t.Errorf("unable to initialize delayed core: %s", errCore)
		return
	}
	core.With([]Field{makeInt64Field("k", 1)})

	errSync := core.Sync()
	if errSync != nil {
		t.Errorf("Expected Syncing a temp file to succeed.: %s", errSync)
	}

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

	logged, errRead := os.ReadFile(temp.Name())
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
	sink := &Discarder{}
	err := fmt.Errorf("failed")
	sink.SetError(err)

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

	errSync := core.Sync()
	if err != errSync {
		t.Errorf("expected core.Sync to return errors from underlying WriteSyncer: got %s, want %s", errSync, err)
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
		sink := &Discarder{}
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

		core.Write(tt.entry, nil)

		if tt.shouldSync != sink.Called() {
			t.Errorf("incorrect Sync behavior. %d", i)
			return
		}
	}
}

// TestDelayedCoreDelayedSyncsOutput tests the delayed syncing triggered by a Write
func TestDelayedCoreDelayedSyncsOutput(t *testing.T) {
	tests := []struct {
		entries    []Entry
		delay      time.Duration
		shouldSync bool
	}{
		{[]Entry{{Level: InfoLevel}}, time.Second * 4, true}, // Log level is not checked by the write function
		{[]Entry{{Level: DebugLevel}}, time.Second, false},
		{[]Entry{{Level: DebugLevel}}, time.Second * 4, true},
		{[]Entry{{Level: WarnLevel}}, time.Second, false},
		{[]Entry{{Level: WarnLevel}}, time.Second * 2, true},
		{[]Entry{{Level: DebugLevel}, {Level: WarnLevel}}, time.Second, false},
		{[]Entry{{Level: DebugLevel}, {Level: WarnLevel}}, time.Second * 2, true},
		{[]Entry{{Level: WarnLevel}, {Level: DebugLevel}}, time.Second, false},
		{[]Entry{{Level: WarnLevel}, {Level: DebugLevel}}, time.Second * 2, true},
		{[]Entry{{Level: WarnLevel}, {Level: WarnLevel}}, time.Second, false},
		{[]Entry{{Level: WarnLevel}, {Level: WarnLevel}}, time.Second * 2, true},
		{[]Entry{{Level: DebugLevel}, {Level: DebugLevel}}, time.Second * 2, false},
		{[]Entry{{Level: DebugLevel}, {Level: DebugLevel}}, time.Second * 4, true},
	}

	for _, tt := range tests {
		sink := &Discarder{}
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

		for _, entry := range tt.entries {
			core.Write(entry, nil)
		}

		// Wait for the specified delay, as the sync will be triggered in a new goroutine we will also add a small
		// additional delay
		time.Sleep(tt.delay + time.Millisecond*100)

		if tt.shouldSync != sink.Called() {
			t.Error("incorrect delay behavior.")
		}

	}
}

func TestDelayedCoreWriteFailure(t *testing.T) {

	core, errCore := NewDelayedCore(
		zap.LevelEnablerFunc(func(lvl Level) bool { return true }),
		NewJSONEncoder(testEncoderConfig()),
		Lock(&OneTimeFailWriter{}),
		zap.LevelEnablerFunc(func(lvl Level) bool { return true }),
		0,
		0,
	)
	if errCore != nil {
		t.Errorf("unable to initialize delayed core: %s", errCore)
		return
	}

	// The initial write will start a new sync routine. The error might not be immediately retrieved.
	errs := core.Write(Entry{}, nil)

	// Sleep real quick to allow the sync routine to catch up
	time.Sleep(time.Millisecond * 100)

	// A consecutive write returns any previous errors
	errs = multierr.Append(errs, core.Write(Entry{}, nil))
	if len(multierr.Errors(errs)) != 1 {
		t.Errorf("Expected exactly one error, got %d", len(multierr.Errors(errs)))
	}
}
