/*
* ZapSmtp, a Zap (Golang) logger extension for sending urgent log messages via SMTP
*
* Copyright (c) Siemens AG, 2021.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package example

import (
	"github.com/siemens/ZapSmtp/_test"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"net/mail"
	"testing"
	"time"
)

func Test_example(t *testing.T) {

	// Prepare logger cores and close function
	cores := make([]zapcore.Core, 0, 2)

	// Initialize console core
	coreConsole, errConsole := initConsoleCore(zapcore.DebugLevel)
	if errConsole != nil {
		t.Errorf("Console core intialization failed: %s", errConsole)
		return
	}

	// Attach console core
	cores = append(cores, coreConsole)

	// Initialize SMTP core
	coreSmtp, coreCloseFn, errSmtp := initSmtpCore(
		zapcore.WarnLevel,
		zapcore.ErrorLevel,
		time.Hour*24,
		time.Minute*5,
		_test.Server,
		_test.Port,
		_test.Username,
		_test.Password,
		"Example Logger",
		_test.Sender,
		[]mail.Address{_test.Recipient},
		_test.OpensslPath,
		"",
		"",
		nil,
		"",
	)

	// Make SMTP core is closed properly
	defer func() { _ = coreCloseFn() }()

	// Check for SMTP core initialization errors
	if errSmtp != nil {
		t.Errorf("Console core intialization failed: %s", errSmtp)
		return
	}

	// Attach SMTP core
	cores = append(cores, coreSmtp)

	// Tee all the cores together
	tee := zapcore.NewTee(cores...)

	// Initialize logger with cores
	logger := zap.New(tee).Sugar()

	// Make sure logger is flushed before shutting down
	defer func() {
		errSync := logger.Sync()
		if errSync != nil {
			t.Errorf("error while syncing: %s", errSync)
		}
	}()

	// Send some sample log messages
	logger.Infof("This info message is '%s'", "standard")    // Would not be sent by email
	logger.Warnf("This warn message is '%s'", "interesting") // Would be sent after 24 hours, if no more urgent message got triggered
	logger.Errorf("This error message is '%s'", "urgent")    // Would be sent after 5 minutes, will include all warnings until then
}
