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
	"net/mail"
	"os"
	"testing"
	"time"

	"github.com/siemens/ZapSmtp"
	"github.com/siemens/ZapSmtp/_test"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func Test_example(t *testing.T) {

	// Prepare memory for Zap cores
	cores := make([]zapcore.Core, 0, 2)

	// Prepare encoder
	encConf := zap.NewDevelopmentEncoderConfig()
	enc := zapcore.NewConsoleEncoder(encConf)

	/*
	 * Console logger
	 */

	// Prepare console writeSyncer
	consoleWriteSyncer := zapcore.Lock(os.Stdout)

	// Prepare console core
	consoleCore := zapcore.NewCore(enc, consoleWriteSyncer, zapcore.DebugLevel)

	// Attach console core
	cores = append(cores, consoleCore)

	/*
	 * SMTP logger
	 */

	// Prepare SMTP writeSyncer
	smtpWriteSyncer, fnCleanup, errSmtpWriteSyncer := ZapSmtp.NewSmtpSyncer(
		_test.SmtpServer,
		_test.SmtpPort,
		_test.SmtpUser,
		_test.SmtpPassword,

		"Example Logger",
		_test.MailFrom,
		[]mail.Address{_test.MailTo},

		false,

		_test.OpensslPath,
		"",
		"",
		nil,
	)
	if errSmtpWriteSyncer != nil {
		t.Errorf("could not initilialize SMTP writeSyncer: %s", errSmtpWriteSyncer)
		return
	}

	// Cleanup SMTP writeSyncer (if you are using it with signature or encryption).
	// OpenSSL can only receive one argument via Stdin, which is the message. Other arguments, such as
	// signature or encryption keys must be passed as file paths in a PEM format. The SMTP writeSyncer
	// prepares the necessary files as temporary files in the required format and uses them throughout
	// its lifetime. You are responsible for cleaning them up on exit, Zap logger cannot not take care
	// of that automatically!
	defer func() { _ = fnCleanup() }()

	// Prepare SMTP core
	smtpCore, errSmtpCore := ZapSmtp.NewDelayedCore(
		zapcore.WarnLevel,
		enc,
		smtpWriteSyncer,
		zapcore.ErrorLevel,
		time.Hour*24,
		time.Minute*5,
	)
	if errSmtpCore != nil {
		t.Errorf("could not initilialize SMTP core: %s", errSmtpCore)
		return
	}

	// Attach SMTP core
	cores = append(cores, smtpCore)

	// Tee all the cores together
	// You could also initialize a single core with teed writeSyncers,
	// but you wouldn't be able to set different log activation levels for them.
	coresTeed := zapcore.NewTee(cores...)

	// Initialize logger with cores
	logger := zap.New(coresTeed).Sugar()

	// Make sure logger is flushed before shutting down. The SMTP writeSyncer does not need to be flushed,
	// but the delayed core might still have unsent messages queued.
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
