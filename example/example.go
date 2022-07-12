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
	"fmt"
	"github.com/siemens/ZapSmtp/cores"
	"github.com/siemens/ZapSmtp/smtp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"net/mail"
	"os"
	"time"
)

// InitConsoleCore creates a new core for logging to the console according to the provided configuration
func initConsoleCore(level zapcore.Level) (zapcore.Core, error) {

	ws := zapcore.Lock(os.Stdout)

	// Create the encoder. We prefer to have a custom Name (/Tag) Encoder
	encConf := zap.NewDevelopmentEncoderConfig()
	enc := zapcore.NewConsoleEncoder(encConf)

	// Create the core
	return zapcore.NewCore(enc, ws, level), nil
}

func initSmtpCore(
	level zapcore.Level,
	levelPriority zapcore.Level,
	delay time.Duration,
	delayPriority time.Duration,
	server string,
	port uint16,
	username string, // Leave empty to skip authentication
	password string, // Leave empty to skip authentication
	subject string,
	sender mail.Address,
	recipients []mail.Address,
	opensslPath string,
	signatureCertPath string,
	signatureKeyPath string,
	encryptionCertPaths []string,
	tempDir string,
) (zapcore.Core, func() error, error) {

	// Prepare SMTP sink
	sink, errSink := smtp.NewWriteSyncCloser(
		server,
		port,
		username,
		password,
		subject,
		sender,
		recipients,
		opensslPath,
		signatureCertPath,
		signatureKeyPath,
		encryptionCertPaths,
		tempDir,
	)
	if errSink != nil {
		return nil, nil, fmt.Errorf("could not initilialize SMTP sink: %s", errSink)
	}

	// Create the encoder. We prefer to have a custom Name (/Tag) Encoder
	encConf := zap.NewDevelopmentEncoderConfig()
	enc := zapcore.NewConsoleEncoder(encConf)

	// Initialize SMTP core
	core, errCore := cores.NewDelayedCore(level, enc, sink, levelPriority, delay, delayPriority)
	if errCore != nil {

		// Prepare base error message
		errCore = fmt.Errorf("could not initilialize SMTP core: %s", errCore)

		// Close the newly created files
		_ = sink.Close()

		// Return error
		return nil, nil, errCore
	}

	// Return initialized core and associated close function
	return core, sink.Close, nil
}
