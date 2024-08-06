/*
* ZapSmtp, a Zap (Golang) logger extension for sending urgent log messages via SMTP
*
* Copyright (c) Siemens AG, 2021.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package smtp

import (
	"fmt"
	"go.uber.org/zap/zapcore"
	"net/mail"
	"os"
)

type writeSyncer struct {
	server      string
	port        uint16
	username    string // Leave empty to skip authentication
	password    string // Leave empty to skip authentication
	from        mail.Address
	to          []mail.Address
	subject     string
	opensslPath string
	fromCert    []byte
	fromKey     []byte
	toCerts     [][]byte
	tempDir     string
}

// NewWriteSyncer returns a zap.WriteSyncer. It will save the needed certificate and key files every time a mail
// is sent out and remove them again immediately afterward. Some remarks for the parameters:
//   - The first five parameters must always be set.
//   - All the key and certificate files MUST NOT be password protected.
//   - All the key and certificate files MUST BE in either PEM or DER format.
//   - If neither key nor certificates files are provided the opensslPath and tempDir won't be used.
//   - If recipientCerts are provided the amount must match the number of recipients. The order does not matter though.
//     It is not possible to encrypt the message for only a subset of recipients.
func NewWriteSyncer(
	host string,
	port uint16,
	username string, // Leave empty to skip authentication
	password string, // Leave empty to skip authentication
	subject string,
	sender mail.Address,
	recipients []mail.Address,

	opensslPath string, // Can be omitted if neither signature nor encryption is desired
	senderCert string, // Can be omitted if no signature is desired
	senderKey string, // Can be omitted if no signature is desired
	recipientCerts []string, // Can be omitted if no encryption is desired
	tempDir string, // Can be omitted if neither signature nor encryption is desired

) (zapcore.WriteSyncer, error) {

	// Simple checks of the input parameters so the logger is less likely to fail during operation

	// Filter out empty recipients and also convert them to strings and save their addresses
	to := make([]mail.Address, 0, len(recipients))
	for _, r := range recipients {
		if r.Address != "" {
			to = append(to, r)
		}
	}
	recipients = to

	// Check addresses
	if len(recipients) == 0 {
		return nil, fmt.Errorf("no recipients specified")
	}
	if sender.Address == "" {
		return nil, fmt.Errorf("no sender specified")
	}

	// Check signature and encryption settings
	if (len(senderCert) > 0 || len(senderKey) > 0 || len(recipientCerts) > 0) && len(opensslPath) == 0 {
		return nil, fmt.Errorf("path to Openssl required")
	}

	if (len(senderCert) > 0 && len(senderKey) == 0) ||
		(len(senderCert) == 0 && len(senderKey) > 0) {
		return nil, fmt.Errorf("certificate and key required to sign")
	}

	// Filter out empty recipients certificates
	rCerts := make([]string, 0, len(recipientCerts))
	for _, cert := range recipientCerts {
		if cert != "" {
			rCerts = append(rCerts, cert)
		}
	}
	recipientCerts = rCerts
	if len(recipientCerts) > 0 && len(recipientCerts) != len(recipients) {
		return nil, fmt.Errorf("number of recipient certificates must match number of recipients")
	}

	if tempDir != "" && (len(recipientCerts) > 0 || (len(senderCert) > 0 && len(senderKey) > 0)) {
		if stat, err := os.Stat(tempDir); err != nil || !stat.IsDir() {
			return nil, fmt.Errorf("temporary directory does not exist")
		}
	}

	// Prepare memory
	var fromCert []byte
	var fromKey []byte
	var toCerts = make([][]byte, 0, len(recipientCerts))
	var err error

	// Load and convert signature certificate and key, if necessary
	if len(senderCert) > 0 && len(senderKey) > 0 {

		// Load signature certificate and key
		fromCert, err = os.ReadFile(senderCert)
		if err != nil {
			return nil, fmt.Errorf("could not load sender certificate: %s", err)
		}
		fromKey, err = os.ReadFile(senderKey)
		if err != nil {
			return nil, fmt.Errorf("could not load sender key: %s", err)
		}

		// Convert signature certificate and key if necessary
		fromCert, fromKey, err = PrepareSignatureKeys(opensslPath, fromCert, fromKey)
		if err != nil {
			return nil, fmt.Errorf("unable to convert signature key: %s", err)
		}
	}

	// Load and convert encryption certificates if necessary
	if len(recipientCerts) > 0 {

		// Load encryption keys
		for _, recipientCert := range recipientCerts {
			toCert, errLoad := os.ReadFile(recipientCert)
			if errLoad != nil {
				return nil, fmt.Errorf("could not load recipient certificate: %s", errLoad)
			}
			toCerts = append(toCerts, toCert)
		}

		// Convert encryption certificates if necessary
		toCerts, err = PrepareEncryptionKeys(opensslPath, toCerts)
		if err != nil {
			return nil, fmt.Errorf("unable to convert encryption key: %s", err)
		}
	}

	// Return initialized write syncer
	return &writeSyncer{
		server:      host,
		port:        port,
		username:    username,
		password:    password,
		from:        sender,
		to:          recipients,
		subject:     subject,
		opensslPath: opensslPath,
		fromCert:    fromCert,
		fromKey:     fromKey,
		toCerts:     toCerts,
		tempDir:     tempDir,
	}, nil
}

func (s *writeSyncer) Write(p []byte) (int, error) {

	// Don't send out a mail if the message is empty
	if len(p) == 0 {
		return 0, nil
	}

	// Send log messages by mail
	err := SendMail2(
		s.server,
		s.port,
		s.username,
		s.password,
		s.from,
		s.to,
		s.subject,
		p,
		s.opensslPath,
		s.fromCert,
		s.fromKey,
		s.toCerts,
		s.tempDir,
	)
	if err != nil {
		return 0, err
	}

	// Return length of payload
	return len(p), nil
}

func (s *writeSyncer) Sync() error {
	return nil
}
