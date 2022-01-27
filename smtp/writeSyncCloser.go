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
	"go.uber.org/multierr"
	"go.uber.org/zap"
	"net/mail"
	"os"
)

type writeSyncCloser struct {
	*writeSyncer
	fromCert string
	fromKey  string
	toCerts  []string
}

// NewWriteSyncCloser wraps a smtp.writeSyncer. It will safe the needed certificate and key files at initialization
// instead of creating it every time a mail is sent out. The files will be removed by calling Close. If an error occurs
// the files will be automatically removed again. For more information on the parameters take a look at NewWriteSyncer.
func NewWriteSyncCloser(
	host string,
	port uint16,
	username string, // Leave empty to skip authentication
	password string, // Leave empty to skip authentication
	subject string,
	sender mail.Address,
	recipients []mail.Address,
	opensslPath string,
	senderCert string,
	senderKey string,
	recipientCerts []string,
	tempDir string,
) (zap.Sink, error) {

	ws, err := NewWriteSyncer(
		host,
		port,
		username,
		password,
		subject,
		sender,
		recipients,
		opensslPath,
		senderCert,
		senderKey,
		recipientCerts,
		tempDir,
	)
	if err != nil {
		return nil, err
	}
	sws := ws.(*writeSyncer)

	sink := &writeSyncCloser{writeSyncer: sws}

	// Create temporary files for all the certificates and the key. Use Anonymous function so we can handle errors
	// and subsequent clean-up better
	err = func() error {
		if len(sws.fromCert) > 0 {
			sink.fromCert, err = saveToTemp(sws.fromCert, tempDir)
			if err != nil {
				return fmt.Errorf("sender certificate: %s", err)
			}
		}

		if len(sws.fromKey) > 0 {
			sink.fromKey, err = saveToTemp(sws.fromKey, tempDir)
			if err != nil {
				return fmt.Errorf("sender key: %s", err)
			}
		}

		for _, toCert := range sws.toCerts {
			cert, err := saveToTemp(toCert, tempDir)
			if err != nil {
				return fmt.Errorf("recipient certificate: %s", err)
			}
			sink.toCerts = append(sink.toCerts, cert)
		}

		return nil
	}()
	if err != nil {
		errC := sink.Close()
		if errC != nil {
			err = multierr.Append(err, errC)
		}
		return nil, err
	}

	return sink, nil
}

func (s *writeSyncCloser) Write(p []byte) (int, error) {

	// Don't send out a mail if the message is empty
	if len(p) == 0 {
		return 0, nil
	}

	// Send log messages by mail
	err := SendMail(
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
	)
	if err != nil {
		return 0, err
	}

	// Return length of payload
	return len(p), nil
}

func (s *writeSyncCloser) Close() error {
	var errs error

	// Remove the previously created files
	if s.fromCert != "" {
		err := os.Remove(s.fromCert)
		if err != nil {
			errs = multierr.Append(errs, err)
		}
	}
	if s.fromKey != "" {
		err := os.Remove(s.fromKey)
		if err != nil {
			errs = multierr.Append(errs, err)
		}
	}

	for _, toCert := range s.toCerts {
		if toCert != "" {
			err := os.Remove(toCert)
			if err != nil {
				errs = multierr.Append(errs, err)
			}
		}
	}

	return errs
}
