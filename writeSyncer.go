/*
* ZapSmtp, a Zap (Golang) logger extension for sending urgent log messages via SMTP
*
* Copyright (c) Siemens AG, 2021.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package ZapSmtp

import (
	"fmt"
	"github.com/siemens/ZapSmtp/openssl"
	"github.com/siemens/ZapSmtp/smtp"
	"net/mail"
	"os"
)

// SmtpSyncer implements the zapcore.WriteSyncer interface and provides a logger plugin for sending logs by mail
// Ideally this SmtpSyncer is combined with core.DelayedCore in order to send bulks of log messages, rather
// than single ones!
type SmtpSyncer struct {
	smtpServer   string
	smtpPort     uint16
	smtpUser     string // Leave empty to skip authentication
	smtpPassword string // Leave empty to skip authentication

	mailSubject    string         // Subject to use for e-mails
	mailFrom       mail.Address   // E-mail address of the sender
	mailRecipients []mail.Address // E-mail addresses of recipients

	pathOpenssl         string
	pathSignatureCert   string   // Path to the signature certificate to sign the mail with
	pathSignatureKey    string   // Path to the signature key to sign the mail with
	pathEncryptionCerts []string // Path to the encryption certificates to sign the mail with, one per recipient
}

// NewSmtpSyncer returns a zap.SmtpSyncer. It will save the needed certificate and key files every time a mail
// is sent out and remove them again immediately afterward. Some remarks for the parameters:
//   - The first six parameters must always be set.
//   - All the key and certificate files MUST NOT be password protected.
//   - All the key and certificate files MUST BE in either PEM or DER format.
//   - If neither key nor certificates files are provided the pathOpenssl won't be used.
//   - If pathEncryptionCerts are provided the amount must match the number of recipients. The order does not matter though.
//     It is not possible to encrypt the message for only a subset of recipients.
func NewSmtpSyncer(
	smtpServer string,
	smtpPort uint16,
	smtpUser string, // Leave empty to skip authentication
	smtpPassword string, // Leave empty to skip authentication

	mailSubject string,
	mailFrom mail.Address,
	mailRecipients []mail.Address,

	pathOpenssl string, // Can be omitted if neither signature nor encryption is desired
	pathSignatureCert string, // Can be omitted if no signature is desired
	pathSignatureKey string, // Can be omitted if no signature is desired
	pathEncryptionCerts []string, // Can be omitted if no encryption is desired

) (*SmtpSyncer, func() error, error) {

	fnNil := func() error { return nil }

	// Check SMTP connection data
	if smtpServer == "" {
		return nil, fnNil, fmt.Errorf("no SMTP server provided")
	}
	if smtpPort == 0 {
		return nil, fnNil, fmt.Errorf("no SMTP port provided")
	}

	// Check origination address
	if mailFrom.Address == "" {
		return nil, fnNil, fmt.Errorf("no sender provided")
	}

	// Filter empty recipients
	to := make([]mail.Address, 0, len(mailRecipients))
	for _, r := range mailRecipients {
		if r.Address != "" {
			to = append(to, r)
		}
	}
	mailRecipients = to

	// Check recipient address
	if len(mailRecipients) == 0 {
		return nil, fnNil, fmt.Errorf("no recipients provided")
	}

	// Check OpenSSL path if necessary
	if (len(pathSignatureCert) > 0 || len(pathSignatureKey) > 0 || len(pathEncryptionCerts) > 0) && len(pathOpenssl) == 0 {
		return nil, fnNil, fmt.Errorf("no Openssl path provided")
	}

	// Check certificate files if necessary
	if (len(pathSignatureCert) > 0 && len(pathSignatureKey) == 0) ||
		(len(pathSignatureCert) == 0 && len(pathSignatureKey) > 0) {
		return nil, fnNil, fmt.Errorf("no certificate or key file provided")
	}

	// Filter empty certificates
	toCrts := make([]string, 0, len(pathEncryptionCerts))
	for _, cert := range pathEncryptionCerts {
		if cert != "" {
			toCrts = append(toCrts, cert)
		}
	}
	pathEncryptionCerts = toCrts

	// Check recipient certificate
	if len(pathEncryptionCerts) > 0 && len(pathEncryptionCerts) != len(mailRecipients) {
		return nil, fnNil, fmt.Errorf("invalid amount of recipient certificates provided")
	}

	// Prepare memory
	var err error
	var signatureCert []byte
	var signatureKey []byte
	var encryptionCerts = make([][]byte, 0, len(pathEncryptionCerts))

	var pathTmpSigCert string
	var errSaveTmpSigCert error
	var pathTmpSigKey string
	var errSaveTmpSigKey error
	var pathTmpEncCerts = make([]string, 0, len(encryptionCerts))
	var errSaveTmpEncCert error

	// Load and convert signature certificate and key, if necessary
	if len(pathSignatureCert) > 0 && len(pathSignatureKey) > 0 {

		// Load signature certificate and key
		signatureCert, err = os.ReadFile(pathSignatureCert)
		if err != nil {
			return nil, fnNil, fmt.Errorf("could not read sender certificate: %s", err)
		}
		signatureKey, err = os.ReadFile(pathSignatureKey)
		if err != nil {
			return nil, fnNil, fmt.Errorf("could not read sender key: %s", err)
		}

		// Convert signature certificate and key, if necessary
		signatureCert, signatureKey, err = openssl.PrepareSignatureKeys(pathOpenssl, signatureCert, signatureKey)
		if err != nil {
			return nil, fnNil, fmt.Errorf("could not convert signature key: %s", err)
		}

		// Write signature certificate and key to temporary files for later usage
		pathTmpSigCert, errSaveTmpSigCert = smtp.SaveToTemp(signatureCert, "openssl-signature-cert-*.pem")
		pathTmpSigKey, errSaveTmpSigKey = smtp.SaveToTemp(signatureKey, "openssl-signature-key-*.pem")
	}

	// Load and convert encryption certificates, if necessary
	if len(pathEncryptionCerts) > 0 {

		// Load encryption keys
		for _, toCert := range pathEncryptionCerts {
			recipientCert, errRead := os.ReadFile(toCert)
			if errRead != nil {
				return nil, fnNil, fmt.Errorf("could not read recipient certificate: %s", errRead)
			}
			encryptionCerts = append(encryptionCerts, recipientCert)
		}

		// Convert encryption certificates, if necessary
		encryptionCerts, err = openssl.PrepareEncryptionKeys(pathOpenssl, encryptionCerts)
		if err != nil {
			return nil, fnNil, fmt.Errorf("could not to convert encryption key: %s", err)
		}

		// Write encryption keys to temporary files for later usage
		for _, encryptionCert := range encryptionCerts {
			var pathTmpEncCert string
			pathTmpEncCert, errSaveTmpEncCert = smtp.SaveToTemp(encryptionCert, "openssl-encryption-cert-*.pem")
			if errSaveTmpEncCert != nil {
				break
			}
			pathTmpEncCerts = append(pathTmpEncCerts, pathTmpEncCert)
		}
	}

	// Prepare cleanup function to return
	fnCleanup := func() error {
		_ = os.Remove(pathTmpSigCert)
		_ = os.Remove(pathTmpSigKey)
		for _, pathTmpEncCert := range pathTmpEncCerts {
			_ = os.Remove(pathTmpEncCert)
		}
		return nil
	}

	// Cleanup and return error if temporary files could not be prepared
	if errSaveTmpSigCert != nil {
		_ = fnCleanup()
		return nil, fnNil, fmt.Errorf("could not prepare signature certificate: %s", errSaveTmpSigCert)
	}
	if errSaveTmpSigKey != nil {
		_ = fnCleanup()
		return nil, fnNil, fmt.Errorf("could not prepare signature key: %s", errSaveTmpSigKey)
	}
	if errSaveTmpEncCert != nil {
		_ = fnCleanup()
		return nil, fnNil, fmt.Errorf("could not prepare encryption key: %s", errSaveTmpEncCert)
	}

	// Return initialized write syncer
	return &SmtpSyncer{
		smtpServer:   smtpServer,
		smtpPort:     smtpPort,
		smtpUser:     smtpUser,
		smtpPassword: smtpPassword,

		mailFrom:       mailFrom,
		mailRecipients: mailRecipients,
		mailSubject:    mailSubject,

		pathOpenssl:         pathOpenssl,
		pathSignatureCert:   pathTmpSigCert,
		pathSignatureKey:    pathTmpSigKey,
		pathEncryptionCerts: pathTmpEncCerts,
	}, fnCleanup, nil
}

func (s *SmtpSyncer) Write(p []byte) (int, error) {

	// Don't send out a mail if the message is empty
	if len(p) == 0 {
		return 0, nil
	}

	// Send log messages by mail
	err := smtp.SendMail(
		s.smtpServer,
		s.smtpPort,
		s.smtpUser,
		s.smtpPassword,
		s.mailFrom,
		s.mailRecipients,
		s.mailSubject,
		p,
		s.pathOpenssl,
		s.pathSignatureCert,
		s.pathSignatureKey,
		s.pathEncryptionCerts,
	)
	if err != nil {
		return 0, err
	}

	// Return length of payload
	return len(p), nil
}

func (s *SmtpSyncer) Sync() error {
	return nil // Writes are sent out immediately, nothing to sync
}
