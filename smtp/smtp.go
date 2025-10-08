/*
* ZapSmtp, a Zap (Golang) logger extension for sending urgent log messages via SMTP
*
* Copyright (c) Siemens AG, 2025.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package smtp

import (
	"fmt"
	"net/mail"
	"net/smtp"
	"os"
	"os/exec"

	"github.com/siemens/ZapSmtp/openssl"
)

type Mailer struct {
	smtpServer string
	smtpPort   uint16

	// Authentication details (optional)
	smtpUser     string
	smtpPassword string

	// Signature and encryption details
	pathOpenssl       string // Can be omitted if neither signature nor encryption is desired
	pathSignatureCert string // path to the signature certificate of sender. Can be omitted if no signature is desired.
	pathSignatureKey  string // path to the signature key of sender. Can be omitted if no signature is desired.
}

func (mailer *Mailer) SetAuth(username string, password string) {
	mailer.smtpUser = username
	mailer.smtpPassword = password
}

func (mailer *Mailer) SetOpenssl(path string) error {

	// Verify OpenSSL executable path
	if path != "" {
		if _, err := exec.LookPath(path); err != nil {
			return ErrInvalidOpensslPath
		}
	}

	// Set path
	mailer.pathOpenssl = path

	// Return nil as everything went fine
	return nil
}

func (mailer *Mailer) SetSignature(signatureCert []byte, signatureKey []byte) error {

	// Check if openssl is set
	if mailer.pathOpenssl == "" {
		return ErrInvalidOpensslPath
	}

	// Check for plausibility
	if signatureCert == nil || signatureKey == nil {
		return ErrInvalidSigCert
	}

	// Convert signature certificate and key if necessary
	var err error
	signatureCert, signatureKey, err = openssl.PrepareSignatureKeys(mailer.pathOpenssl, signatureCert, signatureKey)
	if err != nil {
		return fmt.Errorf("could not prepare signature certificate and key: %s", err)
	}

	// Write signing certificate to disk, where it can be used by OpenSSL
	pathSignatureCert, errPathSignatureCert := SaveToTemp(signatureCert, "openssl-signature-cert-*.pem")
	if errPathSignatureCert != nil {
		return fmt.Errorf("could not prepare signature certificate: %s", errPathSignatureCert)
	}

	// Write signing key to disk, where it can be used by OpenSSL
	pathSignatureKey, errPathSignatureKey := SaveToTemp(signatureKey, "openssl-signature-key-*.pem")
	if errPathSignatureKey != nil {
		return fmt.Errorf("could not prepare signature key: %s", errPathSignatureKey)
	}

	// Set signature certificate. Needs to be put into temporary file later, which
	// will be done temporarily by the sending function to ensure proper cleanup.
	mailer.pathSignatureCert = pathSignatureCert
	mailer.pathSignatureKey = pathSignatureKey

	// Return nil as everything went fine
	return nil
}

func (mailer *Mailer) Send(
	from mail.Address,
	to []mail.Address,
	toCerts [][]byte, // Optional encryption. One encryption certificate per recipient in 'to'.
	subject string,
	message []byte,
	attachments []string, // List of file paths to attach
	html bool,
) error {

	// Prepare encryption certificates
	pathEncryptionCerts := make([]string, 0, len(toCerts))
	if len(toCerts) > 0 {

		// Check if openssl is set
		if mailer.pathOpenssl == "" {
			return ErrInvalidOpensslPath
		}

		// Convert encryption certificates if necessary
		var err error
		toCerts, err = openssl.PrepareEncryptionKeys(mailer.pathOpenssl, toCerts)
		if err != nil {
			return fmt.Errorf("could not prepare encryption key: %s", err)
		}

		// Write encryption keys to disk, where it can be used by OpenSSL
		for _, encryptionCert := range toCerts {

			// Write certificate to disk
			pathEncryptionCert, errPathEncryptionCert := SaveToTemp(encryptionCert, "openssl-encryption-cert-*.pem")
			if errPathEncryptionCert != nil {
				return fmt.Errorf("could not prepare encryption key: %s", errPathEncryptionCert)
			}

			// Cleanup temporary file on return
			defer func() { _ = os.Remove(pathEncryptionCert) }()

			// Remember path
			pathEncryptionCerts = append(pathEncryptionCerts, pathEncryptionCert)
		}
	}

	// Prepare mail
	msg := mailer.newMessage(from, to, subject, message)

	// Add attachments
	errAttach := msg.Attach(attachments...)
	if errAttach != nil {
		return errAttach
	}

	// Enable signing if desired
	if mailer.pathSignatureCert != "" {
		errSign := msg.Sign()
		if errSign != nil {
			return errSign
		}
	}

	// Enable encryption if desired
	if len(pathEncryptionCerts) > 0 {
		errEncrypt := msg.Encrypt(pathEncryptionCerts)
		if errEncrypt != nil {
			return errEncrypt
		}
	}

	// Prepare some header values
	msgRecipients := make([]string, len(to))
	for i, r := range to {
		msgRecipients[i] = r.Address
	}

	// Enable HTML if desired
	if html {
		msg.EnableHtml()
	}

	// Build mail message
	msgCompiled, errMsgCompiled := msg.Message()
	if errMsgCompiled != nil {
		return errMsgCompiled
	}

	// Set authentication if desired
	var auth smtp.Auth
	if len(mailer.smtpUser) > 0 && len(mailer.smtpPassword) > 0 {
		auth = smtp.PlainAuth("", mailer.smtpUser, mailer.smtpPassword, mailer.smtpServer)
	}

	// Connect to the server, authenticate, set the sender and recipient and send the email all in one step.
	errSend := smtp.SendMail(
		fmt.Sprintf("%s:%d", mailer.smtpServer, mailer.smtpPort),
		auth,
		from.Address,
		msgRecipients,
		msgCompiled,
	)
	if errSend != nil {
		return fmt.Errorf("could not send mail: %s", errSend)
	}

	// Return nil as everything went fine
	return nil
}

// Close cleans up remaining temporary files
func (mailer *Mailer) Close() {
	_ = os.Remove(mailer.pathSignatureCert)
	_ = os.Remove(mailer.pathSignatureKey)
}

// newMessage creates a basic message in the context of an existing Mailer. The Mailer
func (mailer *Mailer) newMessage(from mail.Address, to []mail.Address, subject string, message []byte) *Message {
	return &Message{
		From:              from,
		To:                to,
		Subject:           subject,
		rawMessage:        message,
		rawAttachments:    make(map[string][]byte),
		pathOpenssl:       mailer.pathOpenssl,
		pathSignatureCert: mailer.pathSignatureCert,
		pathSignatureKey:  mailer.pathSignatureKey,
	}
}

// NewMailer constructs a new mailer with basic configuration.
// Detailed configuration needs to be set using the methods on Mailer.
func NewMailer(smtpServer string, smtpPort uint16) *Mailer {
	return &Mailer{
		smtpServer: smtpServer,
		smtpPort:   smtpPort,
	}
}

// SaveToTemp writes data to a newly created temporary file. The name of the created file is returned.
// You need to remove the file again when you are done! It's not done automatically, and the operating system
// might not do it either for a long time.
func SaveToTemp(data []byte, namePattern string) (string, error) {

	// Create temporary file and write the certificate to it
	tmpFile, errTmp := os.CreateTemp("", namePattern)
	if errTmp != nil {
		return "", fmt.Errorf("could not create temporary file: %s", errTmp)
	}

	// Get the path
	tmpPath := tmpFile.Name()

	// Write data to the file
	_, errWrite := tmpFile.Write(data)
	if errWrite != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("could not write temporary file: %s", errWrite)
	}

	// Clean up the file descriptor - file needs to be removed later on.
	errClose := tmpFile.Close()
	if errClose != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("could not close temporary file: %s", errClose)
	}

	// Return path of the temporary file
	return tmpPath, nil
}

// SendMail is a small helper function that can be used to send an email with a single function call.
func SendMail(
	smtpServer string,
	smtpPort uint16,
	smtpUsername string, // Optional credentials, can be left empty to skip authentication
	smtpPassword string, // Optional credentials, can be left empty to skip authentication
	mailFrom mail.Address,
	mailTo []mail.Address,
	mailToCerts [][]byte, // Optional encryption certificates, can be nil
	mailSubject string,
	mailBody []byte,
	pathMailAttachments []string, // Optional file attachments, can be nil
	pathOpenssl string, // Optional path to OpenSSL, only required for signatures and encryption
	signatureCert []byte, // Optional signature key, can be nil
	signatureKey []byte, // Optional signature key, can be nil
	html bool, // Whether to send the mail message as HTML content type or plaintext
) error {

	// Prepare Mailer
	mlr := NewMailer(smtpServer, smtpPort)

	// Make sure mailer is cleaned up
	defer mlr.Close()

	// Set authentication
	mlr.SetAuth(smtpUsername, smtpPassword)

	// Set OpenSSL path for optional signature or encryption
	errOpenssl := mlr.SetOpenssl(pathOpenssl)
	if errOpenssl != nil {
		return errOpenssl
	}

	// Enable signature if desired
	if signatureCert != nil && signatureKey != nil {
		errSignature := mlr.SetSignature(signatureCert, signatureKey)
		if errSignature != nil {
			return errSignature
		}
	}

	// Send mail
	errMail := mlr.Send(
		mailFrom,
		mailTo,
		mailToCerts,
		mailSubject,
		mailBody,
		pathMailAttachments, // List of file paths to attach
		html,
	)
	if errMail != nil {
		return errMail
	}

	// Return nil as everything went fine
	return nil
}
