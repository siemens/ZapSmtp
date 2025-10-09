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
	"bytes"
	"errors"
	"fmt"
	"net/smtp"
	"os"
	"os/exec"
	"strings"

	"github.com/siemens/ZapSmtp/openssl"
)

var ErrInvalidOpensslPath = errors.New("invalid OpenSSL path")
var ErrInvalidSigCert = errors.New("invalid signature certificate or key")
var ErrInvalidEncCerts = errors.New("invalid encryption certificates")

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

// SetAuth can be used to set SMTP authentication
func (mailer *Mailer) SetAuth(username string, password string) {
	mailer.smtpUser = username
	mailer.smtpPassword = password
}

// SetOpenssl can be used to set the OpenSSL path if signing or encryption will be used
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

// SetSignature can be used to set the signature certificates for MIME messag signing
func (mailer *Mailer) SetSignature(signatureCert []byte, signatureKey []byte) error {

	// Check if OpenSSL is set
	if mailer.pathOpenssl == "" {
		return ErrInvalidOpensslPath
	}

	// Check for plausibility
	if len(signatureCert) == 0 || len(signatureKey) == 0 {
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

// Send builds a message and optionally attaches files, signs and encrypts it and sends it out by mail
func (mailer *Mailer) Send(msg *Message) error {

	// Prepare encryption certificates by putting them into temporary files
	pathEncryptionCerts := make([]string, 0, len(msg.To))
	if len(msg.EncCerts) > 0 {

		// Check if OpenSSL is set
		if mailer.pathOpenssl == "" {
			return ErrInvalidOpensslPath
		}

		// Check encryption certificates
		if len(msg.To) != len(msg.EncCerts) {
			return ErrInvalidEncCerts
		}

		// Convert encryption certificates if necessary
		var err error
		msg.EncCerts, err = openssl.PrepareEncryptionKeys(mailer.pathOpenssl, msg.EncCerts)
		if err != nil {
			return fmt.Errorf("could not prepare encryption key: %s", err)
		}

		// Write encryption keys to disk, where it can be used by OpenSSL
		for _, encryptionCert := range msg.EncCerts {

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

	// Build mail message
	message, errMessage := msg.Message()
	if errMessage != nil {
		return errMessage
	}

	// Prepare necessary header values
	recipientStr := make([]string, len(msg.To))
	recipientAddr := make([]string, len(msg.To))
	for i, recipient := range msg.To {
		recipientStr[i] = recipient.String()
		recipientAddr[i] = recipient.Address
	}

	// SetSignature MIME message if prerequisites are fulfilled
	if msg.Sign && mailer.pathSignatureCert != "" && mailer.pathSignatureKey != "" {

		// Sign message
		msgSigned, errSign := openssl.SignMessage(mailer.pathOpenssl, mailer.pathSignatureCert, mailer.pathSignatureKey, message)
		if errSign != nil {
			return fmt.Errorf("could not sign message: %s", errSign)
		}

		// Address OpenSSL bug
		// OpenSSL tries to be helpful by converting \n to CRLF (\r\n), because email standards (RFC 5322, MIME) expect it.
		// If input already uses Windows line endings (\r\n), OpenSSL might insert extra \r, resulting in \r\r\n or worse.
		// This breaks Outlook and other S/MIME-compliant mail readers, because the structure becomes malformed.
		msgSigned = bytes.Replace(msgSigned, []byte("\r\r\n"), []byte("\r\n"), -1)

		// Prepare signed message with required headers (some got removed by OpenSSL)
		var msgSignedPrefixed bytes.Buffer
		msgSignedPrefixed.WriteString(fmt.Sprintf("From: %s\r\n", msg.From.String()))
		msgSignedPrefixed.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(recipientStr, ", ")))
		msgSignedPrefixed.WriteString(fmt.Sprintf("Subject: %s\r\n", msg.Subject))
		msgSignedPrefixed.Write(msgSigned)

		// Assign signed message
		message = msgSignedPrefixed.Bytes()
	}

	// Encrypt MIME message
	if len(pathEncryptionCerts) > 0 {
		var errEnc error
		message, errEnc = openssl.EncryptMessage(mailer.pathOpenssl, msg.From.Address, recipientAddr, msg.Subject, message, pathEncryptionCerts)
		if errEnc != nil {
			return fmt.Errorf("could not encrypt message: %s", errEnc)
		}
	}

	// Set authentication if desired
	var auth smtp.Auth
	if len(mailer.smtpUser) > 0 && len(mailer.smtpPassword) > 0 {
		auth = smtp.PlainAuth("", mailer.smtpUser, mailer.smtpPassword, mailer.smtpServer)
	}

	// Prepare some header values
	messageRecipients := make([]string, len(msg.To))
	for i, r := range msg.To {
		messageRecipients[i] = r.Address
	}

	// Connect to the server, authenticate, set the sender and recipient and send the email all in one step.
	errSend := smtp.SendMail(
		fmt.Sprintf("%s:%d", mailer.smtpServer, mailer.smtpPort),
		auth,
		msg.From.Address,
		messageRecipients,
		message,
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

// NewMailer constructs a new mailer with basic configuration.
// Detailed configuration needs to be set using the methods on Mailer.
func NewMailer(smtpServer string, smtpPort uint16) *Mailer {
	return &Mailer{
		smtpServer: smtpServer,
		smtpPort:   smtpPort,
	}
}
