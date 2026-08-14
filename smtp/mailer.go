/*
* ZapSmtp, a Zap (Golang) logger extension for sending urgent log messages via SMTP
*
* Copyright (c) Siemens AG, 2021-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package smtp

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/siemens/ZapSmtp/openssl"
)

const defaultSmtpTimeout = time.Second * 30

var ErrInvalidOpensslPath = errors.New("invalid OpenSSL path")
var ErrInvalidSigCert = errors.New("invalid signature certificate or key")
var ErrInvalidEncCerts = errors.New("invalid encryption certificates")

type Mailer struct {
	smtpServer string
	smtpPort   uint16
	timeout    time.Duration

	// Authentication details (optional)
	smtpUser     string
	smtpPassword string

	// Signature and encryption details
	pathOpenssl       string // Can be omitted if neither signature nor encryption is desired
	pathSignatureCert string // path to the signature certificate of sender. Can be omitted if no signature is desired.
	pathSignatureKey  string // path to the signature key of sender. Can be omitted if no signature is desired.
}

// NewMailer constructs a new mailer with basic configuration.
// Detailed configuration needs to be set using the methods on Mailer.
func NewMailer(smtpServer string, smtpPort uint16) *Mailer {
	return &Mailer{
		smtpServer: smtpServer,
		smtpPort:   smtpPort,
		timeout:    defaultSmtpTimeout,
	}
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

// SetSignature can be used to set the signature certificates for MIME message signing
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
	var errPrepare error
	signatureCert, signatureKey, errPrepare = openssl.PrepareSignatureKeys(mailer.pathOpenssl, signatureCert, signatureKey)
	if errPrepare != nil {
		return fmt.Errorf("could not prepare signature certificate and key: %w", errPrepare)
	}

	// Write signing certificate to disk, where it can be used by OpenSSL
	pathSignatureCert, errPathSignatureCert := SaveToTemp(signatureCert, "openssl-signature-cert-*.pem")
	if errPathSignatureCert != nil {
		return fmt.Errorf("could not prepare signature certificate: %w", errPathSignatureCert)
	}

	// Write signing key to disk, where it can be used by OpenSSL
	pathSignatureKey, errPathSignatureKey := SaveToTemp(signatureKey, "openssl-signature-key-*.pem")
	if errPathSignatureKey != nil {
		return fmt.Errorf("could not prepare signature key: %w", errPathSignatureKey)
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
		var errPrepareEnc error
		msg.EncCerts, errPrepareEnc = openssl.PrepareEncryptionKeys(mailer.pathOpenssl, msg.EncCerts)
		if errPrepareEnc != nil {
			return fmt.Errorf("could not prepare encryption key: %w", errPrepareEnc)
		}

		// Write encryption keys to disk, where it can be used by OpenSSL
		for _, encryptionCert := range msg.EncCerts {

			// Write certificate to disk
			pathEncryptionCert, errPathEncryptionCert := SaveToTemp(encryptionCert, "openssl-encryption-cert-*.pem")
			if errPathEncryptionCert != nil {
				return fmt.Errorf("could not prepare encryption key: %w", errPathEncryptionCert)
			}

			// Remember path and register cleanup
			pathEncryptionCerts = append(pathEncryptionCerts, pathEncryptionCert)
		}

		// Cleanup temporary encryption certificate files on return
		defer func() {
			for _, p := range pathEncryptionCerts {
				_ = os.Remove(p)
			}
		}()
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

	// Sanitize message subject to make it safe from header injection attempts
	msgSubject := strings.NewReplacer("\r", " ", "\n", " ").Replace(msg.Subject)

	// SetSignature MIME message if prerequisites are fulfilled
	if msg.Sign && mailer.pathSignatureCert != "" && mailer.pathSignatureKey != "" {

		// Sign message
		msgSigned, errSign := openssl.SignMessage(mailer.pathOpenssl, mailer.pathSignatureCert, mailer.pathSignatureKey, message)
		if errSign != nil {
			return fmt.Errorf("could not sign message: %w", errSign)
		}

		// Address OpenSSL bug
		// OpenSSL tries to be helpful by converting \n to CRLF (\r\n), because email standards (RFC 5322, MIME) expect it.
		// If input already uses Windows line endings (\r\n), OpenSSL might insert extra \r, resulting in \r\r\n or worse.
		// This breaks Outlook and other S/MIME-compliant mail readers, because the structure becomes malformed.
		msgSigned = bytes.ReplaceAll(msgSigned, []byte("\r\r\n"), []byte("\r\n"))

		// Prepare signed message with required headers (some got removed by OpenSSL)
		var msgSignedPrefixed bytes.Buffer
		_, _ = msgSignedPrefixed.WriteString("From: " + msg.From.String() + "\r\n")
		_, _ = msgSignedPrefixed.WriteString("To: " + strings.Join(recipientStr, ", ") + "\r\n")
		_, _ = msgSignedPrefixed.WriteString("Subject: " + mime.QEncoding.Encode("utf-8", msgSubject) + "\r\n")
		_, _ = msgSignedPrefixed.Write(msgSigned)

		// Assign signed message
		message = msgSignedPrefixed.Bytes()
	}

	// Encrypt MIME message
	if len(pathEncryptionCerts) > 0 {
		var errEnc error
		message, errEnc = openssl.EncryptMessage(mailer.pathOpenssl, msg.From.Address, recipientAddr, msgSubject, message, pathEncryptionCerts)
		if errEnc != nil {
			return fmt.Errorf("could not encrypt message: %w", errEnc)
		}
	}

	// Send the message while distinguishing delivery errors from later session cleanup errors
	errSend := mailer.sendMessage(msg.From.Address, recipientAddr, message)
	if errSend != nil {
		return fmt.Errorf("could not send mail: %w", errSend)
	}

	// Return nil as everything went fine
	return nil
}

// Close cleans up remaining temporary files
func (mailer *Mailer) Close() {
	_ = os.Remove(mailer.pathSignatureCert)
	_ = os.Remove(mailer.pathSignatureKey)
}

// sendMessage runs the SMTP transaction and treats a message as delivered after the server accepts its DATA
func (mailer *Mailer) sendMessage(mailFrom string, mailRecipients []string, message []byte) error {

	// Connect with a bounded dial and an IPv6-safe address
	smtpAddress := net.JoinHostPort(mailer.smtpServer, strconv.Itoa(int(mailer.smtpPort)))
	connection, errConnection := net.DialTimeout("tcp", smtpAddress, mailer.timeout)
	if errConnection != nil {
		return fmt.Errorf("could not connect to SMTP server: %w", errConnection)
	}

	// Bound the complete SMTP transaction, including greeting, TLS, DATA, and QUIT
	errDeadline := connection.SetDeadline(time.Now().Add(mailer.timeout))
	if errDeadline != nil {
		_ = connection.Close()
		return fmt.Errorf("could not set SMTP connection deadline: %w", errDeadline)
	}

	// Initialize the SMTP protocol after the deadline is active
	client, errClient := smtp.NewClient(connection, mailer.smtpServer)
	if errClient != nil {
		_ = connection.Close()
		return fmt.Errorf("could not initialize SMTP session: %w", errClient)
	}
	defer func() { _ = client.Close() }()

	// Upgrade the connection when the server advertises STARTTLS
	if supportsStarttls, _ := client.Extension("STARTTLS"); supportsStarttls {
		tlsConfig := &tls.Config{ServerName: mailer.smtpServer}
		errStarttls := client.StartTLS(tlsConfig)
		if errStarttls != nil {
			return fmt.Errorf("could not start SMTP TLS session: %w", errStarttls)
		}
	}

	// Authenticate only when both credentials were configured
	if len(mailer.smtpUser) > 0 && len(mailer.smtpPassword) > 0 {
		if authentication, _ := client.Extension("AUTH"); !authentication {
			return errors.New("SMTP server does not support authentication")
		}
		auth := smtp.PlainAuth("", mailer.smtpUser, mailer.smtpPassword, mailer.smtpServer)
		errAuth := client.Auth(auth)
		if errAuth != nil {
			return fmt.Errorf("could not authenticate with SMTP server: %w", errAuth)
		}
	}

	// Define the SMTP envelope before transferring the message
	errFrom := client.Mail(mailFrom)
	if errFrom != nil {
		return fmt.Errorf("could not set SMTP sender: %w", errFrom)
	}
	for _, mailRecipient := range mailRecipients {
		errRecipient := client.Rcpt(mailRecipient)
		if errRecipient != nil {
			return fmt.Errorf("could not set SMTP recipient '%s': %w", mailRecipient, errRecipient)
		}
	}

	// Transfer the message body and wait for the server's acceptance response
	dataWriter, errDataWriter := client.Data()
	if errDataWriter != nil {
		return fmt.Errorf("could not start SMTP message transfer: %w", errDataWriter)
	}
	_, errWrite := dataWriter.Write(message)
	if errWrite != nil {
		return fmt.Errorf("could not write SMTP message: %w", errWrite)
	}
	errDataClose := dataWriter.Close()
	if errDataClose != nil {
		return fmt.Errorf("could not submit SMTP message: %w", errDataClose)
	}

	// Report session cleanup errors locally without retrying an already accepted message
	errQuit := client.Quit()
	if errQuit != nil {
		_, _ = fmt.Fprintf(os.Stderr, "ZapSMTP: Could not close SMTP session after the message was accepted: %v\n", errQuit)
	}

	// Return nil because the SMTP server accepted the message
	return nil
}
