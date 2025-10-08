package smtp

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/siemens/ZapSmtp/openssl"
)

var ErrInvalidOpensslPath = errors.New("invalid OpenSSL path")
var ErrInvalidSigCert = errors.New("invalid signature certificate or key")
var ErrInvalidEncCerts = errors.New("invalid encryption certificates")

// Message holds all necessary information and data to be sent by mail and is intended to ease the process of
// building a valid MIME message. It offers optional functionality to take care of optional signature and encryption.
type Message struct {
	From    mail.Address
	To      []mail.Address
	Subject string

	// Raw mail body
	rawMessage     []byte
	rawAttachments map[string][]byte

	// Signature and encryption details
	pathOpenssl         string
	pathSignatureCert   string
	pathSignatureKey    string
	pathEncryptionCerts []string

	// State flags
	html bool // Whether to send mail with HTML content or as plaintext
	sign bool // Whether to sign the message
}

// EnableHtml enables sending HTML messages. By default only plain text messages are sent.
func (message *Message) EnableHtml() {
	message.html = true
}

// Attach adds attachments to the message
func (message *Message) Attach(paths ...string) error {

	// Read files and prepare content map for attachments
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		message.rawAttachments[filepath.Base(p)] = data
	}

	// Return nil as everything went fine
	return nil
}

// Sign enables signing of the MIME message. Signing is executed later during building of the message.
func (message *Message) Sign() error {

	// Check if OpenSSL is set
	if message.pathOpenssl == "" {
		return ErrInvalidOpensslPath
	}

	// Check if signature certificate is set
	if message.pathSignatureCert == "" || message.pathSignatureKey == "" {
		return ErrInvalidSigCert
	}

	// Enable signing
	message.sign = true

	// Return nil as everything went fine
	return nil
}

// Encrypt enables encryption of the MIME message. Encryption is executed later during building of the message.
func (message *Message) Encrypt(encCertsPaths []string) error {

	// Check if OpenSSL is set
	if message.pathOpenssl == "" {
		return ErrInvalidOpensslPath
	}

	// Check encryption certificates are defined
	if len(message.To) != len(encCertsPaths) {
		return ErrInvalidEncCerts
	}

	// Check paths of encryption certificates
	for _, pathEncryptionCert := range message.pathEncryptionCerts {
		if _, err := os.Stat(pathEncryptionCert); errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("invalid encryption certificate '%s'", pathEncryptionCert)
		}
	}

	// Enable encryption
	message.pathEncryptionCerts = encCertsPaths

	// Return nil as everything went fine
	return nil
}

// Message builds and optionally signs and encrypts the prepared message and returns
// it as []byte ready to be sent by the Mailer.
func (message *Message) Message() ([]byte, error) {

	// Prepare necessary header values
	toStrs := make([]string, len(message.To))
	toAddrs := make([]string, len(message.To))
	for i, r := range message.To {
		toStrs[i] = r.String()
		toAddrs[i] = r.Address
	}

	// Build mime message
	msg, err := buildMimeMessage(message.From, message.To, message.Subject, message.rawMessage, message.rawAttachments, message.html)
	if err != nil {
		return nil, fmt.Errorf("could not build MIME message: %w", err)
	}

	// Sign MIME message
	if message.sign {

		// Sign message
		msgSigned, errSign := openssl.SignMessage(message.pathOpenssl, message.pathSignatureCert, message.pathSignatureKey, msg)
		if errSign != nil {
			return nil, fmt.Errorf("could not sign message: %s", errSign)
		}

		// Address OpenSSL bug
		// OpenSSL tries to be helpful by converting \n to CRLF (\r\n), because email standards (RFC 5322, MIME) expect it.
		// If input already uses Windows line endings (\r\n), OpenSSL might insert extra \r, resulting in \r\r\n or worse.
		// This breaks Outlook and other S/MIME-compliant mail readers, because the structure becomes malformed.
		msgSigned = bytes.Replace(msgSigned, []byte("\r\r\n"), []byte("\r\n"), -1)

		// Prepare signed message with required headers (some got removed by OpenSSL)
		var msgSignedPrefixed bytes.Buffer
		msgSignedPrefixed.WriteString(fmt.Sprintf("From: %s\r\n", message.From.String()))
		msgSignedPrefixed.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(toStrs, ", ")))
		msgSignedPrefixed.WriteString(fmt.Sprintf("Subject: %s\r\n", message.Subject))
		msgSignedPrefixed.Write(msgSigned)

		// Assign signed message
		msg = msgSignedPrefixed.Bytes()
	}

	// Encrypt MIME message
	if len(message.pathEncryptionCerts) > 0 {
		var errEnc error
		msg, errEnc = openssl.EncryptMessage(message.pathOpenssl, message.From.Address, toAddrs, message.Subject, msg, message.pathEncryptionCerts)
		if errEnc != nil {
			return nil, fmt.Errorf("could not encrypt message: %s", errEnc)
		}
	}

	// Return generated message
	return msg, nil
}

// buildMimeMessage builds the MIME mail message from the given data. It can either generate plain text or HTML mail.
func buildMimeMessage(
	mailFrom mail.Address,
	mailTo []mail.Address,
	mailSubject string,
	mailMessage []byte,
	mailAttachments map[string][]byte,
	html bool,
) ([]byte, error) {

	// Prepare memory
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	boundary := writer.Boundary()

	// Write headers
	toStrs := make([]string, len(mailTo))
	for i, r := range mailTo {
		toStrs[i] = r.String()
	}

	// Write headers
	buf.WriteString(fmt.Sprintf("From: %s\r\n", mailFrom.String()))
	buf.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(toStrs, ", ")))
	buf.WriteString(fmt.Sprintf("Subject: %s\r\n", strings.NewReplacer("\r", " ", "\n", " ").Replace(mailSubject)))
	buf.WriteString(fmt.Sprintf("Date: %s\r\n", time.Now().Format(time.RFC1123Z)))
	buf.WriteString("MIME-Version: 1.0\r\n")
	buf.WriteString(fmt.Sprintf("Content-Type: multipart/mixed; boundary=%s\r\n", boundary))
	buf.WriteString("\r\n")

	// Determine Content-Type for body
	var contentType string
	if html {
		contentType = "text/html; charset=utf-8"
	} else {
		contentType = "text/plain; charset=utf-8"
	}

	// Add plain text body
	partHeader := textproto.MIMEHeader{}
	partHeader.Set("Content-Type", contentType)
	partHeader.Set("Content-Transfer-Encoding", "quoted-printable")
	bodyPart, err := writer.CreatePart(partHeader)
	if err != nil {
		return nil, fmt.Errorf("could not create body part: %w", err)
	}
	qpWriter := quotedprintable.NewWriter(bodyPart)
	if _, errQpWrite := qpWriter.Write(mailMessage); errQpWrite != nil {
		return nil, fmt.Errorf("could not write body part: %w", errQpWrite)
	}
	_ = qpWriter.Close()

	// Add attachments
	for filename, content := range mailAttachments {

		// Prepare mime type
		mimeType := mime.TypeByExtension(path.Ext(filename))
		if mimeType == "" {
			mimeType = "application/octet-stream"
		}

		// Add attachment to body
		partHeaderAttachment := textproto.MIMEHeader{}
		partHeaderAttachment.Set("Content-Type", fmt.Sprintf("%s; name=%q", mimeType, filename))
		partHeaderAttachment.Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
		partHeaderAttachment.Set("Content-Transfer-Encoding", "base64")
		partWriter, errPartWriter := writer.CreatePart(partHeaderAttachment)
		if errPartWriter != nil {
			return nil, fmt.Errorf("could not create attachment part for '%s': %w", filename, err)
		}
		b64Writer := base64.NewEncoder(base64.StdEncoding, partWriter)
		if _, errWrite := b64Writer.Write(content); errWrite != nil {
			return nil, fmt.Errorf("could not write attachment part for '%s': %w", filename, err)
		}
		_ = b64Writer.Close()
	}

	_ = writer.Close()
	return buf.Bytes(), nil
}

/*
 *
 * Some methods that might be necessary if Message is used standalone outside the context of Mailer.
 *
 */

func (message *Message) SetOpenssl(path string) error {

	// Verify OpenSSL executable path
	if _, err := exec.LookPath(path); err != nil {
		return ErrInvalidOpensslPath
	}

	// Set OpenSSL paths
	message.pathOpenssl = path

	// Return nil as everything went fine
	return nil
}

func (message *Message) SetSignature(pathSigCert string, pathSigKey string) error {

	// Check if OpenSSL is set
	if message.pathOpenssl == "" {
		return ErrInvalidOpensslPath
	}

	// Check certificate paths
	if _, err := os.Stat(pathSigCert); errors.Is(err, os.ErrNotExist) {
		return ErrInvalidSigCert
	}
	if _, err := os.Stat(pathSigKey); errors.Is(err, os.ErrNotExist) {
		return ErrInvalidSigCert
	}

	// Set certificate paths
	message.pathSignatureCert = pathSigCert
	message.pathSignatureKey = pathSigKey

	// Return nil as everything went fine
	return nil
}

// NewMessage creates a basic message with a dedicated OpenSSL path and a dedicated optional signature certificate.
// This function is only necessary if not used together with Mailer.
func NewMessage(
	mailFrom mail.Address,
	mailTo []mail.Address,
	mailSubject string,
	mailMessage []byte,
) (*Message, error) {
	return &Message{
		From:           mailFrom,
		To:             mailTo,
		Subject:        mailSubject,
		rawMessage:     mailMessage,
		rawAttachments: make(map[string][]byte),
	}, nil
}
