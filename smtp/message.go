package smtp

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// Message holds all necessary information and data to be sent by mail and is intended to ease the process of
// building a valid MIME message. It offers optional attributes to indicate desired signing and encryption.
// Signing and encryption has to be done by the Mailer.
type Message struct {
	From    mail.Address
	To      []mail.Address
	Subject string

	// Actionable attributes
	Sign     bool     // Whether the message should be signed
	EncCerts [][]byte // Whether the message should be encrypted and the applicable encryption certificates

	// Raw mail body
	rawMessage     []byte
	rawAttachments map[string][]byte

	// Raw mail attributes
	html bool // Whether the message contains HTML content or only plaintext
}

// EnableHtml enables sending HTML MIME messages. By default, only plain text messages are sent.
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

// SetSigning indicates desired signing for this message.
// Signing is executed later by the Mailer.
func (message *Message) SetSigning() {
	message.Sign = true
}

// SetEncryption indicates desired encryption by setting the encryption certificates for this message.
// Encryption is executed later by the Mailer.
func (message *Message) SetEncryption(encryptionCerts [][]byte) error {

	// Check encryption certificates are defined
	if len(message.To) != len(encryptionCerts) {
		return ErrInvalidEncCerts
	}

	// Enable encryption
	message.EncCerts = encryptionCerts

	// Return nil as everything went fine
	return nil
}

// Message builds the message including all MIME headers and file
// attachments and returns it as []byte ready to be sent by the Mailer.
// The message is yet unsigned and unencrypted, it has to be done by the Mailer.
func (message *Message) Message() ([]byte, error) {

	// Prepare memory
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	boundary := writer.Boundary()

	// Write headers
	toStrs := make([]string, len(message.To))
	for i, r := range message.To {
		toStrs[i] = r.String()
	}

	// Write headers
	buf.WriteString(fmt.Sprintf("From: %s\r\n", message.From.String()))
	buf.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(toStrs, ", ")))
	buf.WriteString(fmt.Sprintf("Subject: %s\r\n", strings.NewReplacer("\r", " ", "\n", " ").Replace(message.Subject)))
	buf.WriteString(fmt.Sprintf("Date: %s\r\n", time.Now().Format(time.RFC1123Z)))
	buf.WriteString("MIME-Version: 1.0\r\n")
	buf.WriteString(fmt.Sprintf("Content-Type: multipart/mixed; boundary=%s\r\n", boundary))
	buf.WriteString("\r\n")

	// Determine Content-Type for body
	var contentType string
	if message.html {
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
	if _, errQpWrite := qpWriter.Write(message.rawMessage); errQpWrite != nil {
		return nil, fmt.Errorf("could not write body part: %w", errQpWrite)
	}
	_ = qpWriter.Close()

	// Add attachments
	for filename, content := range message.rawAttachments {

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

// NewMessage constructs a new message with basic content that can be sent by the Mailer.
// Detailed configuration needs to be set using the methods on Message.
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
