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
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"
)

// TestMessage_Message_LargeAttachmentUsesFoldedBase64 verifies MIME attachment lines stay within 76 characters
func TestMessage_Message_LargeAttachmentUsesFoldedBase64(t *testing.T) {

	// Prepare a message with an attachment large enough to exceed the SMTP line limit without folding
	attachmentExpected := bytes.Repeat([]byte("attachment-content-"), 200)
	message, errMessage := NewMessage(
		mail.Address{Name: "Sender", Address: "sender@domain.tld"},
		[]mail.Address{{Name: "Recipient", Address: "recipient@domain.tld"}},
		"Attachment folding",
		[]byte("Body"),
	)
	if errMessage != nil {
		t.Errorf("NewMessage() error = '%v', want = nil", errMessage)
		return
	}
	message.rawAttachments["large.bin"] = attachmentExpected

	// Build and parse the MIME message through standard library readers
	messageRaw, errMessageRaw := message.Message()
	if errMessageRaw != nil {
		t.Errorf("Message() error = '%v', want = nil", errMessageRaw)
		return
	}
	messageParsed, errMessageParsed := mail.ReadMessage(bytes.NewReader(messageRaw))
	if errMessageParsed != nil {
		t.Errorf("mail.ReadMessage() error = '%v', want = nil", errMessageParsed)
		return
	}
	_, parameters, errContentType := mime.ParseMediaType(messageParsed.Header.Get("Content-Type"))
	if errContentType != nil {
		t.Errorf("mime.ParseMediaType() error = '%v', want = nil", errContentType)
		return
	}
	parts := multipart.NewReader(messageParsed.Body, parameters["boundary"])

	// Skip the body and read the attachment part
	_, errBodyPart := parts.NextPart()
	if errBodyPart != nil {
		t.Errorf("multipart.Reader.NextPart() body error = '%v', want = nil", errBodyPart)
		return
	}
	attachmentPart, errAttachmentPart := parts.NextPart()
	if errAttachmentPart != nil {
		t.Errorf("multipart.Reader.NextPart() attachment error = '%v', want = nil", errAttachmentPart)
		return
	}
	attachmentEncoded, errAttachmentEncoded := io.ReadAll(attachmentPart)
	if errAttachmentEncoded != nil {
		t.Errorf("io.ReadAll() error = '%v', want = nil", errAttachmentEncoded)
		return
	}

	// Verify every encoded line follows the MIME 76-character recommendation
	attachmentLines := strings.Split(strings.TrimSpace(string(attachmentEncoded)), "\r\n")
	for _, attachmentLine := range attachmentLines {
		if len(attachmentLine) > 76 {
			t.Errorf("Message() base64 line length = '%d', want <= '76'", len(attachmentLine))
			return
		}
	}

	// Verify folding does not change the decoded attachment content
	attachmentDecoded, errAttachmentDecoded := base64.StdEncoding.DecodeString(strings.Join(attachmentLines, ""))
	if errAttachmentDecoded != nil {
		t.Errorf("base64.DecodeString() error = '%v', want = nil", errAttachmentDecoded)
		return
	}
	if !bytes.Equal(attachmentDecoded, attachmentExpected) {
		t.Errorf("Message() attachment length = '%d', want = '%d'", len(attachmentDecoded), len(attachmentExpected))
		return
	}
}
