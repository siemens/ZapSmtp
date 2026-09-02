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
	"bufio"
	"bytes"
	"io"
	"net"
	"net/mail"
	"net/textproto"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/siemens/ZapSmtp/_test"
)

// TestSendMail_VariousConfigurations_SendsOrRejects verifies that SendMail correctly handles various signing,
// encryption and recipient configurations
func TestSendMail_VariousConfigurations_SendsOrRejects(t *testing.T) {

	// Unfortunately testing the correct sending of mails is not that easy and relies on manual labor. The correctness can
	// only be reviewed manually

	// Make sure all the variables needed for the tests are set
	if _test.OpensslPath == "" {
		t.Skip("Integration test skipped: OpensslPath not configured in _test/unitTestConf.go")
		return
	}

	// Make sure all the variables needed for the tests are set
	if _test.SmtpServer == "" ||
		_test.SmtpPort == 0 {
		t.Skip("Integration test skipped: SmtpServer not configured in _test/unitTestConf.go")
		return
	}

	// Make sure all the variables needed for the tests are set
	if _test.Cert1Path == "" ||
		_test.Key1Path == "" ||
		_test.RealRecipient.Address == "" {
		t.Skip("Integration test skipped: recipient details not configured in _test/unitTestConf.go")
		return
	}

	// Read signature certificate bytes
	sigCert, errSigCert := os.ReadFile(_test.Cert1Path)
	if errSigCert != nil {
		t.Errorf("TestSendMail_VariousConfigurations_SendsOrRejects() error: Could not read certificate: %v", errSigCert)
		return
	}
	sigKey, errSigKey := os.ReadFile(_test.Key1Path)
	if errSigKey != nil {
		t.Errorf("TestSendMail_VariousConfigurations_SendsOrRejects() error: Could not read certificate: %v", errSigKey)
		return
	}

	// Prepare certificate paths
	var toCerts [][]byte
	var toCertsDouble [][]byte
	if len(_test.RealCertPath) > 0 {

		// Read encryption certificate bytes
		data, errReadCert := os.ReadFile(_test.RealCertPath)
		if errReadCert != nil {
			t.Errorf("TestSendMail_VariousConfigurations_SendsOrRejects() error: Could not read certificate: %v", errReadCert)
			return
		}
		toCerts = append(toCerts, data)
		toCertsDouble = append(toCertsDouble, data)
		toCertsDouble = append(toCertsDouble, data)
	}

	// Prepare test cases
	type args struct {
		message      []byte
		smtpServer   string
		smtpPort     uint16
		smtpUser     string
		smtpPassword string

		mailSubject    string
		mailFrom       mail.Address
		mailRecipients []mail.Address

		pathOpenssl     string
		signatureCert   []byte
		signatureKey    []byte
		encryptionCerts [][]byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "valid", args: args{
			message:         []byte("valid email, signed and optionally encrypted"),
			smtpServer:      _test.SmtpServer,
			smtpPort:        _test.SmtpPort,
			smtpUser:        _test.SmtpUser,
			smtpPassword:    _test.SmtpPassword,
			mailSubject:     _test.MailSubject,
			mailFrom:        _test.MailFrom,
			mailRecipients:  []mail.Address{{Name: "Test", Address: _test.RealRecipient.Address}},
			pathOpenssl:     _test.OpensslPath,
			signatureCert:   sigCert,
			signatureKey:    sigKey,
			encryptionCerts: toCerts,
		}},
		{name: "valid-no-subject", args: args{
			message:         []byte("valid email, signed and optionally encrypted, no subject"),
			smtpServer:      _test.SmtpServer,
			smtpPort:        _test.SmtpPort,
			smtpUser:        _test.SmtpUser,
			smtpPassword:    _test.SmtpPassword,
			mailSubject:     "",
			mailFrom:        _test.MailFrom,
			mailRecipients:  []mail.Address{{Name: "Test", Address: _test.RealRecipient.Address}},
			pathOpenssl:     _test.OpensslPath,
			signatureCert:   sigCert,
			signatureKey:    sigKey,
			encryptionCerts: toCerts,
		}},
		{name: "valid-no-message", args: args{
			message:         []byte(""),
			smtpServer:      _test.SmtpServer,
			smtpPort:        _test.SmtpPort,
			smtpUser:        _test.SmtpUser,
			smtpPassword:    _test.SmtpPassword,
			mailSubject:     _test.MailSubject + " (signed and optionally encrypted, no content inside)",
			mailFrom:        _test.MailFrom,
			mailRecipients:  []mail.Address{{Name: "Test", Address: _test.RealRecipient.Address}},
			pathOpenssl:     _test.OpensslPath,
			signatureCert:   sigCert,
			signatureKey:    sigKey,
			encryptionCerts: toCerts,
		}},
		{name: "valid-multiple-recipients", args: args{
			message:      []byte("valid email, signed and encrypted, sent to multiple recipients"),
			smtpServer:   _test.SmtpServer,
			smtpPort:     _test.SmtpPort,
			smtpUser:     _test.SmtpUser,
			smtpPassword: _test.SmtpPassword,
			mailSubject:  _test.MailSubject,
			mailFrom:     _test.MailFrom,
			mailRecipients: []mail.Address{
				{Name: "Test 1", Address: _test.RealRecipient.Address},
				{Name: _test.MailTo.Name, Address: _test.MailTo.Address},
			},
			pathOpenssl:     _test.OpensslPath,
			signatureCert:   sigCert,
			signatureKey:    sigKey,
			encryptionCerts: toCertsDouble,
		}},
		{name: "valid-no-signing", args: args{
			message:         []byte("valid email, not signed and optionally encrypted"),
			smtpServer:      _test.SmtpServer,
			smtpPort:        _test.SmtpPort,
			smtpUser:        _test.SmtpUser,
			smtpPassword:    _test.SmtpPassword,
			mailSubject:     _test.MailSubject,
			mailFrom:        _test.MailFrom,
			mailRecipients:  []mail.Address{{Name: "Test", Address: _test.RealRecipient.Address}},
			pathOpenssl:     _test.OpensslPath,
			signatureCert:   nil,
			signatureKey:    nil,
			encryptionCerts: toCerts,
		}},
		{name: "valid-no-encryption", args: args{
			message:         []byte("valid email, signed but not encrypted"),
			smtpServer:      _test.SmtpServer,
			smtpPort:        _test.SmtpPort,
			smtpUser:        _test.SmtpUser,
			smtpPassword:    _test.SmtpPassword,
			mailSubject:     _test.MailSubject,
			mailFrom:        _test.MailFrom,
			mailRecipients:  []mail.Address{{Name: "Test", Address: _test.RealRecipient.Address}},
			pathOpenssl:     _test.OpensslPath,
			signatureCert:   sigCert,
			signatureKey:    sigKey,
			encryptionCerts: nil,
		}},
		{name: "valid-plain", args: args{
			message:         []byte("valid email, not signed and not encrypted"),
			smtpServer:      _test.SmtpServer,
			smtpPort:        _test.SmtpPort,
			smtpUser:        _test.SmtpUser,
			smtpPassword:    _test.SmtpPassword,
			mailSubject:     _test.MailSubject,
			mailFrom:        _test.MailFrom,
			mailRecipients:  []mail.Address{{Name: "Test", Address: _test.RealRecipient.Address}},
			signatureCert:   nil,
			signatureKey:    nil,
			encryptionCerts: nil,
		}},

		{name: "invalid-host", args: args{
			message:         []byte("some test message that should NOT be received"),
			smtpServer:      "notexisting",
			smtpPort:        _test.SmtpPort,
			smtpUser:        _test.SmtpUser,
			smtpPassword:    _test.SmtpPassword,
			mailSubject:     _test.MailSubject,
			mailFrom:        _test.MailFrom,
			mailRecipients:  []mail.Address{{Name: "Test", Address: _test.RealRecipient.Address}},
			pathOpenssl:     _test.OpensslPath,
			signatureCert:   nil,
			signatureKey:    nil,
			encryptionCerts: nil,
		}, wantErr: true},
		{name: "invalid-from", args: args{
			message:         []byte("some test message that should NOT be received"),
			smtpServer:      _test.SmtpServer,
			smtpPort:        _test.SmtpPort,
			smtpUser:        _test.SmtpUser,
			smtpPassword:    _test.SmtpPassword,
			mailSubject:     _test.MailSubject,
			mailFrom:        mail.Address{Name: "Test", Address: "notexisting@domian.tld"},
			mailRecipients:  []mail.Address{{Name: "Test", Address: _test.RealRecipient.Address}},
			pathOpenssl:     _test.OpensslPath,
			signatureCert:   nil,
			signatureKey:    nil,
			encryptionCerts: nil,
		}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Run test
			err := SendMail(
				tt.args.smtpServer,
				tt.args.smtpPort,
				tt.args.smtpUser,
				tt.args.smtpPassword,
				tt.args.mailFrom,
				tt.args.mailRecipients,
				tt.args.encryptionCerts, // One encryption certificate per recipient
				tt.args.mailSubject,
				tt.args.message,
				nil, // List of file paths to attach
				tt.args.pathOpenssl,
				tt.args.signatureCert,
				tt.args.signatureKey,
				false, // Send as plaintext
			)
			if (err != nil) != tt.wantErr {
				t.Errorf("SendMail() error = '%v', wantErr = '%v'", err, tt.wantErr)
				return
			}
		})
	}
}

// TestMailer_Send_AcceptedMessageLogsQuitErrorWithoutFailing verifies that a cleanup error after SMTP acceptance
// is reported locally without marking the delivered message as failed
func TestMailer_Send_AcceptedMessageLogsQuitErrorWithoutFailing(t *testing.T) {

	// Start a real local SMTP connection that accepts the message before rejecting QUIT
	smtpHost, smtpPort, chMessage, chServer := test_startSmtpServer(t, true, true, 0, 0)

	// Prepare a plain message that does not require external certificates or credentials
	mailer := NewMailer(smtpHost, smtpPort)
	message, errMessage := NewMessage(
		mail.Address{Name: "Sender", Address: "sender@domain.tld"},
		[]mail.Address{{Name: "Recipient", Address: "recipient@domain.tld"}},
		"Test subject",
		[]byte("Test body"),
	)
	if errMessage != nil {
		t.Errorf("NewMessage() error = '%v', want = nil", errMessage)
		return
	}

	// Capture the local cleanup warning without changing the logger integration
	stderrOriginal := os.Stderr
	stderrReader, stderrWriter, errPipe := os.Pipe()
	if errPipe != nil {
		t.Errorf("os.Pipe() error = '%v', want = nil", errPipe)
		return
	}
	os.Stderr = stderrWriter
	t.Cleanup(func() {
		os.Stderr = stderrOriginal
		_ = stderrReader.Close()
		_ = stderrWriter.Close()
	})

	// Send the message through the full SMTP transaction
	errSend := mailer.Send(message)
	os.Stderr = stderrOriginal
	_ = stderrWriter.Close()
	stderrOutput, errStderrOutput := io.ReadAll(stderrReader)
	if errStderrOutput != nil {
		t.Errorf("io.ReadAll() error = '%v', want = nil", errStderrOutput)
		return
	}

	// Verify the accepted message is not reported as a delivery failure
	if errSend != nil {
		t.Errorf("Mailer.Send() error = '%v', want = nil", errSend)
		return
	}

	// Verify the server received the original message exactly once
	select {
	case messageReceived := <-chMessage:
		if !bytes.Contains(messageReceived, []byte("Test body")) {
			t.Errorf("Mailer.Send() message = '%s', want to contain = 'Test body'", messageReceived)
			return
		}
	case <-time.After(time.Second * 2):
		t.Error("Mailer.Send() message was not received, want one accepted message")
		return
	}

	// Verify the harmless post-send failure remains visible locally
	if !strings.Contains(string(stderrOutput), "Could not close SMTP session after the message was accepted") {
		t.Errorf("Mailer.Send() stderr = '%s', want cleanup warning", stderrOutput)
		return
	}

	// Verify the local SMTP session itself completed without an infrastructure error
	select {
	case errServer := <-chServer:
		if errServer != nil {
			t.Errorf("SMTP test server error = '%v', want = nil", errServer)
			return
		}
	case <-time.After(time.Second * 2):
		t.Error("SMTP test server did not stop, want completed session")
		return
	}
}

// TestMailer_Send_LargeLogAttachmentRespectsSmtpLineLimit verifies that a large log body and attachment are accepted
// by an SMTP server enforcing the RFC 2821 data-line limit
func TestMailer_Send_LargeLogAttachmentRespectsSmtpLineLimit(t *testing.T) {

	// Start a real local SMTP connection that reproduces the production server's line-length rejection
	const smtpMaxDataLineLength = 998
	smtpHost, smtpPort, chMessage, chServer := test_startSmtpServer(t, true, false, smtpMaxDataLineLength, 0)

	// Prepare a message whose body and attachment would exceed the limit without transfer-encoding line folding
	mailer := NewMailer(smtpHost, smtpPort)
	message, errMessage := NewMessage(
		mail.Address{Name: "Sender", Address: "sender@domain.tld"},
		[]mail.Address{{Name: "Recipient", Address: "recipient@domain.tld"}},
		"Large logger message",
		bytes.Repeat([]byte("log-entry-content "), 200),
	)
	if errMessage != nil {
		t.Errorf("NewMessage() error = '%v', want = nil", errMessage)
		return
	}
	message.rawAttachments["zapsmtp-log.txt"] = bytes.Repeat([]byte("attachment-content-"), 200)

	// Send the message through the complete SMTP transaction
	errSend := mailer.Send(message)

	// Verify the server accepted the RFC-compliant message instead of returning its line-length error
	if errSend != nil {
		t.Errorf("Mailer.Send() error = '%v', want = nil", errSend)
		return
	}
	select {
	case <-chMessage:
	case <-time.After(time.Second * 2):
		t.Error("Mailer.Send() message was not received, want one accepted message")
		return
	}

	// Verify the local SMTP session itself completed without an infrastructure error
	select {
	case errServer := <-chServer:
		if errServer != nil {
			t.Errorf("SMTP test server error = '%v', want = nil", errServer)
			return
		}
	case <-time.After(time.Second * 2):
		t.Error("SMTP test server did not stop, want completed session")
		return
	}
}

// TestMailer_Send_RejectedMessageReturnsError verifies that failures before SMTP acceptance remain delivery errors
func TestMailer_Send_RejectedMessageReturnsError(t *testing.T) {

	// Start a real local SMTP connection that rejects the message transfer
	smtpHost, smtpPort, _, chServer := test_startSmtpServer(t, false, false, 0, 0)

	// Prepare a plain message that does not require external certificates or credentials
	mailer := NewMailer(smtpHost, smtpPort)
	message, errMessage := NewMessage(
		mail.Address{Name: "Sender", Address: "sender@domain.tld"},
		[]mail.Address{{Name: "Recipient", Address: "recipient@domain.tld"}},
		"Test subject",
		[]byte("Test body"),
	)
	if errMessage != nil {
		t.Errorf("NewMessage() error = '%v', want = nil", errMessage)
		return
	}

	// Send the message through the rejected SMTP transaction
	errSend := mailer.Send(message)

	// Verify the pre-delivery failure remains visible to the retrying caller
	if errSend == nil {
		t.Error("Mailer.Send() error = nil, want delivery error")
		return
	}

	// Verify the local SMTP session itself completed without an infrastructure error
	select {
	case errServer := <-chServer:
		if errServer != nil {
			t.Errorf("SMTP test server error = '%v', want = nil", errServer)
			return
		}
	case <-time.After(time.Second * 2):
		t.Error("SMTP test server did not stop, want completed session")
		return
	}
}

// TestMailer_Send_StalledServerReturnsTimeout verifies that a silent SMTP peer cannot block delivery indefinitely
func TestMailer_Send_StalledServerReturnsTimeout(t *testing.T) {

	// Start a server that accepts TCP but delays its SMTP greeting beyond the configured timeout
	smtpHost, smtpPort := test_startStalledSmtpServer(t, time.Millisecond*300)

	// Prepare a mailer with a short deterministic timeout
	mailer := NewMailer(smtpHost, smtpPort)
	mailer.timeout = time.Millisecond * 40
	message, errMessage := NewMessage(
		mail.Address{Name: "Sender", Address: "sender@domain.tld"},
		[]mail.Address{{Name: "Recipient", Address: "recipient@domain.tld"}},
		"Timeout",
		[]byte("Body"),
	)
	if errMessage != nil {
		t.Errorf("NewMessage() error = '%v', want = nil", errMessage)
		return
	}

	// Send and measure the stalled transaction
	startedAt := time.Now()
	errSend := mailer.Send(message)
	duration := time.Since(startedAt)

	// Verify the timeout interrupts the SMTP greeting promptly
	if errSend == nil {
		t.Error("Mailer.Send() error = nil, want timeout error")
		return
	}
	if duration >= time.Millisecond*200 {
		t.Errorf("Mailer.Send() duration = '%v', want < '200ms'", duration)
		return
	}
}

// TestMailer_Send_SlowButProgressingServerSucceeds verifies that the timeout behaves as an inactivity timeout rather
// than a hard cap on the whole transaction: a transfer whose total duration exceeds the timeout still succeeds as long
// as each individual step makes progress within it. This reproduces sending a large report to a slow SMTP peer.
func TestMailer_Send_SlowButProgressingServerSucceeds(t *testing.T) {

	// Pause before every server response so the transaction outlasts the timeout while each step stays under it
	const idleTimeout = time.Millisecond * 200
	const stepDelay = time.Millisecond * 70
	smtpHost, smtpPort, chMessage, chServer := test_startSmtpServer(t, true, false, 0, stepDelay)

	// Prepare a mailer whose inactivity timeout is shorter than the total transaction time
	mailer := NewMailer(smtpHost, smtpPort)
	mailer.timeout = idleTimeout
	message, errMessage := NewMessage(
		mail.Address{Name: "Sender", Address: "sender@domain.tld"},
		[]mail.Address{{Name: "Recipient", Address: "recipient@domain.tld"}},
		"Slow but progressing",
		[]byte("Body"),
	)
	if errMessage != nil {
		t.Errorf("NewMessage() error = '%v', want = nil", errMessage)
		return
	}

	// Send and measure the deliberately slow transaction
	startedAt := time.Now()
	errSend := mailer.Send(message)
	duration := time.Since(startedAt)

	// Verify the steadily progressing transfer was delivered despite outlasting a single timeout window
	if errSend != nil {
		t.Errorf("Mailer.Send() error = '%v', want = nil", errSend)
		return
	}
	if duration <= idleTimeout {
		t.Errorf("Mailer.Send() duration = '%v', want > '%v' to prove the transaction outlasted one timeout window", duration, idleTimeout)
		return
	}

	// Verify the server actually received the message after the slow exchange
	select {
	case <-chMessage:
	case <-time.After(time.Second * 2):
		t.Error("Mailer.Send() message was not received, want one accepted message")
		return
	}

	// Verify the local SMTP session itself completed without an infrastructure error
	select {
	case errServer := <-chServer:
		if errServer != nil {
			t.Errorf("SMTP test server error = '%v', want = nil", errServer)
			return
		}
	case <-time.After(time.Second * 2):
		t.Error("SMTP test server did not stop, want completed session")
		return
	}
}

// TestSendMail_WithAttachment_SendsOrRejects verifies that SendMail correctly handles file attachments
// with various signing and encryption configurations
func TestSendMail_WithAttachment_SendsOrRejects(t *testing.T) {

	// Unfortunately testing the correct sending of mails is not that easy and relies on manual labor. The correctness can
	// only be reviewed manually

	// Make sure all the variables needed for the tests are set
	if _test.OpensslPath == "" {
		t.Skip("Integration test skipped: OpensslPath not configured in _test/unitTestConf.go")
		return
	}

	// Make sure all the variables needed for the tests are set
	if _test.SmtpServer == "" ||
		_test.SmtpPort == 0 {
		t.Skip("Integration test skipped: SmtpServer not configured in _test/unitTestConf.go")
		return
	}

	// Make sure all the variables needed for the tests are set
	if _test.Cert1Path == "" ||
		_test.Key1Path == "" ||
		_test.RealRecipient.Address == "" {
		t.Skip("Integration test skipped: recipient details not configured in _test/unitTestConf.go")
		return
	}

	// Read signature certificate bytes
	sigCert, errSigCert := os.ReadFile(_test.Cert1Path)
	if errSigCert != nil {
		t.Errorf("TestSendMail_WithAttachment_SendsOrRejects() error: Could not read certificate: %v", errSigCert)
		return
	}
	sigKey, errSigKey := os.ReadFile(_test.Key1Path)
	if errSigKey != nil {
		t.Errorf("TestSendMail_WithAttachment_SendsOrRejects() error: Could not read certificate: %v", errSigKey)
		return
	}

	// Prepare certificate paths
	var toCerts [][]byte
	if len(_test.RealCertPath) > 0 {

		// Read encryption certificate bytes
		data, errReadCert := os.ReadFile(_test.RealCertPath)
		if errReadCert != nil {
			t.Errorf("TestSendMail_WithAttachment_SendsOrRejects() error: Could not read certificate: %v", errReadCert)
			return
		}
		toCerts = append(toCerts, data)
	}

	// Prepare test cases
	type args struct {
		message         []byte
		attachmentPaths []string
		smtpServer      string
		smtpPort        uint16
		smtpUser        string
		smtpPassword    string

		mailSubject    string
		mailFrom       mail.Address
		mailRecipients []mail.Address

		pathOpenssl     string
		signatureCert   []byte
		signatureKey    []byte
		encryptionCerts [][]byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "valid-attachment",
			args: args{
				message:         []byte("valid email, signed and optionally encrypted, with attachment"),
				attachmentPaths: []string{_test.Cert1Path},
				smtpServer:      _test.SmtpServer,
				smtpPort:        _test.SmtpPort,
				smtpUser:        _test.SmtpUser,
				smtpPassword:    _test.SmtpPassword,
				mailSubject:     _test.MailSubject,
				mailFrom:        _test.MailFrom,
				mailRecipients:  []mail.Address{_test.RealRecipient},
				pathOpenssl:     _test.OpensslPath,
				signatureCert:   sigCert,
				signatureKey:    sigKey,
				encryptionCerts: toCerts,
			},
			wantErr: false,
		},
		{
			name: "valid-attachment-no-signing",
			args: args{
				message:         []byte("valid email, not signed and optionally encrypted, with attachment"),
				attachmentPaths: []string{_test.Cert1Path},
				smtpServer:      _test.SmtpServer,
				smtpPort:        _test.SmtpPort,
				smtpUser:        _test.SmtpUser,
				smtpPassword:    _test.SmtpPassword,
				mailSubject:     _test.MailSubject,
				mailFrom:        _test.MailFrom,
				mailRecipients:  []mail.Address{_test.RealRecipient},
				pathOpenssl:     _test.OpensslPath,
				signatureCert:   nil,
				signatureKey:    nil,
				encryptionCerts: toCerts,
			},
			wantErr: false,
		},
		{
			name: "valid-attachment-no-encryption",
			args: args{
				message:         []byte("valid email, signed but not encrypted, with attachment"),
				attachmentPaths: []string{_test.Cert1Path},
				smtpServer:      _test.SmtpServer,
				smtpPort:        _test.SmtpPort,
				smtpUser:        _test.SmtpUser,
				smtpPassword:    _test.SmtpPassword,
				mailSubject:     _test.MailSubject,
				mailFrom:        _test.MailFrom,
				mailRecipients:  []mail.Address{_test.RealRecipient},
				pathOpenssl:     _test.OpensslPath,
				signatureCert:   sigCert,
				signatureKey:    sigKey,
				encryptionCerts: nil,
			},
			wantErr: false,
		},
		{
			name: "valid-attachment-no-signing-no-encryption",
			args: args{
				message:         []byte("valid email, not signed and not encrypted, with attachment"),
				attachmentPaths: []string{_test.Cert1Path},
				smtpServer:      _test.SmtpServer,
				smtpPort:        _test.SmtpPort,
				smtpUser:        _test.SmtpUser,
				smtpPassword:    _test.SmtpPassword,
				mailSubject:     _test.MailSubject,
				mailFrom:        _test.MailFrom,
				mailRecipients:  []mail.Address{_test.RealRecipient},
				pathOpenssl:     _test.OpensslPath,
				signatureCert:   nil,
				signatureKey:    nil,
				encryptionCerts: nil,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Run test
			err := SendMail(
				tt.args.smtpServer,
				tt.args.smtpPort,
				tt.args.smtpUser,
				tt.args.smtpPassword,
				tt.args.mailFrom,
				tt.args.mailRecipients,
				tt.args.encryptionCerts, // One encryption certificate per recipient
				tt.args.mailSubject+"(with attachment)",
				tt.args.message,
				tt.args.attachmentPaths, // List of file paths to attach
				tt.args.pathOpenssl,
				tt.args.signatureCert,
				tt.args.signatureKey,
				false, // Send as plaintext
			)
			if (err != nil) != tt.wantErr {
				t.Errorf("TestSendMail_WithAttachment_SendsOrRejects() error = '%v', wantErr = '%v'", err, tt.wantErr)
				return
			}
		})
	}
}

// test_messageExceedsLineLength reports whether a message contains a data line longer than the configured limit
func test_messageExceedsLineLength(message []byte, maxLineLength int) bool {

	// Inspect normalized message lines without counting their CRLF terminators
	for _, messageLine := range bytes.Split(message, []byte("\n")) {
		messageLine = bytes.TrimSuffix(messageLine, []byte("\r"))
		if len(messageLine) > maxLineLength {
			return true
		}
	}

	// Confirm all message lines fit within the configured limit
	return false
}

// test_startSmtpServer starts a local SMTP server with configurable delivery and cleanup outcomes
func test_startSmtpServer(
	t *testing.T,
	acceptMessage bool,
	quitError bool,
	maxDataLineLength int,
	stepDelay time.Duration, // Pause before each response to emulate a slow but steadily progressing peer
) (string, uint16, <-chan []byte, <-chan error) {

	// Mark failures at the caller and listen only on the local loopback interface
	t.Helper()
	listener, errListener := net.Listen("tcp", "127.0.0.1:0")
	if errListener != nil {
		t.Errorf("net.Listen() error = '%v', want = nil", errListener)
		return "", 0, nil, nil
	}
	t.Cleanup(func() { _ = listener.Close() })

	// Resolve the dynamically assigned port for the mailer
	host, portRaw, errAddress := net.SplitHostPort(listener.Addr().String())
	if errAddress != nil {
		t.Errorf("net.SplitHostPort() error = '%v', want = nil", errAddress)
		return "", 0, nil, nil
	}
	port, errPort := strconv.ParseUint(portRaw, 10, 16)
	if errPort != nil {
		t.Errorf("strconv.ParseUint() error = '%v', want = nil", errPort)
		return "", 0, nil, nil
	}

	// Serve one complete SMTP transaction on the real TCP connection
	chMessage := make(chan []byte, 1)
	chServer := make(chan error, 1)
	go func() {
		connection, errConnection := listener.Accept()
		if errConnection != nil {
			chServer <- errConnection
			return
		}
		defer func() { _ = connection.Close() }()

		// Prepare line-oriented SMTP protocol handling
		reader := textproto.NewReader(bufio.NewReader(connection))
		writer := bufio.NewWriter(connection)
		writeResponse := func(response string) error {

			// Pause before responding so the transaction can outlast a single timeout window while still progressing
			if stepDelay > 0 {
				time.Sleep(stepDelay)
			}
			_, errWrite := writer.WriteString(response + "\r\n")
			if errWrite != nil {
				return errWrite
			}

			// Flush each response because the client waits before continuing
			return writer.Flush()
		}

		// Greet the client before receiving SMTP commands
		if errGreeting := writeResponse("220 localhost ESMTP ready"); errGreeting != nil {
			chServer <- errGreeting
			return
		}

		// Handle the minimal SMTP command set needed by net/smtp
		for {
			command, errCommand := reader.ReadLine()
			if errCommand != nil {
				chServer <- errCommand
				return
			}

			switch {
			case strings.HasPrefix(command, "EHLO "), strings.HasPrefix(command, "HELO "):
				if errHello := writeResponse("250 localhost"); errHello != nil {
					chServer <- errHello
					return
				}
			case strings.HasPrefix(command, "MAIL FROM:"), strings.HasPrefix(command, "RCPT TO:"):
				if errRecipient := writeResponse("250 OK"); errRecipient != nil {
					chServer <- errRecipient
					return
				}
			case command == "DATA":
				if !acceptMessage {
					if errRejected := writeResponse("451 message rejected"); errRejected != nil {
						chServer <- errRejected
						return
					}
					chServer <- nil
					return
				}
				if errDataStart := writeResponse("354 End data with <CR><LF>.<CR><LF>"); errDataStart != nil {
					chServer <- errDataStart
					return
				}
				messageReceived, errMessageReceived := reader.ReadDotBytes()
				if errMessageReceived != nil {
					chServer <- errMessageReceived
					return
				}
				if maxDataLineLength > 0 && test_messageExceedsLineLength(messageReceived, maxDataLineLength) {
					if errLineLength := writeResponse("500 Line length exceeded. See RFC 2821 #4.5.3.1."); errLineLength != nil {
						chServer <- errLineLength
						return
					}
					chServer <- nil
					return
				}
				chMessage <- messageReceived
				if errAccepted := writeResponse("250 queued"); errAccepted != nil {
					chServer <- errAccepted
					return
				}
			case command == "QUIT":
				quitResponse := "221 goodbye"
				if quitError {
					quitResponse = "451 cleanup unavailable"
				}
				if errQuit := writeResponse(quitResponse); errQuit != nil {
					chServer <- errQuit
					return
				}
				chServer <- nil
				return
			default:
				if errUnknown := writeResponse("500 unsupported command"); errUnknown != nil {
					chServer <- errUnknown
					return
				}
			}
		}
	}()

	// Return the listener details and observation channels
	return host, uint16(port), chMessage, chServer
}

// test_startStalledSmtpServer starts a local TCP server that intentionally delays its SMTP greeting
func test_startStalledSmtpServer(t *testing.T, delay time.Duration) (string, uint16) {

	// Listen only on the local loopback interface
	t.Helper()
	listener, errListener := net.Listen("tcp", "127.0.0.1:0")
	if errListener != nil {
		t.Errorf("net.Listen() error = '%v', want = nil", errListener)
		return "", 0
	}
	t.Cleanup(func() { _ = listener.Close() })

	// Resolve the dynamically assigned port for the mailer
	host, portRaw, errAddress := net.SplitHostPort(listener.Addr().String())
	if errAddress != nil {
		t.Errorf("net.SplitHostPort() error = '%v', want = nil", errAddress)
		return "", 0
	}
	port, errPort := strconv.ParseUint(portRaw, 10, 16)
	if errPort != nil {
		t.Errorf("strconv.ParseUint() error = '%v', want = nil", errPort)
		return "", 0
	}

	// Accept one connection and keep it silent longer than the client timeout
	go func() {
		connection, errConnection := listener.Accept()
		if errConnection != nil {
			return
		}
		defer func() { _ = connection.Close() }()
		time.Sleep(delay)
	}()

	// Return the listener details
	return host, uint16(port)
}
