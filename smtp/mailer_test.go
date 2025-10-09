/*
* ZapSmtp, a Zap (Golang) logger extension for sending urgent log messages via SMTP
*
* Copyright (c) Siemens AG, 2021-2025.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package smtp

import (
	"net/mail"
	"os"
	"path/filepath"
	"testing"

	"github.com/siemens/ZapSmtp/_test"
)

func TestSendMail(t *testing.T) {

	// Unfortunately testing the correct sending of mails is not that easy and relies on manual labor. The correctness can
	// only be reviewed manually

	// Make sure all the variables needed for the tests are set
	if _test.OpensslPath == "" {
		t.Errorf("please configure the OpenSSL installation path and restart the test")
		return
	}

	// Make sure all the variables needed for the tests are set
	if _test.SmtpServer == "" ||
		_test.SmtpPort == 0 {
		t.Errorf("please configure the SMTP server and restart the test")
		return
	}

	// Make sure all the variables needed for the tests are set
	if _test.Cert1Path == "" ||
		_test.Key1Path == "" ||
		_test.RealRecipient.Address == "" {
		t.Errorf("please configure the recipient details and restart the test")
		return
	}

	// Read signature certificate bytes
	sigCert, errSigCert := os.ReadFile(_test.Cert1Path)
	if errSigCert != nil {
		t.Errorf("TestSendMail() error: Could not read certificate: %v", errSigCert)
		return
	}
	sigKey, errSigKey := os.ReadFile(_test.Key1Path)
	if errSigKey != nil {
		t.Errorf("TestSendMail() error: Could not read certificate: %v", errSigKey)
		return
	}

	// Prepare certificate paths
	var toCerts [][]byte
	var toCertsDouble [][]byte
	if len(_test.RealCertPath) > 0 {

		// Read encryption certificate bytes
		data, errReadCert := os.ReadFile(_test.RealCertPath)
		if errReadCert != nil {
			t.Errorf("TestSendMail() error: Could not read certificate: %v", errReadCert)
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
			mailRecipients:  []mail.Address{{"Test", _test.RealRecipient.Address}},
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
			mailRecipients:  []mail.Address{{"Test", _test.RealRecipient.Address}},
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
			mailRecipients:  []mail.Address{{"Test", _test.RealRecipient.Address}},
			pathOpenssl:     _test.OpensslPath,
			signatureCert:   sigCert,
			signatureKey:    sigKey,
			encryptionCerts: toCerts,
		}},
		{name: "valid-multiple-recipients", args: args{
			message:         []byte("valid email, signed and encrypted, sent to multiple recipients"),
			smtpServer:      _test.SmtpServer,
			smtpPort:        _test.SmtpPort,
			smtpUser:        _test.SmtpUser,
			smtpPassword:    _test.SmtpPassword,
			mailSubject:     _test.MailSubject,
			mailFrom:        _test.MailFrom,
			mailRecipients:  []mail.Address{{"Test 1", _test.RealRecipient.Address}, {_test.MailTo.Name, _test.MailTo.Address}},
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
			mailRecipients:  []mail.Address{{"Test", _test.RealRecipient.Address}},
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
			mailRecipients:  []mail.Address{{"Test", _test.RealRecipient.Address}},
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
			mailRecipients:  []mail.Address{{"Test", _test.RealRecipient.Address}},
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
			mailRecipients:  []mail.Address{{"Test", _test.RealRecipient.Address}},
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
			mailFrom:        mail.Address{"Test", "notexisting@domian.tld"},
			mailRecipients:  []mail.Address{{"Test", _test.RealRecipient.Address}},
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
				t.Errorf("TestSendMail() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestSendMail_attachment(t *testing.T) {

	// Unfortunately testing the correct sending of mails is not that easy and relies on manual labor. The correctness can
	// only be reviewed manually

	// Make sure all the variables needed for the tests are set
	if _test.OpensslPath == "" {
		t.Errorf("please configure the OpenSSL installation path and restart the test")
		return
	}

	// Make sure all the variables needed for the tests are set
	if _test.SmtpServer == "" ||
		_test.SmtpPort == 0 {
		t.Errorf("please configure the SMTP server and restart the test")
		return
	}

	// Make sure all the variables needed for the tests are set
	if _test.Cert1Path == "" ||
		_test.Key1Path == "" ||
		_test.RealRecipient.Address == "" {
		t.Errorf("please configure the recipient details and restart the test")
		return
	}

	// Read signature certificate bytes
	sigCert, errSigCert := os.ReadFile(_test.Cert1Path)
	if errSigCert != nil {
		t.Errorf("TestSendMail_attachment() error: Could not read certificate: %v", errSigCert)
		return
	}
	sigKey, errSigKey := os.ReadFile(_test.Key1Path)
	if errSigKey != nil {
		t.Errorf("TestSendMail_attachment() error: Could not read certificate: %v", errSigKey)
		return
	}

	// Prepare certificate paths
	var toCerts [][]byte
	var toCertsDouble [][]byte
	if len(_test.RealCertPath) > 0 {

		// Read encryption certificate bytes
		data, errReadCert := os.ReadFile(_test.RealCertPath)
		if errReadCert != nil {
			t.Errorf("TestSendMail_attachment() error: Could not read certificate: %v", errReadCert)
			return
		}
		toCerts = append(toCerts, data)
		toCertsDouble = append(toCertsDouble, data)
		toCertsDouble = append(toCertsDouble, data)
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

			// Read attachments
			attachments := make(map[string][]byte)
			for _, attachmentPath := range tt.args.attachmentPaths {
				fileName := filepath.Base(attachmentPath)
				fileBytes, errFileBytes := os.ReadFile(attachmentPath)
				if errFileBytes != nil {
					t.Errorf("TestSendMail_attachment() could not read file: %v", errFileBytes)
					return
				}
				attachments[fileName] = fileBytes
			}

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
				t.Errorf("TestSendMail_attachment() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
