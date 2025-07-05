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
	"github.com/siemens/ZapSmtp/_test"
	"net/mail"
	"testing"
)

func Test_sendMail(t *testing.T) {

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

	// Prepare certificate paths
	var toCerts []string
	var toCertsDouble []string
	if len(_test.RealCertPath) > 0 {
		toCerts = append(toCerts, _test.RealCertPath)
		toCertsDouble = append(toCertsDouble, _test.RealCertPath)
		toCertsDouble = append(toCertsDouble, _test.RealCertPath)
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

		pathOpenssl         string
		pathSignatureCert   string
		pathSignatureKey    string
		pathEncryptionCerts []string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"valid", args{[]byte("valid email, signed and optionally encrypted"), _test.SmtpServer, _test.SmtpPort, _test.SmtpUser, _test.SmtpPassword, _test.MailSubject, _test.MailFrom, []mail.Address{{"Test", _test.RealRecipient.Address}}, _test.OpensslPath, _test.Cert1Path, _test.Key1Path, toCerts}, false},
		{"valid-no-subject", args{[]byte("valid email, signed and optionally encrypted, no subject"), _test.SmtpServer, _test.SmtpPort, _test.SmtpUser, _test.SmtpPassword, "", _test.MailFrom, []mail.Address{{"Test", _test.RealRecipient.Address}}, _test.OpensslPath, _test.Cert1Path, _test.Key1Path, toCerts}, false},
		{"valid-no-message", args{[]byte(""), _test.SmtpServer, _test.SmtpPort, _test.SmtpUser, _test.SmtpPassword, _test.MailSubject + " (signed and optionally encrypted, no content inside)", _test.MailFrom, []mail.Address{{"Test", _test.RealRecipient.Address}}, _test.OpensslPath, _test.Cert1Path, _test.Key1Path, toCerts}, false},
		{"valid-multiple-recipients", args{[]byte("valid email, signed but not encrypted, sent to multiple recipients"), _test.SmtpServer, _test.SmtpPort, _test.SmtpUser, _test.SmtpPassword, _test.MailSubject, _test.MailFrom, []mail.Address{{"Test", _test.RealRecipient.Address}, {"Test", _test.RealRecipient.Address}}, _test.OpensslPath, _test.Cert1Path, _test.Key1Path, toCertsDouble}, false},
		{"valid-no-signing", args{[]byte("valid email, not signed and optionally encrypted"), _test.SmtpServer, _test.SmtpPort, _test.SmtpUser, _test.SmtpPassword, _test.MailSubject, _test.MailFrom, []mail.Address{{"Test", _test.RealRecipient.Address}}, _test.OpensslPath, "", "", toCerts}, false},
		{"valid-no-encryption", args{[]byte("valid email, signed but not encrypted"), _test.SmtpServer, _test.SmtpPort, _test.SmtpUser, _test.SmtpPassword, _test.MailSubject, _test.MailFrom, []mail.Address{{"Test", _test.RealRecipient.Address}}, _test.OpensslPath, _test.Cert1Path, _test.Key1Path, []string{}}, false},
		{"valid-plain", args{[]byte("valid email, not signed and not encrypted"), _test.SmtpServer, _test.SmtpPort, _test.SmtpUser, _test.SmtpPassword, _test.MailSubject, _test.MailFrom, []mail.Address{{"Test", _test.RealRecipient.Address}}, "", "", "", []string{}}, false},

		{"invalid-host", args{[]byte("some test message that should NOT be received"), "notexisting", _test.SmtpPort, _test.SmtpUser, _test.SmtpPassword, _test.MailSubject, _test.MailFrom, []mail.Address{{"Test", _test.RealRecipient.Address}}, _test.OpensslPath, _test.Cert1Path, _test.Key1Path, toCerts}, true},
		{"invalid-from", args{[]byte("some test message that should NOT be received"), _test.SmtpServer, _test.SmtpPort, _test.SmtpUser, _test.SmtpPassword, _test.MailSubject, mail.Address{"Test", "notexisting@test.com"}, []mail.Address{{"Test", _test.RealRecipient.Address}}, _test.OpensslPath, _test.Cert1Path, _test.Key1Path, toCerts}, true},
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
				tt.args.mailSubject,
				tt.args.message,
				tt.args.pathOpenssl,
				tt.args.pathSignatureCert,
				tt.args.pathSignatureKey,
				tt.args.pathEncryptionCerts,
			)
			if (err != nil) != tt.wantErr {
				t.Errorf("SendMail() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
