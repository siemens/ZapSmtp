/*
* ZapSmtp, a Zap (Golang) logger extension for sending urgent log messages via SMTP
*
* Copyright (c) Siemens AG, 2021-2025.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package ZapSmtp

import (
	"net/mail"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/siemens/ZapSmtp/_test"
)

// Unfortunately testing the correct sending of mails is not that easy and relies on manual labor. The correctness can
// only be reviewed manually

func TestNewSmtpWriteSyncer(t *testing.T) {

	// Make sure all the variables needed for the tests are set
	if _test.OpensslPath == "" || _test.MailTo.Address == "" || _test.Cert1Path == "" ||
		_test.Key1Path == "" || _test.Cert2Path == "" {

		t.Errorf("please fill out the test configuration and restart the test")
		return
	}

	// Retrieve the project root and build the absolute paths
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Errorf("could not get caller information")
		return
	}
	root := filepath.Join(filepath.Dir(file), _test.TestDirPath)

	// Prepare certificate and key files
	sigCert := filepath.Join(root, _test.Cert1Path)
	sigKey := filepath.Join(root, _test.Key1Path)
	encCert := filepath.Join(root, _test.Cert2Path)

	type args struct {
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
		{"valid", args{_test.MailFrom, []mail.Address{_test.MailTo}, _test.OpensslPath, sigCert, sigKey, []string{encCert}}, false},
		{"valid-multiple-recipients", args{_test.MailFrom, []mail.Address{_test.MailTo, _test.MailTo, {}}, _test.OpensslPath, sigCert, sigKey, []string{encCert, encCert, "", ""}}, false},
		{"valid-no-singing", args{_test.MailFrom, []mail.Address{_test.MailTo}, _test.OpensslPath, "", "", []string{encCert}}, false},
		{"valid-no-encryption", args{_test.MailFrom, []mail.Address{_test.MailTo}, _test.OpensslPath, sigCert, sigKey, []string{}}, false},
		{"valid-plain", args{_test.MailFrom, []mail.Address{_test.MailTo}, "", "", "", []string{}}, false},

		{"invalid-empty-from", args{mail.Address{}, []mail.Address{_test.MailTo}, _test.OpensslPath, sigCert, sigKey, []string{encCert}}, true},
		{"invalid-mailFrom-cert", args{mail.Address{}, []mail.Address{_test.MailTo}, _test.OpensslPath, "", sigKey, []string{encCert}}, true},
		{"invalid-mailFrom-key", args{mail.Address{}, []mail.Address{_test.MailTo}, _test.OpensslPath, sigCert, "", []string{encCert}}, true},
		{"invalid-empty-to", args{_test.MailFrom, []mail.Address{}, _test.OpensslPath, sigCert, sigKey, []string{encCert}}, true},
		{"invalid-no-to", args{_test.MailFrom, []mail.Address{}, _test.OpensslPath, sigCert, sigKey, []string{encCert}}, true},
		{"invalid-nil-to", args{_test.MailFrom, nil, _test.OpensslPath, sigCert, sigKey, []string{encCert}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			_, fnCleanup, err := NewSmtpSyncer(
				_test.SmtpServer,
				_test.SmtpPort,
				_test.SmtpUser,
				_test.SmtpPassword,
				_test.MailSubject,
				tt.args.mailFrom,
				tt.args.mailRecipients,
				false,
				tt.args.pathOpenssl,
				tt.args.pathSignatureCert,
				tt.args.pathSignatureKey,
				tt.args.pathEncryptionCerts,
			)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewSmtpSyncer() error = %v, wantErr %v", err, tt.wantErr)
			}
			fnCleanup()
		})
	}
}
