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
	"bytes"
	"net/mail"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/siemens/ZapSmtp/_test"
)

// TestSmtpSyncer_prepareAttachment_FlagControlsSafeTempFile verifies optional attachments use a safe file name
func TestSmtpSyncer_prepareAttachment_FlagControlsSafeTempFile(t *testing.T) {

	// Prepare payload and a subject containing characters that are invalid in Windows file names
	payload := []byte("sensitive log payload")
	syncer := &SmtpSyncer{mailSubject: `Alert: / \\ * ? " < > |`}

	// Verify disabling attachments avoids creating any temporary file
	pathDisabled, errPathDisabled := syncer.prepareAttachment(payload)
	if errPathDisabled != nil {
		t.Errorf("prepareAttachment() error = '%v', want = nil", errPathDisabled)
		return
	}
	if pathDisabled != "" {
		t.Errorf("prepareAttachment() path = '%s', want = ''", pathDisabled)
		return
	}

	// Verify enabling attachments creates a safely named temporary file
	syncer.attachAsFile = true
	pathEnabled, errPathEnabled := syncer.prepareAttachment(payload)
	if errPathEnabled != nil {
		t.Errorf("prepareAttachment() error = '%v', want = nil", errPathEnabled)
		return
	}
	defer func() { _ = os.Remove(pathEnabled) }()
	if fileName := filepath.Base(pathEnabled); !strings.HasPrefix(fileName, "zapsmtp-log-") || !strings.HasSuffix(fileName, ".txt") {
		t.Errorf("prepareAttachment() file name = '%s', want safe zapsmtp-log-*.txt name", fileName)
		return
	}

	// Verify the temporary attachment contains the original payload
	attachment, errAttachment := os.ReadFile(pathEnabled)
	if errAttachment != nil {
		t.Errorf("os.ReadFile() error = '%v', want = nil", errAttachment)
		return
	}
	if !bytes.Equal(attachment, payload) {
		t.Errorf("prepareAttachment() payload = '%s', want = '%s'", attachment, payload)
		return
	}
}

// Unfortunately testing the correct sending of mails is not that easy and relies on manual labor. The correctness can
// only be reviewed manually

func TestNewSmtpWriteSyncer(t *testing.T) {

	// Skip if test configuration is incomplete
	if _test.OpensslPath == "" || _test.MailTo.Address == "" || _test.Cert1Path == "" ||
		_test.Key1Path == "" || _test.Cert2Path == "" {
		t.Skip("Integration test skipped: recipient details not configured in _test/unitTestConf.go")
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

			_, err := NewSmtpSyncer(
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
		})
	}
}
