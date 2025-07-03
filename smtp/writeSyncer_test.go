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
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Unfortunately testing the correct sending of mails is not that easy and relies on manual labor. The correctness can
// only be reviewed manually

func TestNewSmtpWriteSyncer(t *testing.T) {

	// Make sure all the variables needed for the tests are set
	if _test.OpensslPath == "" || _test.Recipient.Address == "" || _test.Cert1 == "" ||
		_test.Key1 == "" || _test.Cert2 == "" {

		t.Errorf("please fill out the test configuration and restart the test")
		return
	}

	// Retrieve the project root and build the absolute paths
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Errorf("unable to get caller information")
		return
	}
	root := filepath.Join(filepath.Dir(file), "..", _test.TestDir)

	// Prepare certificate and key files
	cert1 := filepath.Join(root, _test.Cert1)
	key1 := filepath.Join(root, _test.Key1)
	cert2 := filepath.Join(root, _test.Cert2)

	// Create temporary directory
	tempDir, errDir := os.MkdirTemp(root, "temp_dir*")
	if errDir != nil {
		t.Errorf("could not create temporary directory: %s", errDir)
		return
	}

	// Clean up after the test
	defer func() {
		errRm := os.RemoveAll(tempDir)
		if errRm != nil {
			t.Errorf("could not delete temporary directory: %s", errRm)
		}
	}()

	type args struct {
		sender     mail.Address
		recipients []mail.Address

		opensslPath    string
		senderCert     string
		senderKey      string
		recipientCerts []string
		tempDir        string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"valid", args{_test.Sender, []mail.Address{_test.Recipient}, _test.OpensslPath, cert1, key1, []string{cert2}, tempDir}, false},
		{"valid-multiple-recipients", args{_test.Sender, []mail.Address{_test.Recipient, _test.Recipient, {}}, _test.OpensslPath, cert1, key1, []string{cert2, cert2, "", ""}, tempDir}, false},
		{"valid-no-singing", args{_test.Sender, []mail.Address{_test.Recipient}, _test.OpensslPath, "", "", []string{cert2}, tempDir}, false},
		{"valid-no-encryption", args{_test.Sender, []mail.Address{_test.Recipient}, _test.OpensslPath, cert1, key1, []string{}, tempDir}, false},
		{"valid-plain", args{_test.Sender, []mail.Address{_test.Recipient}, "", "", "", []string{}, tempDir}, false},

		{"invalid-empty-from", args{mail.Address{}, []mail.Address{_test.Recipient}, _test.OpensslPath, cert1, key1, []string{cert2}, tempDir}, true},
		{"invalid-sender-cert", args{mail.Address{}, []mail.Address{_test.Recipient}, _test.OpensslPath, "", key1, []string{cert2}, tempDir}, true},
		{"invalid-sender-key", args{mail.Address{}, []mail.Address{_test.Recipient}, _test.OpensslPath, cert1, "", []string{cert2}, tempDir}, true},
		{"invalid-empty-to", args{_test.Sender, []mail.Address{}, _test.OpensslPath, cert1, key1, []string{cert2}, tempDir}, true},
		{"invalid-no-to", args{_test.Sender, []mail.Address{}, _test.OpensslPath, cert1, key1, []string{cert2}, tempDir}, true},
		{"invalid-nil-to", args{_test.Sender, nil, _test.OpensslPath, cert1, key1, []string{cert2}, tempDir}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			_, err := NewWriteSyncer(
				"",
				0,
				"",
				"",
				"",
				tt.args.sender,
				tt.args.recipients,
				tt.args.opensslPath,
				tt.args.senderCert,
				tt.args.senderKey,
				tt.args.recipientCerts,
				tt.args.tempDir,
			)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewWriteSyncer() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSmtpWriteSyncer_Write(t *testing.T) {

	// Retrieve the project root and build the absolute paths
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Errorf("unable to get caller information")
		return
	}
	root := filepath.Join(filepath.Dir(file), "..", _test.TestDir)

	// Create temporary directory
	tempDir, errRead := os.MkdirTemp(root, "temp_dir*")
	if errRead != nil {
		t.Errorf("could not create temporary directory: %s", errRead)
		return
	}

	// Clean up after the test
	defer func() {
		errRm := os.RemoveAll(tempDir)
		if errRm != nil {
			t.Errorf("unable to delete temporary directory: %s", errRm)
		}
	}()

	// We don't really care whether SendMail succeeds, we only want to test whether all files are cleaned up again
	ws := writeSyncer{
		to:          []mail.Address{},
		opensslPath: "some/path",
		fromCert:    []byte("some-from-cert"),
		fromKey:     []byte("some-from-key"),
		toCerts:     [][]byte{[]byte("some-to-cert")},
		tempDir:     tempDir,
	}

	// Write some message
	msg := []byte("some message")
	_, _ = ws.Write(msg) // Ignore the actual result

	// Make sure that all temporary files have been cleaned up
	files, errRead := os.ReadDir(tempDir)
	if errRead != nil {
		t.Errorf("could not read directory: %s", errRead)
		return
	}

	// Check if there are any files left
	if len(files) > 0 {
		t.Errorf("files after execution = %v, expected empty directory", files)
	}

}
