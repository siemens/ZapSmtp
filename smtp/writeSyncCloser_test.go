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

// Basically the same test as TestNewSmtpWriteSyncer but it will also check for the correct creation and removal of the
// temporary files.
func TestNewWriteSyncCloser(t *testing.T) {

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
		{"invalid-empty-to", args{_test.Sender, []mail.Address{}, _test.OpensslPath, cert1, key1, []string{cert2}, tempDir}, true},
		{"invalid-no-to", args{_test.Sender, []mail.Address{}, _test.OpensslPath, cert1, key1, []string{cert2}, tempDir}, true},
		{"invalid-nil-to", args{_test.Sender, nil, _test.OpensslPath, cert1, key1, []string{cert2}, tempDir}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			sink, err := NewWriteSyncCloser(
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
				t.Errorf("NewWriteSyncCloser() error = %v, wantErr %v", err, tt.wantErr)
			}

			// Check whether the creation of the files was successful, clean up afterward
			if err == nil {
				files, errRead := os.ReadDir(tempDir)
				if errRead != nil {
					t.Errorf("could not read directory: %s", errRead)
					return
				}

				numFiles := 0
				if tt.args.senderCert != "" {
					numFiles++
				}
				if tt.args.senderKey != "" {
					numFiles++
				}
				for _, c := range tt.args.recipientCerts {
					if c != "" {
						numFiles++
					}
				}

				if len(files) != numFiles {
					t.Errorf("files after execution = %v, expected exactly %d files", files, numFiles)
				}

				err := sink.Close()
				if err != nil {
					t.Errorf("unable to call close: %s", err)
					return
				}
				return
			}

			// Make sure that all temporary files have been cleaned up correctly. Either by the New function because of
			// an error or because Close was called.
			files, errRead := os.ReadDir(tempDir)
			if errRead != nil {
				t.Errorf("could not read directory: %s", errRead)
				return
			}

			// Check if there are any files left
			if len(files) > 0 {
				t.Errorf("files after cleanup = %v, expected empty directory", files)
			}
		})
	}
}
