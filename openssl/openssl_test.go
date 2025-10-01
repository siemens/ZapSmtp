/*
* ZapSmtp, a Zap (Golang) logger extension for sending urgent log messages via SMTP
*
* Copyright (c) Siemens AG, 2021-2025.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package openssl

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/siemens/ZapSmtp/_test"
)

func Test_PrepareSignatureKeys(t *testing.T) {

	// Make sure all the variables needed for the tests are set
	if _test.OpensslPath == "" || _test.Cert2Path == "" || _test.Cert1Path == "" || _test.Key1Path == "" {
		t.Errorf("please fill out the test configuration and restart the test")
		return
	}

	// Retrieve the project root and build the absolute paths
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Errorf("could not get caller information")
		return
	}
	root := filepath.Join(filepath.Dir(file), "..")

	// Prepare certificate 1 paths
	cert := strings.TrimSuffix(_test.Cert1Path, filepath.Ext(_test.Cert1Path))
	key := strings.TrimSuffix(_test.Key1Path, filepath.Ext(_test.Key1Path))
	certPem := filepath.Join(root, _test.TestDirPath, cert+".pem")
	certDer := filepath.Join(root, _test.TestDirPath, cert+".der")

	// Prepare key 1 paths
	keyPem := filepath.Join(root, _test.TestDirPath, key+".pem")
	keyDer := filepath.Join(root, _test.TestDirPath, key+".der")

	// Prepare certificate 2 paths
	cert2 := strings.TrimSuffix(_test.Cert2Path, filepath.Ext(_test.Cert2Path))
	cert2Pem := filepath.Join(root, _test.TestDirPath, cert2+".pem")
	cert2Der := filepath.Join(root, _test.TestDirPath, cert2+".der")

	// Test load
	wantCert, err := os.ReadFile(certPem)
	if err != nil {
		t.Errorf("unable load cert: %s", err)
		return
	}
	wantKey, err := os.ReadFile(keyPem)
	if err != nil {
		t.Errorf("unable load key: %s", err)
		return
	}

	// Unify the line feed (on windows it is []byte{13 10})
	wantCert = bytes.ReplaceAll(wantCert, []byte{13, 10}, []byte{10})
	wantKey = bytes.ReplaceAll(wantKey, []byte{13, 10}, []byte{10})

	// Prepare test cases
	type args struct {
		pathOpenssl       string
		pathSignatureCert string
		pathSignatureKey  string
	}
	tests := []struct {
		name     string
		args     args
		wantCert []byte
		wantKey  []byte
		wantErr  bool
	}{
		{"valid-pem-pem", args{_test.OpensslPath, certPem, keyPem}, wantCert, wantKey, false},
		{"valid-der-pem", args{_test.OpensslPath, certDer, keyPem}, wantCert, wantKey, false},
		{"valid-pem-der", args{_test.OpensslPath, certPem, keyDer}, wantCert, wantKey, false},
		{"valid-der-der", args{_test.OpensslPath, certDer, keyDer}, wantCert, wantKey, false},
		{"invalid-exe", args{"notexisting", certPem, keyPem}, nil, nil, true},
		{"invalid-exe", args{"", certPem, keyPem}, nil, nil, true},
		{"invalid-exe", args{"notexisting", certDer, keyDer}, nil, nil, true},
		{"invalid-no-cert", args{_test.OpensslPath, "", keyDer}, nil, nil, true},
		{"invalid-no-key", args{_test.OpensslPath, certDer, ""}, nil, nil, true},
		{"invalid-no-key-pair-pem", args{_test.OpensslPath, cert2Pem, keyPem}, nil, nil, true},
		{"invalid-no-key-pair-der", args{_test.OpensslPath, cert2Der, keyDer}, nil, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Load signature certificate and key
			fromCert, errLoadCert := os.ReadFile(tt.args.pathSignatureCert)
			if errLoadCert != nil && tt.args.pathSignatureCert != "" {
				t.Errorf("could not load sender certificate: %s", errLoadCert)
				return
			}
			fromKey, errLoadKey := os.ReadFile(tt.args.pathSignatureKey)
			if errLoadKey != nil && tt.args.pathSignatureKey != "" {
				t.Errorf("could not load sender key: %s", errLoadKey)
				return
			}

			// Run test
			got, got1, errPrep := PrepareSignatureKeys(
				tt.args.pathOpenssl,
				fromCert,
				fromKey,
			)
			if (errPrep != nil) != tt.wantErr {
				t.Errorf("PrepareSignatureKeys() error = %v, wantErr %v", errPrep, tt.wantErr)
			}

			// Unify the line feed (on windows it is []byte{13 10})
			got = bytes.ReplaceAll(got, []byte{13, 10}, []byte{10})
			got1 = bytes.ReplaceAll(got1, []byte{13, 10}, []byte{10})

			// Make sure that all the files that we expect actually exist
			if !bytes.Equal(got, tt.wantCert) {
				t.Errorf("PrepareEncryptionKeys() cert got: '%v', want: '%v", got, tt.wantCert)
			}
			if !bytes.Equal(got1, tt.wantKey) {
				t.Errorf("PrepareEncryptionKeys() key got: '%v', want: '%v", got1, tt.wantKey)
			}
		})
	}
}

func Test_PrepareEncryptionKeys(t *testing.T) {

	// Make sure all the variables needed for the tests are set
	if _test.OpensslPath == "" || _test.Cert2Path == "" || _test.Cert1Path == "" {
		t.Errorf("please fill out the test configuration and restart the test")
		return
	}

	// Retrieve the project root and build the absolute paths
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Errorf("could not get caller information")
		return
	}
	root := filepath.Join(filepath.Dir(file), "..")

	// Prepare certificate 1 paths
	cert1 := strings.TrimSuffix(_test.Cert1Path, filepath.Ext(_test.Cert1Path))
	cert1Pem := filepath.Join(root, _test.TestDirPath, cert1+".pem")
	cert1Der := filepath.Join(root, _test.TestDirPath, cert1+".der")

	// Prepare certificate 2 paths
	cert2 := strings.TrimSuffix(_test.Cert2Path, filepath.Ext(_test.Cert2Path))
	cert2Pem := filepath.Join(root, _test.TestDirPath, cert2+".pem")
	cert2Der := filepath.Join(root, _test.TestDirPath, cert2+".der")

	// Test load
	wantCert1, err := os.ReadFile(cert1Pem)
	if err != nil {
		t.Errorf("unable load cert 1: %s", err)
		return
	}
	wantCert2, err2 := os.ReadFile(cert2Pem)
	if err2 != nil {
		t.Errorf("unable load cert 2: %s", err2)
		return
	}

	// Unify the line feed (on windows it is []byte{13 10})
	wantCert1 = bytes.ReplaceAll(wantCert1, []byte{13, 10}, []byte{10})
	wantCert2 = bytes.ReplaceAll(wantCert2, []byte{13, 10}, []byte{10})

	// Prepare test cases
	type args struct {
		pathOpenssl         string
		pathEncryptionCerts []string
	}
	tests := []struct {
		name    string
		args    args
		want    [][]byte // When a new (temp) file is created we can't predict the path and will therefore only check whether a file has been created
		wantErr bool
	}{
		{"valid-pem", args{_test.OpensslPath, []string{cert1Pem}}, [][]byte{wantCert1}, false},
		{"valid-der", args{_test.OpensslPath, []string{cert1Der}}, [][]byte{wantCert1}, false},
		{"valid-multiple-recipients-pem-pem", args{_test.OpensslPath, []string{cert1Pem, cert2Pem}}, [][]byte{wantCert1, wantCert2}, false},
		{"valid-multiple-recipients-pem-der", args{_test.OpensslPath, []string{cert1Pem, cert2Der}}, [][]byte{wantCert1, wantCert2}, false},
		{"valid-multiple-recipients-der-der", args{_test.OpensslPath, []string{cert1Der, cert2Der}}, [][]byte{wantCert1, wantCert2}, false},
		{"valid-no-cert", args{_test.OpensslPath, []string{}}, [][]byte{}, false},
		{"valid-no-exe", args{"notexisting", []string{cert1Pem}}, [][]byte{wantCert1}, false}, // Only .der format needs an openssl executable, as we do nothing in the other case
		{"valid-no-exe", args{"", []string{cert1Pem}}, [][]byte{wantCert1}, false},            // Only .der format needs an openssl executable, as we do nothing in the other case
		{"invalid-exe", args{"notexisting", []string{cert1Der}}, [][]byte{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Load encryption keys
			toCerts := make([][]byte, 0, len(tt.args.pathEncryptionCerts))
			for _, recipientCert := range tt.args.pathEncryptionCerts {
				toCert, errLoad := os.ReadFile(recipientCert)
				if errLoad != nil && recipientCert != "" {
					t.Errorf("could not load recipient certificate: %s", errLoad)
					return
				}
				toCerts = append(toCerts, toCert)
			}

			// Run test
			got, errPrepare := PrepareEncryptionKeys(tt.args.pathOpenssl, toCerts)
			if (errPrepare != nil) != tt.wantErr {
				t.Errorf("PrepareEncryptionKeys() error = %v, wantErr %v", errPrepare, tt.wantErr)
				return
			}

			// Check correct number
			if len(got) != len(tt.want) {
				t.Errorf("PrepareEncryptionKeys() number of certs got: '%v', want: '%v", len(got), len(tt.want))
				return
			}

			// Unify the line feed (on windows it is []byte{13 10})
			for i, c := range got {
				c = bytes.ReplaceAll(c, []byte{13, 10}, []byte{10})

				// Make sure that all the files that we expect actually exist
				if !bytes.Equal(c, tt.want[i]) {
					t.Errorf("PrepareEncryptionKeys() cert got: '%v', want: '%v", c, tt.want[i])
				}
			}
		})
	}
}

func Test_certToPem(t *testing.T) {

	// Make sure all the variables needed for the tests are set
	if _test.OpensslPath == "" || _test.Cert1Path == "" {
		t.Errorf("please fill out the test configuration and restart the test")
		return
	}

	// Retrieve the project root and build the absolute paths
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Errorf("could not get caller information")
		return
	}
	root := filepath.Join(filepath.Dir(file), "..")

	// Prepare certificate paths
	cert := strings.TrimSuffix(_test.Cert1Path, filepath.Ext(_test.Cert1Path))
	cert = filepath.Join(root, _test.TestDirPath, cert)

	// Load certificates
	certDer, errRead := os.ReadFile(cert + ".der")
	if errRead != nil {
		t.Errorf("could not read file '%s': %s", cert+".der", errRead)
		return
	}
	certPem, errRead2 := os.ReadFile(cert + ".pem")
	if errRead2 != nil {
		t.Errorf("could not read file '%s': %s", cert+".pem", errRead2)
		return
	}

	// Prepare test cases
	type args struct {
		pathOpenssl string
		cert        []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{"valid-der", args{_test.OpensslPath, certDer}, certPem, false},
		{"invalid-pem", args{_test.OpensslPath, certPem}, nil, true},
		{"invalid-exe", args{"notexisting", certDer}, nil, true},
		{"invalid-no-exe", args{"", certDer}, nil, true},
		{"invalid-cert", args{"", []byte("not a certificate")}, nil, true},
		{"invalid-no-cert", args{"", []byte{}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CertToPem(tt.args.pathOpenssl, tt.args.cert)
			if (err != nil) != tt.wantErr {
				t.Errorf("derToPem() error = '%v', wantErr '%v'", err, tt.wantErr)
				return
			}

			// Remove any carriage return codes to make the check work more consistently
			got = bytes.ReplaceAll(got, []byte{13}, []byte{})
			want := bytes.ReplaceAll(tt.want, []byte{13}, []byte{})

			if !reflect.DeepEqual(got, want) {
				t.Errorf("derToPem() got = '%v', want '%v'", got, want)
			}
		})
	}
}

func Test_keyToPem(t *testing.T) {

	// Make sure all the variables needed for the tests are set
	if _test.OpensslPath == "" || _test.Key1Path == "" {
		t.Errorf("please fill out the test configuration and restart the test")
		return
	}

	// Retrieve the project root and build the absolute paths
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Errorf("could not get caller information")
		return
	}
	root := filepath.Join(filepath.Dir(file), "..")

	// Prepare key paths
	key := strings.TrimSuffix(_test.Key1Path, filepath.Ext(_test.Key1Path))
	key = filepath.Join(root, _test.TestDirPath, key)

	// Load Keys
	keyDer, errRead := os.ReadFile(key + ".der")
	if errRead != nil {
		t.Errorf("could not read file '%s': %s", key+".der", errRead)
		return
	}
	keyPem, errRead2 := os.ReadFile(key + ".pem")
	if errRead2 != nil {
		t.Errorf("could not read file '%s': %s", key+".pem", errRead2)
		return
	}

	// Prepare test cases
	type args struct {
		pathOpenssl string
		key         []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{"valid-der", args{_test.OpensslPath, keyDer}, keyPem, false},
		{"valid-pem", args{_test.OpensslPath, keyPem}, nil, true},
		{"invalid-exe", args{"notexisting", keyDer}, nil, true},
		{"invalid-no-exe", args{"", keyDer}, nil, true},
		{"invalid-cert", args{"", []byte("not a certificate")}, nil, true},
		{"invalid-no-cert", args{"", []byte{}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Run test
			got, err := KeyToPem(tt.args.pathOpenssl, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("derToPem() error = '%v', wantErr '%v'", err, tt.wantErr)
				return
			}

			// Remove any carriage return codes to make the check work more consistently
			got = bytes.ReplaceAll(got, []byte{13}, []byte{})
			want := bytes.ReplaceAll(tt.want, []byte{13}, []byte{})

			// Check result
			if !reflect.DeepEqual(got, want) {
				t.Errorf("derToPem() got = '%v',\nwant '%v'", got, want)
			}
		})
	}
}

func Test_signMessage(t *testing.T) {

	// Make sure all the variables needed for the tests are set
	if _test.OpensslPath == "" || _test.Cert1Path == "" || _test.Key1Path == "" {
		t.Errorf("please fill out the test configuration and restart the test")
		return
	}

	// Retrieve the project root and build the absolute paths
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Errorf("could not get caller information")
		return
	}
	root := filepath.Join(filepath.Dir(file), "..")

	// Prepare certificate paths
	cert := strings.TrimSuffix(_test.Cert1Path, filepath.Ext(_test.Cert1Path))
	certPem := filepath.Join(root, _test.TestDirPath, cert+".pem")
	key := strings.TrimSuffix(_test.Key1Path, filepath.Ext(_test.Key1Path))
	keyPem := filepath.Join(root, _test.TestDirPath, key+".pem")

	// Define message
	message := []byte("a very important signed test message")

	// Unfortunately we are not able to compare the result, as sign is not deterministic !
	type args struct {
		message           []byte
		pathOpenssl       string
		pathSignatureCert string
		pathSignatureKey  string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"valid", args{message, _test.OpensslPath, certPem, keyPem}, false},
		{"invalid-no-message", args{[]byte{}, _test.OpensslPath, certPem, keyPem}, true},
		{"invalid-exe", args{message, "notexisting", certPem, keyPem}, true},
		{"invalid-no-exe", args{message, "", certPem, keyPem}, true},
		{"invalid-cert", args{message, _test.OpensslPath, "notexisting", keyPem}, true},
		{"invalid-no-cert", args{message, _test.OpensslPath, "", keyPem}, true},
		{"invalid-key", args{message, _test.OpensslPath, certPem, "notexisting"}, true},
		{"invalid-no-key", args{message, _test.OpensslPath, certPem, ""}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Run test
			signed, err := SignMessage(tt.args.pathOpenssl, tt.args.pathSignatureCert, tt.args.pathSignatureKey, tt.args.message)
			if (err != nil) != tt.wantErr {
				t.Errorf("sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Check for error
			if err != nil {
				return
			}

			// Create the command for verifying the signature. This is very similar to the singing process, so take this
			// test with a grain of salt. Also have to include the -noverify flag, as we have a self signed certificate.
			argsVerify := []string{"smime", "-verify", "-noverify"}
			cmdVerify := exec.Command(tt.args.pathOpenssl, argsVerify...)

			// Set the correct i/o buffers. Stream the signed message to stdin rather than saving it to a file.
			in := bytes.NewReader(signed)
			out := &bytes.Buffer{}
			errs := &bytes.Buffer{}
			cmdVerify.Stdin, cmdVerify.Stdout, cmdVerify.Stderr = in, out, errs

			// Actually run the verification
			errVerify := cmdVerify.Run()
			if errVerify != nil {
				if len(errs.Bytes()) > 0 {
					t.Errorf("error verifying message (%s):\n %v", errVerify, errs.String())
					return
				}
				t.Errorf("errVerify: %s", errVerify)
				return
			}

			// Unify the line feed (on windows it is []byte{13 10})
			errsB := bytes.ReplaceAll(errs.Bytes(), []byte{13, 10}, []byte{10})
			outB := bytes.ReplaceAll(out.Bytes(), []byte{13, 10}, []byte{10})

			// Check output
			if !bytes.Equal(outB, message) || string(errsB) != "Verification successful\n" {
				t.Errorf("could not verify signature. out: '%s', err: '%s'", string(outB), string(errsB))
			}
		})
	}
}

func Test_encryptMessage(t *testing.T) {

	// Make sure all the variables needed for the tests are set
	if _test.OpensslPath == "" || _test.Cert2Path == "" || _test.Key2Path == "" || _test.Cert1Path == "" || _test.Key1Path == "" {
		t.Errorf("please fill out the test configuration and restart the test")
		return
	}

	// Retrieve the project root and build the absolute paths
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Errorf("could not get caller information")
		return
	}
	root := filepath.Join(filepath.Dir(file), "..")

	// Prepare certificate paths
	cert1 := strings.TrimSuffix(_test.Cert1Path, filepath.Ext(_test.Cert1Path))
	cert1Pem := filepath.Join(root, _test.TestDirPath, cert1+".pem")
	cert1Der := filepath.Join(root, _test.TestDirPath, cert1+".der")
	cert2 := strings.TrimSuffix(_test.Cert2Path, filepath.Ext(_test.Cert2Path))
	cert2Pem := filepath.Join(root, _test.TestDirPath, cert2+".pem")

	// Prepare key paths
	key1 := strings.TrimSuffix(_test.Key1Path, filepath.Ext(_test.Key1Path))
	key1Pem := filepath.Join(root, _test.TestDirPath, key1+".pem")
	key1Der := filepath.Join(root, _test.TestDirPath, key1+".der")
	key2 := strings.TrimSuffix(_test.Key2Path, filepath.Ext(_test.Key2Path))
	key2Pem := filepath.Join(root, _test.TestDirPath, key2+".pem")

	// Define subject, message and e-mail addresses
	subject := "some encrypted test mail"
	message := []byte("a very important encrypted test message")

	// Unfortunately we are not able to compare the result, as encrypt is not deterministic!
	type args struct {
		subject             string
		message             []byte
		mailFrom            string
		mailRecipients      []string
		pathOpenssl         string
		pathEncryptionCerts []string
	}
	tests := []struct {
		name    string
		args    args
		keys    []string
		wantErr bool
	}{
		{"valid-pem", args{subject, message, _test.MailFrom.Address, []string{_test.MailTo.Address}, _test.OpensslPath, []string{cert2Pem}}, []string{key2Pem}, false},
		{"valid-der", args{subject, message, _test.MailFrom.Address, []string{_test.MailTo.Address}, _test.OpensslPath, []string{cert1Der}}, []string{key1Der}, false},
		{"valid-no-subject", args{"", message, _test.MailFrom.Address, []string{_test.MailTo.Address}, _test.OpensslPath, []string{cert2Pem}}, []string{key2Pem}, false},
		{"valid-no-sender", args{subject, message, "", []string{_test.MailTo.Address}, _test.OpensslPath, []string{cert2Pem}}, []string{key2Pem}, false},
		{"valid-multiple-recipients", args{subject, message, _test.MailFrom.Address, []string{_test.MailTo.Address, _test.MailFrom.Address}, _test.OpensslPath, []string{cert2Pem, cert1Pem}}, []string{key2Pem, key1Pem}, false},
		{"valid-multiple-mixed-recipients", args{subject, message, _test.MailFrom.Address, []string{_test.MailFrom.Address, _test.MailTo.Address}, _test.OpensslPath, []string{cert1Pem, cert2Pem}}, []string{key1Pem, key2Pem}, false},
		{"invalid-no-message", args{subject, []byte{}, _test.MailFrom.Address, []string{_test.MailTo.Address}, _test.OpensslPath, []string{cert1Pem}}, []string{}, true},
		{"invalid-nil-message", args{subject, nil, _test.MailFrom.Address, []string{_test.MailTo.Address}, _test.OpensslPath, []string{cert1Pem}}, []string{}, true},
		{"invalid-der", args{subject, message, _test.MailFrom.Address, []string{_test.MailTo.Address}, _test.OpensslPath, []string{filepath.Join(root, _test.TestDirPath, "notexisting.der")}}, []string{}, true},
		{"invalid-exe", args{subject, message, _test.MailFrom.Address, []string{_test.MailTo.Address}, "notexisting", []string{cert1Pem}}, []string{}, true},
		{"invalid-no-exe", args{subject, message, _test.MailFrom.Address, []string{_test.MailTo.Address}, "", []string{cert1Pem}}, []string{}, true},
		{"invalid-no-recipients", args{subject, message, _test.MailFrom.Address, []string{}, _test.OpensslPath, []string{cert1Pem, cert2Pem}}, []string{}, true},
		{"invalid-nil-recipients", args{subject, message, _test.MailFrom.Address, nil, _test.OpensslPath, []string{cert1Pem, cert2Pem}}, []string{}, true},
		{"invalid-no-certs", args{subject, message, _test.MailFrom.Address, []string{_test.MailTo.Address, _test.MailFrom.Address}, _test.OpensslPath, []string{}}, []string{}, true},
		{"invalid-nil-certs", args{subject, message, _test.MailFrom.Address, []string{_test.MailTo.Address, _test.MailFrom.Address}, _test.OpensslPath, nil}, []string{}, true},
		{"invalid-not-enough-certs", args{subject, message, _test.MailFrom.Address, []string{_test.MailTo.Address, _test.MailFrom.Address}, _test.OpensslPath, []string{cert1Pem}}, []string{}, true},
		{"invalid-not-enough-recipients", args{subject, message, _test.MailFrom.Address, []string{_test.MailTo.Address}, _test.OpensslPath, []string{cert1Pem, cert2Pem}}, []string{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc, err := EncryptMessage(tt.args.pathOpenssl, tt.args.mailFrom, tt.args.mailRecipients, tt.args.subject, tt.args.message, tt.args.pathEncryptionCerts)
			if (err != nil) != tt.wantErr {
				t.Errorf("encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Check for error
			if err != nil {
				return
			}

			// Iterate keys to test with
			for _, key := range tt.keys {

				// Create the command for verifying the encryption. This is very similar to the encryption process, so
				// take this test with a grain of salt.
				argsDecrypt := []string{"smime", "-decrypt", "-inkey", key}
				cmdDecrypt := exec.Command(tt.args.pathOpenssl, argsDecrypt...)

				// Set the correct i/o buffers. Stream the encrypted message to stdin rather than saving it to a file.
				in := bytes.NewReader(enc)
				out := &bytes.Buffer{}
				errs := &bytes.Buffer{}
				cmdDecrypt.Stdin, cmdDecrypt.Stdout, cmdDecrypt.Stderr = in, out, errs

				// Actually run the decryption
				errDecrypt := cmdDecrypt.Run()
				if errDecrypt != nil {
					if len(errs.Bytes()) > 0 {
						t.Errorf("error decrypting message (%s):\n %v", errDecrypt, errs.String())
						return
					}
					t.Errorf("errDecrypt: %s", errDecrypt)
					return
				}

				// Unify the line feed (on windows it is []byte{13 10})
				errsB := bytes.ReplaceAll(errs.Bytes(), []byte{13, 10}, []byte{10})
				outB := bytes.ReplaceAll(out.Bytes(), []byte{13, 10}, []byte{10})

				// Check result
				if !bytes.Equal(outB, message) || string(errsB) != "" {
					t.Errorf("could not decrypt message. out: '%s', err: '%s'", string(outB), string(errsB))
				}
			}
		})
	}
}
