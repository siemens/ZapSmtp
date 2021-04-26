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
	"bytes"
	"io/ioutil"
	"net/mail"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"zap-smtp/_test"
)

func Test_convertSignatureParameters(t *testing.T) {

	// Make sure all the variables needed for the tests are set
	if _test.OpensslPath == "" || _test.Cert2 == "" || _test.Cert1 == "" || _test.Key1 == "" {
		t.Errorf("please fill out the test configuration and restart the test")
		return
	}

	// Retrieve the project root and build the absolute paths
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Errorf("unable to get caller information")
		return
	}
	root := filepath.Join(filepath.Dir(file), "..")

	cert := strings.TrimSuffix(_test.Cert1, filepath.Ext(_test.Cert1))
	key := strings.TrimSuffix(_test.Key1, filepath.Ext(_test.Key1))
	certPem := filepath.Join(root, _test.TestDir, cert+".pem")
	certDer := filepath.Join(root, _test.TestDir, cert+".der")
	keyPem := filepath.Join(root, _test.TestDir, key+".pem")
	keyDer := filepath.Join(root, _test.TestDir, key+".der")

	cert2 := strings.TrimSuffix(_test.Cert2, filepath.Ext(_test.Cert2))
	cert2Pem := filepath.Join(root, _test.TestDir, cert2+".pem")
	cert2Der := filepath.Join(root, _test.TestDir, cert2+".der")

	wantCert, err := ioutil.ReadFile(certPem)
	if err != nil {
		t.Errorf("unable load cert: %s", err)
		return
	}
	wantKey, err := ioutil.ReadFile(keyPem)
	if err != nil {
		t.Errorf("unable load key: %s", err)
		return
	}

	// Unify the line feed (on windows it is []byte{13 10})
	wantCert = bytes.ReplaceAll(wantCert, []byte{13, 10}, []byte{10})
	wantKey = bytes.ReplaceAll(wantKey, []byte{13, 10}, []byte{10})

	type args struct {
		openSslPath string
		senderCert  string
		senderKey   string
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
			fromCert, errLoadCert := ioutil.ReadFile(tt.args.senderCert)
			if errLoadCert != nil && tt.args.senderCert != "" {
				t.Errorf("could not load sender certificate: %s", errLoadCert)
				return
			}
			fromKey, errLoadKey := ioutil.ReadFile(tt.args.senderKey)
			if errLoadKey != nil && tt.args.senderKey != "" {
				t.Errorf("could not load sender key: %s", errLoadKey)
				return
			}

			got, got1, err := PrepareSignatureKeys(
				tt.args.openSslPath,
				fromCert,
				fromKey,
			)
			if (err != nil) != tt.wantErr {
				t.Errorf("PrepareSignatureKeys() error = %v, wantErr %v", err, tt.wantErr)
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

func Test_convertEncryptionParameters(t *testing.T) {

	// Make sure all the variables needed for the tests are set
	if _test.OpensslPath == "" || _test.Cert2 == "" || _test.Cert1 == "" {
		t.Errorf("please fill out the test configuration and restart the test")
		return
	}

	// Retrieve the project root and build the absolute paths
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Errorf("unable to get caller information")
		return
	}
	root := filepath.Join(filepath.Dir(file), "..")

	cert1 := strings.TrimSuffix(_test.Cert1, filepath.Ext(_test.Cert1))
	cert2 := strings.TrimSuffix(_test.Cert2, filepath.Ext(_test.Cert2))
	cert1Pem := filepath.Join(root, _test.TestDir, cert1+".pem")
	cert1Der := filepath.Join(root, _test.TestDir, cert1+".der")
	cert2Pem := filepath.Join(root, _test.TestDir, cert2+".pem")
	cert2Der := filepath.Join(root, _test.TestDir, cert2+".der")

	wantCert1, err := ioutil.ReadFile(cert1Pem)
	if err != nil {
		t.Errorf("unable load cert 1: %s", err)
		return
	}
	wantCert2, err2 := ioutil.ReadFile(cert2Pem)
	if err2 != nil {
		t.Errorf("unable load cert 2: %s", err2)
		return
	}

	// Unify the line feed (on windows it is []byte{13 10})
	wantCert1 = bytes.ReplaceAll(wantCert1, []byte{13, 10}, []byte{10})
	wantCert2 = bytes.ReplaceAll(wantCert2, []byte{13, 10}, []byte{10})

	type args struct {
		openSslPath string
		toCerts     []string
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
			toCerts := make([][]byte, 0, len(tt.args.toCerts))
			for _, recipientCert := range tt.args.toCerts {
				toCert, errLoad := ioutil.ReadFile(recipientCert)
				if errLoad != nil && recipientCert != "" {
					t.Errorf("could not load recipient certificate: %s", errLoad)
					return
				}
				toCerts = append(toCerts, toCert)
			}

			got, errPrepare := PrepareEncryptionKeys(tt.args.openSslPath, toCerts)
			if (errPrepare != nil) != tt.wantErr {
				t.Errorf("PrepareEncryptionKeys() error = %v, wantErr %v", errPrepare, tt.wantErr)
				return
			}

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
	if _test.OpensslPath == "" || _test.Cert1 == "" {
		t.Errorf("please fill out the test configuration and restart the test")
		return
	}

	// Retrieve the project root and build the absolute paths
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Errorf("unable to get caller information")
		return
	}
	root := filepath.Join(filepath.Dir(file), "..")

	cert := strings.TrimSuffix(_test.Cert1, filepath.Ext(_test.Cert1))
	cert = filepath.Join(root, _test.TestDir, cert)

	// Load certificates
	certDer, errRead := ioutil.ReadFile(cert + ".der")
	if errRead != nil {
		t.Errorf("unable to read file '%s': %s", cert+".der", errRead)
		return
	}
	certPem, errRead := ioutil.ReadFile(cert + ".pem")
	if errRead != nil {
		t.Errorf("unable to read file '%s': %s", cert+".pem", errRead)
		return
	}

	type args struct {
		opensslPath string
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
			got, err := certToPem(tt.args.opensslPath, tt.args.cert)
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
	if _test.OpensslPath == "" || _test.Key1 == "" {
		t.Errorf("please fill out the test configuration and restart the test")
		return
	}

	// Retrieve the project root and build the absolute paths
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Errorf("unable to get caller information")
		return
	}
	root := filepath.Join(filepath.Dir(file), "..")

	key := strings.TrimSuffix(_test.Key1, filepath.Ext(_test.Key1))
	key = filepath.Join(root, _test.TestDir, key)

	// Load Keys
	keyDer, errRead := ioutil.ReadFile(key + ".der")
	if errRead != nil {
		t.Errorf("unable to read file '%s': %s", key+".der", errRead)
		return
	}
	keyPem, errRead := ioutil.ReadFile(key + ".pem")
	if errRead != nil {
		t.Errorf("unable to read file '%s': %s", key+".pem", errRead)
		return
	}

	type args struct {
		opensslPath string
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
			got, err := keyToPem(tt.args.opensslPath, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("derToPem() error = '%v', wantErr '%v'", err, tt.wantErr)
				return
			}

			// Remove any carriage return codes to make the check work more consistently
			got = bytes.ReplaceAll(got, []byte{13}, []byte{})
			want := bytes.ReplaceAll(tt.want, []byte{13}, []byte{})

			if !reflect.DeepEqual(got, want) {
				t.Errorf("derToPem() got = '%v',\nwant '%v'", got, want)
			}
		})
	}
}

func Test_signMessage(t *testing.T) {

	// Make sure all the variables needed for the tests are set
	if _test.OpensslPath == "" || _test.Cert1 == "" || _test.Key1 == "" {
		t.Errorf("please fill out the test configuration and restart the test")
		return
	}

	// Retrieve the project root and build the absolute paths
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Errorf("unable to get caller information")
		return
	}
	root := filepath.Join(filepath.Dir(file), "..")

	cert := strings.TrimSuffix(_test.Cert1, filepath.Ext(_test.Cert1))
	certPem := filepath.Join(root, _test.TestDir, cert+".pem")
	certDer := filepath.Join(root, _test.TestDir, cert+".der")
	key := strings.TrimSuffix(_test.Key1, filepath.Ext(_test.Key1))
	keyPem := filepath.Join(root, _test.TestDir, key+".pem")
	keyDer := filepath.Join(root, _test.TestDir, key+".der")

	// Define message
	message := []byte("a very important signed test message")

	// Unfortunately we are not able to compare the result, as sign is not deterministic !
	type args struct {
		message        []byte
		openSslPath    string
		senderCertPath string
		senderKeyPath  string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"valid", args{message, _test.OpensslPath, certPem, keyPem}, false},
		{"invalid-no-message", args{[]byte{}, _test.OpensslPath, certPem, keyPem}, true},
		{"invalid-der-cert", args{message, _test.OpensslPath, certDer, keyPem}, true},
		{"invalid-der-key", args{message, _test.OpensslPath, certPem, keyDer}, true},
		{"invalid-exe", args{message, "notexisting", certPem, keyPem}, true},
		{"invalid-no-exe", args{message, "", certPem, keyPem}, true},
		{"invalid-cert", args{message, _test.OpensslPath, "notexisting", keyPem}, true},
		{"invalid-no-cert", args{message, _test.OpensslPath, "", keyPem}, true},
		{"invalid-key", args{message, _test.OpensslPath, certPem, "notexisting"}, true},
		{"invalid-no-key", args{message, _test.OpensslPath, certPem, ""}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signed, err := signMessage(tt.args.openSslPath, tt.args.senderCertPath, tt.args.senderKeyPath, tt.args.message)
			if (err != nil) != tt.wantErr {
				t.Errorf("sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil {
				return
			}

			// Create the command for verifying the signature. This is very similar to the singing process, so take this
			// test with a grain of salt. Also have to include the -noverify flag, as we have a self signed certificate.
			argsVerify := []string{"smime", "-verify", "-noverify"}
			cmdVerify := exec.Command(tt.args.openSslPath, argsVerify...)

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

			if !bytes.Equal(outB, message) || string(errsB) != "Verification successful\n" {
				t.Errorf("unable to verify signature. out: '%s', err: '%s'", string(outB), string(errsB))
			}
		})
	}
}

func Test_encryptMessage(t *testing.T) {

	// Make sure all the variables needed for the tests are set
	if _test.OpensslPath == "" || _test.Cert2 == "" || _test.Key2 == "" || _test.Cert1 == "" || _test.Key1 == "" {
		t.Errorf("please fill out the test configuration and restart the test")
		return
	}

	// Retrieve the project root and build the absolute paths
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Errorf("unable to get caller information")
		return
	}
	root := filepath.Join(filepath.Dir(file), "..")

	cert1 := strings.TrimSuffix(_test.Cert1, filepath.Ext(_test.Cert1))
	cert1Pem := filepath.Join(root, _test.TestDir, cert1+".pem")
	cert1Der := filepath.Join(root, _test.TestDir, cert1+".der")
	cert2 := strings.TrimSuffix(_test.Cert2, filepath.Ext(_test.Cert2))
	cert2Pem := filepath.Join(root, _test.TestDir, cert2+".pem")
	key1 := strings.TrimSuffix(_test.Key1, filepath.Ext(_test.Key1))
	key1Pem := filepath.Join(root, _test.TestDir, key1+".pem")
	key2 := strings.TrimSuffix(_test.Key2, filepath.Ext(_test.Key2))
	key2Pem := filepath.Join(root, _test.TestDir, key2+".pem")

	// Define subject, message and e-mail addresses
	subject := "some encrypted test mail"
	message := []byte("a very important encrypted test message")

	// Unfortunately we are not able to compare the result, as encrypt is not deterministic!
	type args struct {
		subject     string
		message     []byte
		openSslPath string
		from        string
		to          []string
		toCerts     []string
	}
	tests := []struct {
		name    string
		args    args
		keys    []string
		wantErr bool
	}{
		{"valid-pem", args{subject, message, _test.OpensslPath, _test.Sender.Address, []string{_test.Recipient.Address}, []string{cert2Pem}}, []string{key2Pem}, false},
		{"valid-no-subject", args{"", message, _test.OpensslPath, _test.Sender.Address, []string{_test.Recipient.Address}, []string{cert2Pem}}, []string{key2Pem}, false},
		{"valid-no-sender", args{subject, message, _test.OpensslPath, "", []string{_test.Recipient.Address}, []string{cert2Pem}}, []string{key2Pem}, false},
		{"valid-multiple-recipients", args{subject, message, _test.OpensslPath, _test.Sender.Address, []string{_test.Recipient.Address, _test.Sender.Address}, []string{cert2Pem, cert1Pem}}, []string{key2Pem, key1Pem}, false},
		{"valid-multiple-mixed-recipients", args{subject, message, _test.OpensslPath, _test.Sender.Address, []string{_test.Sender.Address, _test.Recipient.Address}, []string{cert1Pem, cert2Pem}}, []string{key1Pem, key2Pem}, false},
		{"invalid-no-message", args{subject, []byte{}, _test.OpensslPath, _test.Sender.Address, []string{_test.Recipient.Address}, []string{cert1Pem}}, []string{}, true},
		{"invalid-nil-message", args{subject, nil, _test.OpensslPath, _test.Sender.Address, []string{_test.Recipient.Address}, []string{cert1Pem}}, []string{}, true},
		{"invalid-der", args{subject, message, _test.OpensslPath, _test.Sender.Address, []string{_test.Recipient.Address}, []string{cert1Der}}, []string{}, true},
		{"invalid-exe", args{subject, message, "notexisting", _test.Sender.Address, []string{_test.Recipient.Address}, []string{cert1Pem}}, []string{}, true},
		{"invalid-no-exe", args{subject, message, "", _test.Sender.Address, []string{_test.Recipient.Address}, []string{cert1Pem}}, []string{}, true},
		{"invalid-no-recipients", args{subject, message, _test.OpensslPath, _test.Sender.Address, []string{}, []string{cert1Pem, cert2Pem}}, []string{}, true},
		{"invalid-nil-recipients", args{subject, message, _test.OpensslPath, _test.Sender.Address, nil, []string{cert1Pem, cert2Pem}}, []string{}, true},
		{"invalid-no-certs", args{subject, message, _test.OpensslPath, _test.Sender.Address, []string{_test.Recipient.Address, _test.Sender.Address}, []string{}}, []string{}, true},
		{"invalid-nil-certs", args{subject, message, _test.OpensslPath, _test.Sender.Address, []string{_test.Recipient.Address, _test.Sender.Address}, nil}, []string{}, true},
		{"invalid-not-enough-certs", args{subject, message, _test.OpensslPath, _test.Sender.Address, []string{_test.Recipient.Address, _test.Sender.Address}, []string{cert1Pem}}, []string{}, true},
		{"invalid-not-enough-recipients", args{subject, message, _test.OpensslPath, _test.Sender.Address, []string{_test.Recipient.Address}, []string{cert1Pem, cert2Pem}}, []string{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc, err := encryptMessage(tt.args.openSslPath, tt.args.from, tt.args.to, tt.args.toCerts, tt.args.subject, tt.args.message)
			if (err != nil) != tt.wantErr {
				t.Errorf("encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil {
				return
			}

			for _, key := range tt.keys {

				// Create the command for verifying the encryption. This is very similar to the encryption process, so
				// take this test with a grain of salt.
				argsDecrypt := []string{"smime", "-decrypt", "-inkey", key}
				cmdDecrypt := exec.Command(tt.args.openSslPath, argsDecrypt...)

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

				if !bytes.Equal(outB, message) || string(errsB) != "" {
					t.Errorf("unable to decrypt message. out: '%s', err: '%s'", string(outB), string(errsB))
				}
			}
		})
	}
}

// Unfortunately testing the correct sending of mails is not that easy and relies on manual labor. The correctness can
// only be reviewed manually

func Test_sendMail(t *testing.T) {

	// Make sure all the variables needed for the tests are set
	if _test.OpensslPath == "" ||
		_test.Cert1 == "" ||
		_test.Key1 == "" ||
		_test.RealRecipient.Address == "" ||
		_test.Server == "" ||
		_test.Port == 0 {
		t.Errorf("please configure the OpenSSL installation path and restart the test")
		return
	}

	var toCerts []string
	var toCertsDouble []string
	if len(_test.RealCert) > 0 {
		toCerts = append(toCerts, _test.RealCert)
		toCertsDouble = append(toCertsDouble, _test.RealCert)
		toCertsDouble = append(toCertsDouble, _test.RealCert)
	}

	type args struct {
		msg         []byte
		server      string
		port        uint16
		subject     string
		from        mail.Address
		to          []mail.Address
		opensslPath string
		fromCert    string
		fromKey     string
		toCerts     []string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"valid", args{[]byte("valid email"), _test.Server, _test.Port, _test.Subject, _test.Sender, []mail.Address{{"Test", _test.RealRecipient.Address}}, _test.OpensslPath, _test.Cert1, _test.Key1, toCerts}, false},
		{"valid-no-subject", args{[]byte("valid email, but no subject"), _test.Server, _test.Port, "", _test.Sender, []mail.Address{{"Test", _test.RealRecipient.Address}}, _test.OpensslPath, _test.Cert1, _test.Key1, toCerts}, false},
		{"valid-no-message", args{[]byte(""), _test.Server, _test.Port, _test.Subject + " (no content inside)", _test.Sender, []mail.Address{{"Test", _test.RealRecipient.Address}}, _test.OpensslPath, _test.Cert1, _test.Key1, toCerts}, false},
		{"valid-multiple-recipients", args{[]byte("valid email, sent to multiple recipients"), _test.Server, _test.Port, _test.Subject, _test.Sender, []mail.Address{{"Test", _test.RealRecipient.Address}, {"Test", _test.RealRecipient.Address}}, _test.OpensslPath, _test.Cert1, _test.Key1, toCertsDouble}, false},
		{"valid-no-signing", args{[]byte("valid email, not signed"), _test.Server, _test.Port, _test.Subject, _test.Sender, []mail.Address{{"Test", _test.RealRecipient.Address}}, _test.OpensslPath, "", "", toCerts}, false},
		{"valid-no-encryption", args{[]byte("valid email, not encrypted"), _test.Server, _test.Port, _test.Subject, _test.Sender, []mail.Address{{"Test", _test.RealRecipient.Address}}, _test.OpensslPath, _test.Cert1, _test.Key1, []string{}}, false},
		{"valid-plain", args{[]byte("valid email, not signed and not encrypted"), _test.Server, _test.Port, _test.Subject, _test.Sender, []mail.Address{{"Test", _test.RealRecipient.Address}}, "", "", "", []string{}}, false},

		{"invalid-host", args{[]byte("some test message that should NOT be received"), "notexisting", _test.Port, _test.Subject, _test.Sender, []mail.Address{{"Test", _test.RealRecipient.Address}}, _test.OpensslPath, _test.Cert1, _test.Key1, toCerts}, true},
		{"invalid-from", args{[]byte("some test message that should NOT be received"), _test.Server, _test.Port, _test.Subject, mail.Address{"Test", "notexisting@test.com"}, []mail.Address{{"Test", _test.RealRecipient.Address}}, _test.OpensslPath, _test.Cert1, _test.Key1, toCerts}, true},
		{"invalid-to", args{[]byte("some test message that should NOT be received"), _test.Server, _test.Port, _test.Subject, _test.Sender, []mail.Address{{"Test", "notexisting@test.com"}}, _test.OpensslPath, _test.Cert1, _test.Key1, toCerts}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			err := SendMail(
				tt.args.server,
				tt.args.port,
				tt.args.from,
				tt.args.to,
				tt.args.subject,
				tt.args.msg,
				tt.args.opensslPath,
				tt.args.fromCert,
				tt.args.fromKey,
				tt.args.toCerts,
			)
			if (err != nil) != tt.wantErr {
				t.Errorf("SendMail() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
