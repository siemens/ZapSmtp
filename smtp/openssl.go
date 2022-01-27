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
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/mail"
	"net/smtp"
	"os"
	"os/exec"
	"strings"
)

// PrepareSignatureKeys converts the sender's key pair to PEM if necessary and verifies that they are a matching
// key pair.
func PrepareSignatureKeys(
	openSslPath string,
	signatureCert []byte,
	signatureKey []byte,
) ([]byte, []byte, error) {

	// Prepare memory
	var err error

	// Check whether the certificate and key are already in PEM format, and try to convert them if not
	if block, _ := pem.Decode(signatureCert); block == nil {
		signatureCert, err = certToPem(openSslPath, signatureCert)
		if err != nil {
			return nil, nil, fmt.Errorf("sender certificate: %s", err)
		}
	}
	if block, _ := pem.Decode(signatureKey); block == nil {
		signatureKey, err = keyToPem(openSslPath, signatureKey)
		if err != nil {
			return nil, nil, fmt.Errorf("sender key: %s", err)
		}
	}

	// Check whether the private key and the public key match. Otherwise any validation of the signature would fail.
	// First create a matching public key for the private key
	args := []string{"pkey", "-pubout", "-outform", "pem"}
	cmd := exec.Command(openSslPath, args...)

	// Create the needed buffers. We stream the key to stdin rather than saving it in a file first.
	in := bytes.NewReader(signatureKey)
	outPriv := &bytes.Buffer{}
	errsPriv := &bytes.Buffer{}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = in, outPriv, errsPriv

	if err := cmd.Run(); err != nil {
		if len(errsPriv.Bytes()) > 0 {
			return nil, nil, fmt.Errorf("error checking sender's private key (%s):\n %v", err, errsPriv.String())
		}
		return nil, nil, err
	}

	// Secondly read the public key from the certificate
	args = []string{"x509", "-pubkey", "-noout", "-outform", "pem"}
	cmd = exec.Command(openSslPath, args...)

	// Create new buffers buffers, we can't reuse the old ones by resetting, as buffer is not thread safe. We stream the
	// certificate to stdin rather than saving it in a file first.
	inCert := bytes.NewReader(signatureCert)
	outPub := &bytes.Buffer{}
	errsPub := &bytes.Buffer{}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = inCert, outPub, errsPub

	if errRun := cmd.Run(); errRun != nil {
		if len(errsPub.Bytes()) > 0 {
			return nil, nil, fmt.Errorf("error checking sender's certificate (%s):\n %v", errRun, errsPub.String())
		}
		return nil, nil, errRun
	}

	// Compare string results - PEM format is base64 encoded and this way no reflection is needed.
	if string(outPriv.Bytes()) != string(outPub.Bytes()) {
		return nil, nil, fmt.Errorf("private key and certificate of sender do not match")
	}

	// Return signing certificate and key
	return signatureCert, signatureKey, nil
}

// PrepareEncryptionKeys converts a list of encryption keys to PEM if necessary. The order of the recipients and
// their certificates does not have to match and no check is performed, that the certificates actually belong to
// later recipients.
func PrepareEncryptionKeys(
	openSslPath string,
	encryptionKeys [][]byte,
) ([][]byte, error) {

	// Prepare memory
	var err error
	keys := make([][]byte, 0, len(encryptionKeys))

	// Go through the recipient certificates, convert them to PEM format if needed and save them to temporary files
	for _, encryptionKey := range encryptionKeys {

		// Check whether the certificate and key are already in PEM format, and try to convert them if not
		if block, _ := pem.Decode(encryptionKey); block == nil {
			encryptionKey, err = certToPem(openSslPath, encryptionKey)
			if err != nil {
				return nil, fmt.Errorf("recipient certificate: %s", err)
			}
		}
		keys = append(keys, encryptionKey)
	}

	// Set the encryption information on the SmtpContext and return it
	return keys, nil
}

// SendMail prepares the email message, signs it if possible, encrypts it if possible and sends it out via SMTP to
// a list of recipients.
func SendMail(
	server string,
	port uint16,
	username string, // Leave empty to skip authentication
	password string, // Leave empty to skip authentication
	from mail.Address,
	to []mail.Address,
	subject string,
	message []byte,
	opensslPath string,
	fromCertPath string, // Path to the signing certificate
	fromKeyPath string, // Path to the signing key
	toCertPaths []string, // List of paths to encryption certificates of recipients
) error {

	// Check if right amount of certificates was passed
	if len(toCertPaths) > 0 && len(toCertPaths) != len(to) {
		return fmt.Errorf("list of certificates does not match recipients")
	}

	// Prepare some header values
	toStrs := make([]string, len(to))
	toAddrs := make([]string, len(to))
	for i, r := range to {
		toStrs[i] = r.String()
		toAddrs[i] = r.Address
	}

	// Prepare e-mail headers including the base64 encoded message body
	header := fmt.Sprintf("From: %s\r\n", from.String())
	header += fmt.Sprintf("To: %s\r\n", strings.Join(toStrs, ", "))
	header += fmt.Sprintf("Subject: %s\r\n", subject)
	header += "MIME-Version: 1.0\r\n"
	header += "Content-Type: text/plain; charset=\"utf-8\"\r\n"
	header += "Content-Transfer-Encoding: base64\r\n"
	header += "\r\n"

	// Prepare message bytes for [signing, encrypting and] sending
	messageRaw := make([]byte, len(header)+base64.StdEncoding.EncodedLen(len(message)))
	copy(messageRaw, header)
	base64.StdEncoding.Encode(messageRaw[len(header):], message)

	// Sign message if desired, indicated by input parameters
	if len(fromCertPath) > 0 || len(fromKeyPath) > 0 {
		var errSign error
		messageRaw, errSign = signMessage(opensslPath, fromCertPath, fromKeyPath, messageRaw)
		if errSign != nil {
			return fmt.Errorf("could not sign message: %s", errSign)
		}
	}

	// Encrypt message if desired, indicated by input parameters
	if len(toCertPaths) > 0 {
		var errEnc error
		messageRaw, errEnc = encryptMessage(opensslPath, from.Address, toAddrs, toCertPaths, subject, messageRaw)
		if errEnc != nil {
			return fmt.Errorf("could not encrypt message: %s", errEnc)
		}
	}

	// Set authentication if desired
	var auth smtp.Auth
	if len(username) > 0 && len(password) > 0 {
		auth = smtp.PlainAuth("", username, password, server)
	}

	// Connect to the server, authenticate, set the sender and recipient and send the email all in one step.
	errSend := smtp.SendMail(
		fmt.Sprintf("%s:%d", server, port),
		auth,
		from.Address,
		toAddrs,
		messageRaw,
	)
	if errSend != nil {
		return fmt.Errorf("could not send mail: %s", errSend)
	}

	return nil
}

// SendMail2 is a wrapper function of the actual SendMail function and allows to supply certificates held in memory,
// rather than requiring parent function to handle file persistence and cleanup.
func SendMail2(
	server string,
	port uint16,
	username string, // Leave empty to skip authentication
	password string, // Leave empty to skip authentication
	from mail.Address,
	to []mail.Address,
	subject string,
	message []byte,
	opensslPath string,
	fromCert []byte,
	fromKey []byte,
	toCerts [][]byte,
	tempDir string, // Keys and certificates must be written to the disk for OpenSSL to use them
) error {

	// Prepare memory
	var fromCertPath, fromKeyPath string
	var err error

	// Prepare signature certificate and key
	if len(fromCert) > 0 && len(fromKey) > 0 {

		// Convert signature certificate and key if necessary
		fromCert, fromKey, err = PrepareSignatureKeys(opensslPath, fromCert, fromKey)
		if err != nil {
			return fmt.Errorf("unable to prepare signature key: %s", err)
		}

		// Write signing certificate to disk, where it can be used by OpenSSL
		fromCertPath, err = saveToTemp(fromCert, tempDir)
		if err != nil {
			return fmt.Errorf("error with sender certificate: %s", err)
		}
		defer func() { _ = os.Remove(fromCertPath) }()

		// Write signing key to disk, where it can be used by OpenSSL
		fromKeyPath, err = saveToTemp(fromKey, tempDir)
		if err != nil {
			return fmt.Errorf("error with sender key: %s", err)
		}
		defer func() { _ = os.Remove(fromKeyPath) }()
	}

	// Prepare encryption certificates
	toCertPaths := make([]string, 0, len(toCerts))
	if len(toCerts) > 0 {

		// Convert encryption certificates if necessary
		toCerts, err = PrepareEncryptionKeys(opensslPath, toCerts)
		if err != nil {
			return fmt.Errorf("unable to prepare encryption key: %s", err)
		}

		// Write encryption keys to disk, where it can be used by OpenSSL
		for _, toCert := range toCerts {
			cert, errSave := saveToTemp(toCert, tempDir)
			if errSave != nil {
				return fmt.Errorf("error with recipient certificate: %s", errSave)
			}
			defer func() { _ = os.Remove(cert) }()
			toCertPaths = append(toCertPaths, cert)
		}
	}

	// Call and return result of actual send mail function
	return SendMail(
		server,
		port,
		username,
		password,
		from,
		to,
		subject,
		message,
		opensslPath,
		fromCertPath,
		fromKeyPath,
		toCertPaths,
	)
}

// SendMail3 is a wrapper function of the actual SendMail2 and allows to supply a message as string, before passing
// data on to the actual SendMail function.
func SendMail3(
	server string,
	port uint16,
	username string, // Leave empty to skip authentication
	password string, // Leave empty to skip authentication
	from mail.Address,
	to []mail.Address,
	subject string,
	message string,
	opensslPath string,
	fromCert []byte,
	fromKey []byte,
	toCerts [][]byte,
	tempDir string, // Keys and certificates must be written to the disk for OpenSSL to use them
) error {

	// Call and return result of actual send mail function
	return SendMail2(
		server,
		port,
		username,
		password,
		from,
		to,
		subject,
		[]byte(message),
		opensslPath,
		fromCert,
		fromKey,
		toCerts,
		tempDir,
	)
}

// Returns the certificate in DER format to PEM format, it fails if the input is in any other encoding.
func certToPem(openSslPath string, cert []byte) ([]byte, error) {

	if len(cert) < 0 {
		return nil, fmt.Errorf("certificate must not be nil/empty")
	}

	// Try to transform the certificate from DER to PEM format
	args := []string{"x509", "-inform", "der", "-outform", "pem"}
	cmd := exec.Command(openSslPath, args...)

	// Create the needed buffers. We stream the certificate to stdin rather than saving it in a file first.
	in := bytes.NewReader(cert)
	out := &bytes.Buffer{}
	errs := &bytes.Buffer{}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = in, out, errs

	if err := cmd.Run(); err != nil {
		if len(errs.Bytes()) > 0 {
			return nil, fmt.Errorf("error converting certificate to PEM format (%s):\n %v", err, errs.String())
		}
		return nil, err
	}

	return out.Bytes(), nil
}

// Returns the key in DER format to PEM format, it fails if the input is in any other encoding.
func keyToPem(openSslPath string, key []byte) ([]byte, error) {

	if len(key) < 0 {
		return nil, fmt.Errorf("key must not be nil/empty")
	}

	// Try to transform the certificate from DER to PEM format
	args := []string{"pkey", "-inform", "der", "-outform", "pem"}
	cmd := exec.Command(openSslPath, args...)

	// Create the needed buffers. We stream the key to stdin rather than saving it in a file first.
	in := bytes.NewReader(key)
	out := &bytes.Buffer{}
	errs := &bytes.Buffer{}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = in, out, errs

	if err := cmd.Run(); err != nil {
		if len(errs.Bytes()) > 0 {
			return nil, fmt.Errorf("error converting key to PEM format (%s):\n %v", err, errs.String())
		}
		return nil, err
	}

	return out.Bytes(), nil
}

func signMessage(
	openSslPath string,
	fromCert string, // Path to certificate
	fromKey string, // Path to key
	message []byte,
) ([]byte, error) {

	// Sanity checks
	if len(openSslPath) == 0 {
		return nil, fmt.Errorf("invalid OpenSSL path")
	}
	if len(message) == 0 {
		return nil, fmt.Errorf("message is empty")
	}

	// Create the command for signing the message
	argsSign := []string{"smime", "-sign", "-signer", fromCert, "-inkey", fromKey}
	cmdSign := exec.Command(openSslPath, argsSign...)

	// Set the correct i/o buffers. Stream the message to stdin rather than saving it to a file.
	in := bytes.NewReader(message)
	out := &bytes.Buffer{}
	errs := &bytes.Buffer{}
	cmdSign.Stdin, cmdSign.Stdout, cmdSign.Stderr = in, out, errs

	// Actually run the signing
	errSign := cmdSign.Run()
	if errSign != nil {
		if len(errs.Bytes()) > 0 {
			return nil, fmt.Errorf("error signing message (%s):\n %v", errSign, errs.String())
		}
		return nil, errSign
	}

	return out.Bytes(), nil
}

func encryptMessage(
	openSslPath string,
	sender string,
	recipients []string,
	recipientCertPaths []string, // Paths to certificates
	subject string,
	message []byte,
) ([]byte, error) {

	// Sanity checks
	if len(openSslPath) == 0 {
		return nil, fmt.Errorf("invalid OpenSSL path")
	}
	if len(message) == 0 {
		return nil, fmt.Errorf("message is empty")
	}
	if len(recipients) < 1 {
		return nil, fmt.Errorf("no recipients defined")
	}
	if len(recipients) != len(recipientCertPaths) {
		return nil, fmt.Errorf(
			"number of recipients (%d) and number of certificates has to match (%d)",
			len(recipients), len(recipientCertPaths),
		)
	}

	// Create the command for encrypting the (signed) message
	argsEnc := []string{
		"smime",
		"-encrypt",
		"-from",
		sender,
		"-to",
		strings.Join(recipients, ", "),
		"-subject",
		subject,
		"-aes256",
	}
	argsEnc = append(argsEnc, recipientCertPaths...)
	cmdEnc := exec.Command(openSslPath, argsEnc...)

	// Set the correct i/o buffers. Stream the message to stdin rather than saving it to a file.
	inEnc := bytes.NewReader(message)
	outEnc := &bytes.Buffer{}
	errsEnc := &bytes.Buffer{}
	cmdEnc.Stdin, cmdEnc.Stdout, cmdEnc.Stderr = inEnc, outEnc, errsEnc

	// Actually run the encryption
	errEnc := cmdEnc.Run()
	if errEnc != nil {
		if len(errsEnc.Bytes()) > 0 {
			return nil, fmt.Errorf("error encrypting message (%s):\n %v", errEnc, errsEnc.String())
		}
		return nil, errEnc
	}

	return outEnc.Bytes(), nil
}

func saveToTemp(data []byte, tempDir string) (string, error) {

	// Create a temporary file and write the certificate to it
	f, errFile := ioutil.TempFile(tempDir, "*.pem")
	if errFile != nil {
		return "", fmt.Errorf("could not create file: %s", errFile)
	}

	// Get the path
	path := f.Name()

	_, errWrite := f.Write(data)
	if errWrite != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("could not write: %s", errWrite)
	}

	// Clean up the file descriptor - file needs to be removed later on.
	errClose := f.Close()
	if errClose != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("could not close file descriptor: %s", errClose)
	}

	return path, nil
}
