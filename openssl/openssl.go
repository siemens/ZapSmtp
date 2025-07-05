/*
* ZapSmtp, a Zap (Golang) logger extension for sending urgent log messages via SMTP
*
* Copyright (c) Siemens AG, 2021.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package openssl

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
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

	// Check whether the certificate and key are already in PEM format, and try to convert them if not
	var err error
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

	// Check whether the private key and the public key match. Otherwise, any validation of the signature would fail.
	// First create a matching public key for the private key
	cmd := exec.Command(openSslPath, "pkey", "-pubout", "-outform", "pem")
	cmd.Stdin = bytes.NewReader(signatureKey)

	// Create the needed buffers
	var outPriv, errsPriv bytes.Buffer
	cmd.Stdout = &outPriv
	cmd.Stderr = &errsPriv

	// Run command
	errRunPriv := cmd.Run()
	if errRunPriv != nil {
		return nil, nil, fmt.Errorf("could not check sender's private key (%s):\n %v", errRunPriv, errsPriv.String())
	}

	// Secondly read the public key from the certificate
	cmd = exec.Command(openSslPath, "x509", "-pubkey", "-noout", "-outform", "pem")
	cmd.Stdin = bytes.NewReader(signatureCert)

	// Create the needed buffers
	var outPub, errsPub bytes.Buffer
	cmd.Stdout = &outPub
	cmd.Stderr = &errsPub

	// Run command
	errRunPub := cmd.Run()
	if errRunPub != nil {
		return nil, nil, fmt.Errorf("could not check sender's certificate (%s):\n %v", errRunPub, errsPub.String())
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

// SendMail prepares the email message and sends it out via SMTP to a list of recipients.
// If signature certificate and key are provided, it will automatically sign the message.
// If encryption certificates are provided, it will automatically encrypt the message.
// Signature and encryption is done by calling OpenSSL via exec.Command. Since only one argument
// can be passed via Stdin, the signature/encryption keys/certificates must be passed as file paths.
func SendMail(
	smtpServer string,
	smtpPort uint16,
	smtpUser string, // Leave empty to skip authentication
	smtpPassword string, // Leave empty to skip authentication

	mailFrom mail.Address,
	mailTo []mail.Address,
	mailSubject string,
	mailMessage []byte,

	opensslPath string, // Can be omitted if neither signature nor encryption is desired
	signatureCertPath string, // Path to the signature certificate of sender. Can be omitted if no signature is desired.
	signatureKeyPath string, // Path to the signature key of sender. Can be omitted if no signature is desired.
	encryptionCertPaths []string, // Paths to encryption keys of recipients. Can be omitted if no signature is desired.
) error {

	// Check if right amount of certificates was passed
	if len(encryptionCertPaths) > 0 && len(encryptionCertPaths) != len(mailTo) {
		return fmt.Errorf("list of certificates does not match recipients")
	}

	// Prepare some header values
	toStrs := make([]string, len(mailTo))
	toAddrs := make([]string, len(mailTo))
	for i, r := range mailTo {
		toStrs[i] = r.String()
		toAddrs[i] = r.Address
	}

	// Prepare raw plaintext unsigned message
	var messageRaw []byte

	// Prepare unsigned message with required headers
	var msg bytes.Buffer
	msg.WriteString(fmt.Sprintf("From: %s\r\n", mailFrom.String()))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(toStrs, ", ")))
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", mailSubject))
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: text/plain; charset=\"utf-8\"\r\n")
	msg.WriteString("Content-Transfer-Encoding: base64\r\n")
	msg.WriteString("\r\n") // End of headers
	msg.WriteString(base64.StdEncoding.EncodeToString(mailMessage))

	// Assign unsigned plaintext message
	messageRaw = msg.Bytes()

	// Replace unsigned message with signed one
	if len(signatureCertPath) > 0 || len(signatureKeyPath) > 0 {

		// Sign message
		messageSigned, errSign := signMessage(opensslPath, signatureCertPath, signatureKeyPath, msg.Bytes())
		if errSign != nil {
			return fmt.Errorf("could not sign message: %s", errSign)
		}

		// Address OpenSSL bug
		// OpenSSL tries to be helpful by converting \n to CRLF (\r\n), because email standards (RFC 5322, MIME) expect it.
		// If input already uses Windows line endings (\r\n), OpenSSL might insert extra \r, resulting in \r\r\n or worse.
		// This breaks Outlook and other S/MIME-compliant mail readers, because the structure becomes malformed.
		messageSigned = bytes.Replace(messageSigned, []byte("\r\r\n"), []byte("\r\n"), -1)

		// Prepare signed message with required headers (some got removed by OpenSSL)
		var msgSigned bytes.Buffer
		msgSigned.WriteString(fmt.Sprintf("From: %s\r\n", mailFrom.String()))
		msgSigned.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(toStrs, ", ")))
		msgSigned.WriteString(fmt.Sprintf("Subject: %s\r\n", mailSubject))
		msgSigned.Write(messageSigned)

		// Assign signed message
		messageRaw = msgSigned.Bytes()
	}

	// Encrypt message if desired, indicated by input parameters
	if len(encryptionCertPaths) > 0 {
		var errEnc error
		messageRaw, errEnc = encryptMessage(opensslPath, mailFrom.Address, toAddrs, mailSubject, messageRaw, encryptionCertPaths)
		if errEnc != nil {
			return fmt.Errorf("could not encrypt message: %s", errEnc)
		}
	}

	// Set authentication if desired
	var auth smtp.Auth
	if len(smtpUser) > 0 && len(smtpPassword) > 0 {
		auth = smtp.PlainAuth("", smtpUser, smtpPassword, smtpServer)
	}

	// Connect to the server, authenticate, set the sender and recipient and send the email all in one step.
	errSend := smtp.SendMail(
		fmt.Sprintf("%s:%d", smtpServer, smtpPort),
		auth,
		mailFrom.Address,
		toAddrs,
		messageRaw,
	)
	if errSend != nil {
		return fmt.Errorf("could not send mail: %s", errSend)
	}

	// Return nil as everything went fine
	return nil
}

// SendMail2 is a wrapper function of the actual SendMail function receiving certificates/keys as []byte
// rather than file paths. It will take care of creating the necessary temporary files and their cleanup.
// Since only one argument can be passed to OpenSSL via Stdin, the signature/encryption keys/certificates
// must be passed as file paths.
func SendMail2(
	smtpServer string,
	smtpPort uint16,
	smtpUser string, // Leave empty to skip authentication
	smtpPassword string, // Leave empty to skip authentication

	mailFrom mail.Address,
	mailTo []mail.Address,
	mailSubject string,
	mailMessage []byte,

	opensslPath string, // Can be omitted if neither signature nor encryption is desired
	signatureCert []byte, // Signature certificate bytes of sender. Can be omitted if no signature is desired.
	signatureKey []byte, // Signature key bytes of sender. Can be omitted if no signature is desired.
	encryptionKeys [][]byte, // Encryption keys bytes of recipients. Can be omitted if no signature is desired.
) error {

	// Prepare memory
	var signatureCertPath, signatureKeyPath string
	var err error

	// Prepare signature certificate and key
	if len(signatureCert) > 0 && len(signatureKey) > 0 {

		// Convert signature certificate and key if necessary
		signatureCert, signatureKey, err = PrepareSignatureKeys(opensslPath, signatureCert, signatureKey)
		if err != nil {
			return fmt.Errorf("unable to prepare signature key: %s", err)
		}

		// Write signing certificate to disk, where it can be used by OpenSSL
		signatureCertPath, err = SaveToTemp(signatureCert, "openssl-signature-cert-*.pem")
		if err != nil {
			return fmt.Errorf("error with sender certificate: %s", err)
		}
		defer func() { _ = os.Remove(signatureCertPath) }()

		// Write signing key to disk, where it can be used by OpenSSL
		signatureKeyPath, err = SaveToTemp(signatureKey, "openssl-signature-key-*.pem")
		if err != nil {
			return fmt.Errorf("error with sender key: %s", err)
		}
		defer func() { _ = os.Remove(signatureKeyPath) }()
	}

	// Prepare encryption certificates
	encryptionCertPaths := make([]string, 0, len(encryptionKeys))
	if len(encryptionKeys) > 0 {

		// Convert encryption certificates if necessary
		encryptionKeys, err = PrepareEncryptionKeys(opensslPath, encryptionKeys)
		if err != nil {
			return fmt.Errorf("unable to prepare encryption key: %s", err)
		}

		// Write encryption keys to disk, where it can be used by OpenSSL
		for _, toCert := range encryptionKeys {
			cert, errSave := SaveToTemp(toCert, "openssl-encryption-cert-*.pem")
			if errSave != nil {
				return fmt.Errorf("error with recipient certificate: %s", errSave)
			}
			defer func() { _ = os.Remove(cert) }()
			encryptionCertPaths = append(encryptionCertPaths, cert)
		}
	}

	// Call and return result of actual send mail function
	return SendMail(
		smtpServer,
		smtpPort,
		smtpUser,
		smtpPassword,
		mailFrom,
		mailTo,
		mailSubject,
		mailMessage,
		opensslPath,
		signatureCertPath,
		signatureKeyPath,
		encryptionCertPaths,
	)
}

// certToPem returns the certificate in DER format to PEM format, it fails if the input is in any other encoding.
func certToPem(openSslPath string, cert []byte) ([]byte, error) {

	// Check if certificate was provided
	if len(cert) == 0 {
		return nil, fmt.Errorf("certificate must not be empty")
	}
	if _, err := x509.ParseCertificate(cert); err != nil {
		return nil, fmt.Errorf("certificate must be DER encoded")
	}

	// Create temporary file for the certificate
	tmpFile, errTmp := os.CreateTemp("", "openssl-cert-*.der")
	if errTmp != nil {
		return nil, fmt.Errorf("could not create temporary DER file: %v", errTmp)
	}

	// Cleanup temporary file afterward
	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name()) // ensure cleanup
	}()

	// Write the certificate bytes to the temp file
	_, errWrite := tmpFile.Write(cert)
	if errWrite != nil {
		return nil, fmt.Errorf("could not write temporary DER file: %v", errWrite)
	}

	// Flush content to disk
	errFlush := tmpFile.Sync()
	if errFlush != nil {
		return nil, fmt.Errorf("could not sync temp file: %w", errFlush)
	}

	// Try to transform the certificate from DER to PEM format
	cmd := exec.Command(openSslPath, "x509",
		"-inform", "der",
		"-in", tmpFile.Name(),
		"-outform", "pem",
	)

	// Create the needed buffers
	var out, errs bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errs

	// Run command
	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("could not convert certificate to PEM format (%s):\n %v", err, errs.String())
	}

	// Return output
	return out.Bytes(), nil
}

// keyToPem returns the key in DER format to PEM format, it fails if the input is in any other encoding.
func keyToPem(openSslPath string, key []byte) ([]byte, error) {

	// Check if key was provided
	if len(key) == 0 {
		return nil, fmt.Errorf("key must not be empty")
	}

	// Create temporary file for the key
	tmpFile, errTmp := os.CreateTemp("", "openssl-key-*.der")
	if errTmp != nil {
		return nil, fmt.Errorf("could not create temporary DER file: %v", errTmp)
	}

	// Cleanup temporary file afterward
	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name()) // ensure cleanup
	}()

	// Write the key bytes to the temp file
	_, errWrite := tmpFile.Write(key)
	if errWrite != nil {
		return nil, fmt.Errorf("could not write temporary DER file: %v", errWrite)
	}

	// Flush content to disk
	errFlush := tmpFile.Sync()
	if errFlush != nil {
		return nil, fmt.Errorf("could not sync temp file: %w", errFlush)
	}

	// Try to transform the key from DER to PEM format
	cmd := exec.Command(openSslPath, "pkey",
		"-inform", "der",
		"-in", tmpFile.Name(),
		"-outform", "pem",
	)

	// Create the needed buffers
	var out, errs bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errs

	// Run command
	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("could not convert key to PEM format (%s):\n %v", err, errs.String())
	}

	// Return output
	return out.Bytes(), nil
}

// signMessage calls OpenSsl to sign the given message
func signMessage(
	openSslPath string,
	signatureCertPath string, // Path to certificate
	signatureKeyPath string, // Path to key
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
	cmd := exec.Command(openSslPath, "smime", "-sign",
		"-signer", signatureCertPath,
		"-inkey", signatureKeyPath,
	)
	cmd.Stdin = bytes.NewBuffer(message)

	// Create the needed buffers
	var out, errs bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errs

	// Run command
	errRun := cmd.Run()
	if errRun != nil {
		return nil, fmt.Errorf("could not sign message (%s):\n %v", errRun, errs.String())
	}

	// Return output
	return out.Bytes(), nil
}

// encryptMessage calls OpenSsl to SMIME encrypt the given message
func encryptMessage(
	openSslPath string,
	mailFrom string,
	mailTo []string,
	mailSubject string,
	mailMessage []byte,
	encryptionCertPaths []string, // Paths to the encryption certificates of the recipients
) ([]byte, error) {

	// Sanity checks
	if len(openSslPath) == 0 {
		return nil, fmt.Errorf("invalid OpenSSL path")
	}
	if len(mailMessage) == 0 {
		return nil, fmt.Errorf("message is empty")
	}
	if len(mailTo) < 1 {
		return nil, fmt.Errorf("no recipients defined")
	}
	if len(mailTo) != len(encryptionCertPaths) {
		return nil, fmt.Errorf(
			"number of recipients (%d) and number of certificates has to match (%d)",
			len(mailTo), len(encryptionCertPaths),
		)
	}

	// Create the command for encrypting the (signed) message
	args := []string{
		"smime",
		"-encrypt",
		"-from",
		mailFrom,
		"-to",
		strings.Join(mailTo, ", "),
		"-subject",
		mailSubject,
		"-aes256",
	}
	args = append(args, encryptionCertPaths...)
	cmd := exec.Command(openSslPath, args...)
	cmd.Stdin = bytes.NewReader(mailMessage)

	// Create the needed buffers
	var out, errs bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errs

	// Actually run the encryption
	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("could not encrypt message (%s):\n %v", err, errs.String())
	}

	// Return output
	return out.Bytes(), nil
}

// SaveToTemp writes data to a newly created temporary file. The name of the created file is returned.
// You need to remove the file again when you are done! It's not done automatically, and the operating system
// might not do it either for a long time.
func SaveToTemp(data []byte, namePattern string) (string, error) {

	// Create temporary file and write the certificate to it
	tmpFile, errTmp := os.CreateTemp("", namePattern)
	if errTmp != nil {
		return "", fmt.Errorf("could not create file: %s", errTmp)
	}

	// Get the path
	path := tmpFile.Name()

	// Write data to the file
	_, errWrite := tmpFile.Write(data)
	if errWrite != nil {
		_ = tmpFile.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("could not write: %s", errWrite)
	}

	// Clean up the file descriptor - file needs to be removed later on.
	errClose := tmpFile.Close()
	if errClose != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("could not close file descriptor: %s", errClose)
	}

	// Return path of the temporary file
	return path, nil
}
