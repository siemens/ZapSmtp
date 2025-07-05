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
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// CertToPem returns the certificate in DER format to PEM format, it fails if the input is in any other encoding.
func CertToPem(openSslPath string, cert []byte) ([]byte, error) {

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

// KeyToPem returns the key in DER format to PEM format, it fails if the input is in any other encoding.
func KeyToPem(openSslPath string, key []byte) ([]byte, error) {

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

// PrepareSignatureKeys converts the sender's key pair to PEM if necessary and verifies that they are a
// matching key pair.
func PrepareSignatureKeys(
	openSslPath string,
	signatureCert []byte,
	signatureKey []byte,
) ([]byte, []byte, error) {

	// Check whether the certificate and key are already in PEM format, and try to convert them if not
	var err error
	if block, _ := pem.Decode(signatureCert); block == nil {
		signatureCert, err = CertToPem(openSslPath, signatureCert)
		if err != nil {
			return nil, nil, fmt.Errorf("sender certificate: %s", err)
		}
	}
	if block, _ := pem.Decode(signatureKey); block == nil {
		signatureKey, err = KeyToPem(openSslPath, signatureKey)
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
			encryptionKey, err = CertToPem(openSslPath, encryptionKey)
			if err != nil {
				return nil, fmt.Errorf("recipient certificate: %s", err)
			}
		}
		keys = append(keys, encryptionKey)
	}

	// Set the encryption information on the SmtpContext and return it
	return keys, nil
}

// SignMessage calls OpenSsl to sign the given message
func SignMessage(
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

// EncryptMessage calls OpenSsl to SMIME encrypt the given message
func EncryptMessage(
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
