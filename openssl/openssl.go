/*
* ZapSmtp, a Zap (Golang) logger extension for sending urgent log messages via SMTP
*
* Copyright (c) Siemens AG, 2021-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package openssl

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const defaultCommandTimeout = time.Second * 30

// CertToPem returns the certificate in DER format to PEM format, it fails if the input is in any other encoding.
func CertToPem(pathOpenssl string, cert []byte) ([]byte, error) {

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
		return nil, fmt.Errorf("could not create temporary DER file: %w", errTmp)
	}

	// Cleanup temporary file afterward
	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name()) // ensure cleanup
	}()

	// Write the certificate bytes to the temp file
	_, errWrite := tmpFile.Write(cert)
	if errWrite != nil {
		return nil, fmt.Errorf("could not write temporary DER file: %w", errWrite)
	}

	// Flush content to disk
	errFlush := tmpFile.Sync()
	if errFlush != nil {
		return nil, fmt.Errorf("could not sync temp file: %w", errFlush)
	}

	// Transform the certificate from DER to PEM with a bounded command runtime
	stdOut, stdErr, errRun := runCommand(
		pathOpenssl,
		nil,
		defaultCommandTimeout,
		"x509",
		"-inform", "der",
		"-in", tmpFile.Name(),
		"-outform", "pem",
	)
	if errRun != nil {
		return nil, fmt.Errorf("could not convert certificate to PEM format (%w):\n %v", errRun, string(stdErr))
	}

	// Return output
	return stdOut, nil
}

// KeyToPem returns the key in DER format to PEM format, it fails if the input is in any other encoding.
func KeyToPem(pathOpenssl string, key []byte) ([]byte, error) {

	// Check if key was provided
	if len(key) == 0 {
		return nil, fmt.Errorf("key must not be empty")
	}

	// Create temporary file for the key
	tmpFile, errTmp := os.CreateTemp("", "openssl-key-*.der")
	if errTmp != nil {
		return nil, fmt.Errorf("could not create temporary DER file: %w", errTmp)
	}

	// Cleanup temporary file afterward
	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name()) // ensure cleanup
	}()

	// Write the key bytes to the temp file
	_, errWrite := tmpFile.Write(key)
	if errWrite != nil {
		return nil, fmt.Errorf("could not write temporary DER file: %w", errWrite)
	}

	// Flush content to disk
	errFlush := tmpFile.Sync()
	if errFlush != nil {
		return nil, fmt.Errorf("could not sync temp file: %w", errFlush)
	}

	// Transform the key from DER to PEM with a bounded command runtime
	stdOut, stdErr, errRun := runCommand(
		pathOpenssl,
		nil,
		defaultCommandTimeout,
		"pkey",
		"-inform", "der",
		"-in", tmpFile.Name(),
		"-outform", "pem",
	)
	if errRun != nil {
		return nil, fmt.Errorf("could not convert key to PEM format (%w):\n %v", errRun, string(stdErr))
	}

	// Return output
	return stdOut, nil
}

// PrepareSignatureKeys converts the sender's key pair to PEM if necessary and verifies that they are a
// matching key pair.
func PrepareSignatureKeys(
	pathOpenssl string,
	signatureCert []byte,
	signatureKey []byte,
) ([]byte, []byte, error) {

	// Check whether the certificate is already in PEM format, and try to convert it if not
	if block, _ := pem.Decode(signatureCert); block == nil {
		var errSignatureCert error
		signatureCert, errSignatureCert = CertToPem(pathOpenssl, signatureCert)
		if errSignatureCert != nil {
			return nil, nil, fmt.Errorf("sender certificate: %w", errSignatureCert)
		}
	}

	// Check whether the key is already in PEM format, and try to convert it if not
	if block, _ := pem.Decode(signatureKey); block == nil {
		var errKey error
		signatureKey, errKey = KeyToPem(pathOpenssl, signatureKey)
		if errKey != nil {
			return nil, nil, fmt.Errorf("sender key: %w", errKey)
		}
	}

	// Derive a public key from the private key with a bounded command runtime
	stdOutPriv, stdErrPriv, errRunPriv := runCommand(
		pathOpenssl,
		signatureKey,
		defaultCommandTimeout,
		"pkey",
		"-pubout",
		"-outform",
		"pem",
	)
	if errRunPriv != nil {
		return nil, nil, fmt.Errorf("could not check sender's private key (%w):\n %v", errRunPriv, string(stdErrPriv))
	}

	// Read the public key from the certificate with the same command bound
	stdOutPub, stdErrPub, errRunPub := runCommand(
		pathOpenssl,
		signatureCert,
		defaultCommandTimeout,
		"x509",
		"-pubkey",
		"-noout",
		"-outform",
		"pem",
	)
	if errRunPub != nil {
		return nil, nil, fmt.Errorf("could not check sender's certificate (%w):\n %v", errRunPub, string(stdErrPub))
	}

	// Compare string results - PEM format is base64 encoded and this way no reflection is needed
	if !bytes.Equal(stdOutPriv, stdOutPub) {
		return nil, nil, fmt.Errorf("private key and certificate of sender do not match")
	}

	// Return signing certificate and key
	return signatureCert, signatureKey, nil
}

// PrepareEncryptionKeys converts a list of encryption keys to PEM if necessary. The order of the recipients and
// their certificates does not have to match and no check is performed, that the certificates actually belong to
// later recipients.
func PrepareEncryptionKeys(
	pathOpenssl string,
	encryptionKeys [][]byte,
) ([][]byte, error) {

	// Prepare memory
	keys := make([][]byte, 0, len(encryptionKeys))

	// Go through the recipient certificates, convert them to PEM format if needed and save them to temporary files
	for _, encryptionKey := range encryptionKeys {

		// Check whether the certificate is already in PEM format, and try to convert it if not
		if block, _ := pem.Decode(encryptionKey); block == nil {
			var errEncryptionKey error
			encryptionKey, errEncryptionKey = CertToPem(pathOpenssl, encryptionKey)
			if errEncryptionKey != nil {
				return nil, fmt.Errorf("recipient certificate: %w", errEncryptionKey)
			}
		}
		keys = append(keys, encryptionKey)
	}

	// Set the encryption information on the SmtpContext and return it
	return keys, nil
}

// SignMessage calls OpenSsl to sign the given message
func SignMessage(
	pathOpenssl string,
	pathSignatureCert string, // Path to certificate
	pathSignatureKey string, // Path to key
	message []byte,
) ([]byte, error) {

	// Sanity checks
	if len(pathOpenssl) == 0 {
		return nil, fmt.Errorf("invalid OpenSSL path")
	}
	if len(message) == 0 {
		return nil, fmt.Errorf("message is empty")
	}

	// Sign the message with a bounded command runtime
	stdOut, stdErr, errRun := runCommand(
		pathOpenssl,
		message,
		defaultCommandTimeout,
		"smime",
		"-sign",
		"-signer", pathSignatureCert,
		"-inkey", pathSignatureKey,
	)
	if errRun != nil {
		return nil, fmt.Errorf("could not sign message (%w):\n %v", errRun, string(stdErr))
	}

	// Return output
	return stdOut, nil
}

// EncryptMessage calls OpenSsl to SMIME encrypt the given message
func EncryptMessage(
	pathOpenssl string,
	mailFrom string,
	mailTo []string,
	mailSubject string,
	mailMessage []byte,
	pathEncryptionCerts []string, // Paths to the encryption certificates of the recipients
) ([]byte, error) {

	// Sanity checks
	if len(pathOpenssl) == 0 {
		return nil, fmt.Errorf("invalid OpenSSL path")
	}
	if len(mailMessage) == 0 {
		return nil, fmt.Errorf("message is empty")
	}
	if len(mailTo) < 1 {
		return nil, fmt.Errorf("no recipients defined")
	}
	if len(mailTo) != len(pathEncryptionCerts) {
		return nil, fmt.Errorf(
			"number of recipients (%d) and number of certificates has to match (%d)",
			len(mailTo), len(pathEncryptionCerts),
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
	args = append(args, pathEncryptionCerts...)

	// Encrypt the message with a bounded command runtime
	stdOut, stdErr, errRun := runCommand(pathOpenssl, mailMessage, defaultCommandTimeout, args...)
	if errRun != nil {
		return nil, fmt.Errorf("could not encrypt message (%w):\n %v", errRun, string(stdErr))
	}

	// Return output
	return stdOut, nil
}

// runCommand executes an OpenSSL command with a bounded runtime and isolated output buffers.
func runCommand(
	path string,
	input []byte,
	timeout time.Duration,
	arguments ...string,
) ([]byte, []byte, error) {

	// Bound the process lifetime so a hung executable cannot block logging indefinitely
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	command := exec.CommandContext(ctx, path, arguments...)
	if input != nil {
		command.Stdin = bytes.NewReader(input)
	}

	// Capture both streams for the caller's contextual error message
	var stdOut bytes.Buffer
	var stdErr bytes.Buffer
	command.Stdout = &stdOut
	command.Stderr = &stdErr

	// Prefer the canonical context error when the process exceeded its deadline
	errRun := command.Run()
	if ctx.Err() != nil {
		return stdOut.Bytes(), stdErr.Bytes(), fmt.Errorf("OpenSSL command timed out: %w", ctx.Err())
	}

	// Return the command result and captured streams
	return stdOut.Bytes(), stdErr.Bytes(), errRun
}
