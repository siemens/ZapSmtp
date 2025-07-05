package smtp

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"github.com/siemens/ZapSmtp/openssl"
	"net/mail"
	"net/smtp"
	"os"
	"strings"
)

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
		messageSigned, errSign := openssl.SignMessage(opensslPath, signatureCertPath, signatureKeyPath, msg.Bytes())
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
		messageRaw, errEnc = openssl.EncryptMessage(opensslPath, mailFrom.Address, toAddrs, mailSubject, messageRaw, encryptionCertPaths)
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
		signatureCert, signatureKey, err = openssl.PrepareSignatureKeys(opensslPath, signatureCert, signatureKey)
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
		encryptionKeys, err = openssl.PrepareEncryptionKeys(opensslPath, encryptionKeys)
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
