package smtp

import (
	"fmt"
	"net/mail"
	"os"
)

// SendMail is a small helper function that can be used to send an email with a single function call.
func SendMail(
	smtpServer string,
	smtpPort uint16,
	smtpUsername string, // Optional credentials, can be left empty to skip authentication
	smtpPassword string, // Optional credentials, can be left empty to skip authentication
	mailFrom mail.Address,
	mailTo []mail.Address,
	mailToCerts [][]byte, // Optional encryption certificates, can be nil
	mailSubject string,
	mailBody []byte,
	pathMailAttachments []string, // Optional file attachments, can be nil
	pathOpenssl string, // Optional path to OpenSSL, only required for signatures and encryption
	signatureCert []byte, // Optional signature key, can be nil
	signatureKey []byte, // Optional signature key, can be nil
	html bool, // Whether to send the mail message as HTML content type or plaintext
) error {

	// Prepare Mailer
	mlr := NewMailer(smtpServer, smtpPort)

	// Make sure mailer is cleaned up
	defer mlr.Close()

	// Set authentication
	mlr.SetAuth(smtpUsername, smtpPassword)

	// Set OpenSSL path for optional signature or encryption
	errOpenssl := mlr.SetOpenssl(pathOpenssl)
	if errOpenssl != nil {
		return errOpenssl
	}

	// Enable signature if desired
	if len(signatureCert) != 0 && len(signatureKey) != 0 {
		errSignature := mlr.SetSignature(signatureCert, signatureKey)
		if errSignature != nil {
			return errSignature
		}
	}

	// Prepare message
	msg, msgErr := NewMessage(mailFrom, mailTo, mailSubject, mailBody)
	if msgErr != nil {
		return msgErr
	}

	// Enable HTML if desired
	if html {
		msg.EnableHtml()
	}

	// Add attachments
	errAttach := msg.Attach(pathMailAttachments...) // List of file paths to attach
	if errAttach != nil {
		return errAttach
	}

	// Enable signing if desired
	if len(signatureCert) != 0 && len(signatureKey) != 0 {
		msg.SetSigning()
	}

	// Enable encryption if desired
	if len(mailToCerts) > 0 {
		errEncrypt := msg.SetEncryption(mailToCerts)
		if errEncrypt != nil {
			return errEncrypt
		}
	}

	// Send message
	errMail := mlr.Send(msg)
	if errMail != nil {
		return errMail
	}

	// Return nil as everything went fine
	return nil
}

// SaveToTemp writes data to a newly created temporary file. The name of the created file is returned.
// You need to remove the file again when you are done! It's not done automatically, and the operating system
// might not do it either for a long time.
func SaveToTemp(data []byte, namePattern string) (string, error) {

	// Create temporary file and write the certificate to it
	tmpFile, errTmp := os.CreateTemp("", namePattern)
	if errTmp != nil {
		return "", fmt.Errorf("could not create temporary file: %s", errTmp)
	}

	// Get the path
	tmpPath := tmpFile.Name()

	// Write data to the file
	_, errWrite := tmpFile.Write(data)
	if errWrite != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("could not write temporary file: %s", errWrite)
	}

	// Clean up the file descriptor - file needs to be removed later on.
	errClose := tmpFile.Close()
	if errClose != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("could not close temporary file: %s", errClose)
	}

	// Return path of the temporary file
	return tmpPath, nil
}
