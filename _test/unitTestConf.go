/*
* ZapSmtp, a Zap (Golang) logger extension for sending urgent log messages via SMTP
*
* Copyright (c) Siemens AG, 2021.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package _test

import (
	"net/mail"
	"path/filepath"
)

var (
	// Need to configure these before testing!
	SmtpServer          = "mail.domain.tld"
	SmtpPort     uint16 = 25
	SmtpUser            = "" // Leave empty to skip authentication
	SmtpPassword        = "" // Leave empty to skip authentication
	OpensslPath         = ""

	// Can optionally be set
	MailSubject = "SmtpSyncer Test Mail"
	MailFrom    = mail.Address{Name: "Test Sender", Address: "sender@domain.tld"}
	MailTo      = mail.Address{Name: "Test Recipient", Address: "recipient@domain.tld"}

	TestDirPath = "_test" // relative path starting at application root
	Cert1Path   = filepath.Join("..", TestDirPath, "cert1.pem")
	Key1Path    = filepath.Join("..", TestDirPath, "key1.pem")
	Cert2Path   = filepath.Join("..", TestDirPath, "cert2.pem")
	Key2Path    = filepath.Join("..", TestDirPath, "key2.pem")

	RealRecipient = mail.Address{Name: "", Address: ""}
	RealCertPath  = ""
)
