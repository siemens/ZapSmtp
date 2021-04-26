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
	Server             = "mail.domain.tld"
	Port        uint16 = 25
	OpensslPath        = ""

	// Can optionally be set
	Subject   = "smtpWriter test mail"
	Sender    = mail.Address{Name: "Test Sender", Address: "sender@domain.tld"}
	Recipient = mail.Address{Name: "Test Recipient", Address: "recipient@domain.tld"}
	TestDir   = "_test" // relative path starting at application root
	Cert1     = filepath.Join("..", TestDir, "cert1.pem")
	Key1      = filepath.Join("..", TestDir, "key1.pem")
	Cert2     = filepath.Join("..", TestDir, "cert2.pem")
	Key2      = filepath.Join("..", TestDir, "key2.pem")

	RealRecipient = mail.Address{Name: "", Address: ""}
	RealCert      = ""
)
