# ZapSmtp
Let's be real, who's regularly browsing through megabytes of log files? Wouldn't it be nice, if important messages 
were delivered to you in time, and the log files just served the purpose of holding the details?

This package offers extended functionality for the [zap logger](https://github.com/uber-go/zap), with the purpose 
of handling (some) log messages via SMTP mails (optionally signed and/or encrypted). 

We use this package to notice critical issues fast, so we can roll out a fix, before the user pushes the same buttons 
again. Yes, yes, alternatively, you can expand the turbine stack of your production environment
by deploying, configuring and maintaining additional log management software.

### Installation
As Golang only supports plain text SMTP mails natively, _OpenSSL_ has to be installed if encryption and/or signature is
to be enabled. Other than that a simple `go get` is sufficient.

### Usage
Because sending out a new mail for every single log message is not desirable in most cases, it is recommended to use
some kind of buffered logger core. For this the `DelayedCore` provided in this package can be used.

Don't forget to clean up the Smtp writeSyncer on exit!

```go
func Exmaple() {

    // Prepare SMTP writeSyncer
    smtpWriteSyncer, fnCleanup, errSmtpWriteSyncer := ZapSmtp.NewSmtpSyncer(
        conf.Server,
        conf.Port,
        conf.Subject,
        conf.Sender,              // mail.Address structs for the sender
        conf.Recipients,          // mail.Address structs for each recipient
        conf.OpensslPath,         // Can be omitted, if no e-mail signature nor encryption is desired
        conf.SignatureCertPath,   // Can be omitted, if no e-mail signature is desired
        conf.SignatureKeyPath,    // Can be omitted, if no e-mail signature is desired
        conf.EncryptionCertPaths, // Can be omitted, if no e-mail encryption is desired
    )
    if errSmtpWriteSyncer != nil {
          fmt.Printf("Initializing SMTP writeSyncer failed: %s\n", errSmtpWriteSyncer)
        return
    }

    // Cleanup SMTP writeSyncer (if you are using it with signature or encryption). 
	// OpenSSL can only receive one argument via Stdin, which is the message. Other arguments, such as 
	// signature or encryption keys must be passed as file paths in a PEM format. The SMTP writeSyncer 
	// prepares the necessary files as temporary files in the required format and uses them throughout 
	// its lifetime. You are responsible for cleaning them up on exit, Zap logger cannot not take care 
	// of that automatically!
    defer func() { fnCleanup() }()

    // Define the encoder
    enc := zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig())

    // Prepare SMTP core
    smtpCore, errSmtpCore := ZapSmtp.NewDelayedCore(
        zapcore.WarnLevel,
        enc,
        smtpWriteSyncer,
        zapcore.ErrorLevel,
        time.Minute*1,
        time.Second*5,
    )
    if errSmtpCore != nil {
        fmt.Printf("Initializing SMTP core failed: %s\n", errSmtpCore)
        return
    }
    
    // Initialize Zap logger
    logger := zap.New(smtpCore)

    // Make sure logger is flushed before shutting down. The SMTP writeSyncer does not need to be flushed,
    // but the delayed core might still have unsent messages queued.
    defer func() {
        errSync := logger.Sync()
        if errSync != nil {
            fmt.Printf("Could not sync logger: %s\n", errSync)
        }
    }()
            
    // Log stuff
    logger.Warn("Warn message, triggering email after 1 minute")
    logger.Error("Error message, triggering email after 5 seconds") // Email sent after 5 seconds will include warning
}
```

Another example can be found in `./example/`. 
You can also visit [Large-Scale Discovery](https://github.com/siemens/large-scale-discovery) to see it applied.

### Best practices
- As encrypting and signing mails via _OpenSSL_ is slow it is recommended to not send logs too frequently. This depends
  heavily on your use case though.
- Email signature and encryption needs certificate and key files in PEM format. The `writeSyncer`
  also allows for DER format but will convert them internally. It's advised though to use PEM format if possible.
