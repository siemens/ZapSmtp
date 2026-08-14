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
to be enabled. Other than that a simple `go get` is sufficient. ZapSmtp requires Go 1.23 or newer. This lets the delayed
logger rely on the safer synchronous timer channel semantics introduced with Go 1.23. Forcing legacy asynchronous timer
channels through `GODEBUG=asynctimerchan=1`, `GODEBUG=asynctimerchan=2`, or an equivalent `godebug` default is unsupported.

### Usage
Because sending out a new mail for every single log message is not desirable in most cases, it is recommended to use
some kind of buffered logger core. For this the `DelayedCore` provided in this package can be used.

Temporary attachment and certificate files are created only for an individual send and removed automatically.

```go
func Example() {

    // Prepare SMTP writeSyncer
    smtpWriteSyncer, errSmtpWriteSyncer := ZapSmtp.NewSmtpSyncer(
        conf.Server,
        conf.Port,
        conf.Username,            // Leave username and password empty to skip authentication
        conf.Password,

        conf.Subject,
        conf.Sender,              // mail.Address structs for the sender
        conf.Recipients,          // mail.Address structs for each recipient
        true,                     // Also attach the collected logs as a text file

        conf.OpensslPath,         // Can be omitted, if no e-mail signature nor encryption is desired
        conf.SignatureCertPath,   // Can be omitted, if no e-mail signature is desired
        conf.SignatureKeyPath,    // Can be omitted, if no e-mail signature is desired
        conf.EncryptionCertPaths, // Can be omitted, if no e-mail encryption is desired
    )
    if errSmtpWriteSyncer != nil {
        fmt.Printf("Initializing SMTP writeSyncer failed: %s\n", errSmtpWriteSyncer)
        return
    }

    // Define the encoder
    encoder := zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig())

    // Prepare SMTP core
    smtpCore, errSmtpCore := ZapSmtp.NewDelayedCore(
        zapcore.WarnLevel,
        encoder,
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
- SMTP transactions and OpenSSL commands are limited to 30 seconds so stalled external services cannot block logging
  indefinitely.
- `DelayedCore` retains at most 5,000 log entries. When delivery remains unavailable, additional entries are dropped
  and the condition is reported locally on stderr with rate limiting.
- Email signature and encryption needs certificate and key files in PEM format. The `writeSyncer`
  also allows for DER format but will convert them internally. It's advised though to use PEM format if possible.
