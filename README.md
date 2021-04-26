# ZapSmtp
Let's be real, who's regularly browsing through megabytes of log files? Wouldn't it be nice, if important messages 
were delivered to you in time, and the log files just served the purpose of holding the details?

This package offers extended functionality for the [zap logger](https://github.com/uber-go/zap), with the purpose 
of handling (some) log messages via (optionally signed and/or encrypted) SMTP mails. 

We use this package to notice critical issues fast, so we can roll out a fix, before the user pushes the same buttons 
again. Yes, yes, alternatively, you can expand the turbine stack of your production environment
by deploying, configuring and maintaining additional log management software.

### Installation
As Golang only supports plain text SMTP mails natively, _OpenSSL_ has to be installed if encryption and/or signature is
to be enabled. Other than that a simple `go get` is sufficient.

### Usage
Because sending out a new mail for every single log message is not desirable in most cases, it is recommended to use
some kind of buffered Core. For this the `delayedCore` provided in this package can be used.

```go
func Exmaple() {

    // Prepare SMTP sink
    sink, errSink := smtp.NewWriteSyncCloser(
        conf.Server,
        conf.Port,
        conf.Subject,
        conf.Sender,              // mail.Address structs for the sender
        conf.Recipients,          // mail.Address structs for each recipient
        conf.OpensslPath,         // Can be omitted, if no e-mail signature nor encryption is desired
        conf.SignatureCertPath,   // Can be omitted, if no e-mail signature is desired
        conf.SignatureKeyPath,    // Can be omitted, if no e-mail signature is desired
        conf.EncryptionCertPaths, // Can be omitted, if no e-mail encryption is desired
        conf.TempDir,             // If empty, the system's temporary directory will be used if needed
    )
    if errSink != nil {
        fmt.Printf("Initializing SMTP sink failed: %s\n", errSink)
        return
    }
    
    // Make sure logger is closed properly
    defer func() {
        if errClose := sink.Close(); errClose != nil {
            fmt.Printf("Closing SMTP sink failed: %s\n", errClose)
        }
    }()
    
    // Define the encoder
    enc := zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig())
    
    // Initialize SMTP core
    core, errCore := cores.NewDelayedCore(zapcore.WarnLevel, enc, sink, zapcore.ErrorLevel, time.Minute*1, time.Second*5)
    if errCore != nil {
        fmt.Printf("Initializing SMTP core failed: %s\n", errCore)
        return
    }
    
    // Initialize Zap logger
    logger := zap.New(core)
    
    // Make sure logger is flushed before shutting down
    defer func() { _ = logger.Sync() }()
    
    // Log stuff
    logger.Warn("Warn message, triggering email after 1 minute")
    logger.Error("Error message, triggering email after 5 seconds") // Email sent after 5 seconds will include warning
}
```

Note that even though the `writeSyncCloser` satisfies zap's `Sink` interface it is not recommended using it with
`RegisterSink` as this way only standard `ioCores` can be used.

Another example can be found in `./examples`. 
You can also visit [Large-Scale Discovery](https://github.com/siemens/large-scale-discovery) to see it applied.

### Best practices
- When possible the `writeSyncCloser` should be preferred over the `writeSyncer`, as it will convert files only once and
  keep a reference to the resulting files until `Close` is called.
- As encrypting and signing mails via _OpenSSL_ is slow it is recommended to not log too frequently. This depends
  heavily on your use case though.
- Email signature and encryption needs certificate and key files in PEM format. The `writeSyncer` (and `writeSyncCloser`)
  also allows for DER format and will convert them internally. It's advised though to use PEM format if possible.
