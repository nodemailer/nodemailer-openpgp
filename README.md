# OpenPGP module for Nodemailer

This module allows you to send PGP encrypted messages using Nodemailer.
Generated messages are in PGP/MIME format and currently it is only possible to
encrypt or encrypt+sign but not just sign messages.

[![Build Status](https://travis-ci.org/nodemailer/nodemailer-openpgp.svg?branch=master)](https://travis-ci.org/nodemailer/nodemailer-openpgp)

## Install

Install from npm

    npm install nodemailer-openpgp --save

## Usage

Load the `openpgpEncrypt` function

```javascript
var openpgpEncrypt = require('nodemailer-openpgp').openpgpEncrypt;
```

Attach it as a 'stream' handler for a nodemailer transport object

```javascript
transporter.use('stream', openpgpEncrypt(options));
```

Where

  * **options** includes the following optional options for encryptionKeys
    * **signingKey** is an optional PGP private key for signing the encrypted message. If this value is not given then messages are encrypted but not signed
    * **passphrase** is the optional passphrase for the signing key in case it is encrypted

To encrypt outgoing messages add `encryptionKeys` array that holds the public keys used to encrypt the message.

## Example

```javascript
var nodemailer = require('nodemailer');
var transporter = nodemailer.createTransport();
var openpgpEncrypt = require('nodemailer-openpgp').openpgpEncrypt;
transporter.use('stream', openpgpEncrypt());
transporter.sendMail({
    from: 'sender@address',
    to: 'receiver@address',
    subject: 'hello',
    text: 'hello world!',
    encryptionKeys: ['-----BEGIN PGP PUBLIC KEY BLOCK-----…']
}, function(err, response) {
    console.log(err || response);
});
```

## License

**LGPL-3.0**
