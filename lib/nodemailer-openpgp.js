'use strict';

const openpgp = require('openpgp');
const Transform = require('stream').Transform;
const crypto = require('crypto');

/**
 * Creates a Transform stream for signing messages
 *
 * @constructor
 * @param {Object} options DKIM options
 */
class Encrypter extends Transform {
    constructor(options) {
        super(options);
        this.options = options || {};

        this._messageChunks = [];
        this._messageLength = 0;
    }

    /**
     * Caches all input
     */
    _transform(chunk, encoding, done) {
        if (encoding !== 'buffer') {
            chunk = Buffer.from(chunk, encoding);
        }
        this._message += chunk;
        this._messageChunks.push(chunk);
        this._messageLength += chunk.length;
        done();
    }

    /**
     * Signs and emits the entire cached input at once
     */
    _flush(done) {
        (async () => {
            try {
                let message = Buffer.concat(this._messageChunks, this._messageLength);

                let privKey = false;
                let pubKeys = await Promise.all((this.options.encryptionKeys || []).map(armoredKey => openpgp.readKey({ armoredKey: armoredKey.toString() })));
                const shouldSign = this.options.shouldSign === false ? false : true;

                if (shouldSign && this.options.signingKey) {
                    privKey = await openpgp.readPrivateKey({ armoredKey: this.options.signingKey.toString() });

                    if (this.options.passphrase) {
                        privKey = await openpgp.decryptKey({
                            privateKey: privKey,
                            passphrase: this.options.passphrase
                        });
                    }
                }

                if (!pubKeys.length && (!shouldSign || !privKey)) {
                    // dont sign or encrypt
                    this.push(message);
                    return done();
                }

                let messageParts = message.toString().split('\r\n\r\n');
                let header = messageParts.shift();
                let headers = [];
                let bodyHeaders = [];
                let lastHeader = false;
                let boundary = 'nm_' + crypto.randomBytes(14).toString('hex');
                header.split('\r\n').forEach((line, i) => {
                    if (!i || !lastHeader || !/^\s/.test(line)) {
                        lastHeader = [line];
                        if (/^(content-type|content-transfer-encoding):/i.test(line)) {
                            bodyHeaders.push(lastHeader);
                        } else {
                            headers.push(lastHeader);
                        }
                    } else {
                        lastHeader.push(line);
                    }
                });

                if (!pubKeys.length) {
                    // sign only
                    headers.push(
                        ['Content-Type: multipart/signed; protocol="application/pgp-signature"; micalg=pgp-sha512;'],
                        [' boundary="' + boundary + '"']
                    );
                    headers.push(['Content-Description: OpenPGP signed message']);

                    headers = headers.map(line => line.join('\r\n')).join('\r\n');
                    bodyHeaders = bodyHeaders.map(line => line.join('\r\n')).join('\r\n');

                    let body = messageParts.join('\r\n\r\n');
                    const data = `${bodyHeaders}\r\n\r\n${body}`;

                    const signature = await openpgp.sign({
                        message: await openpgp.createMessage({ text: data }),
                        signingKeys: privKey,
                        detached: true
                    });
                    const mailBody =
                        '--' +
                        boundary +
                        '\r\n' +
                        data +
                        '\r\n' +
                        '--' +
                        boundary +
                        '\r\n' +
                        'Content-Type: application/pgp-signature\r\n' +
                        'Content-Disposition: inline; filename=signature.asc\r\n' +
                        '\r\n' +
                        signature +
                        '\r\n--' +
                        boundary +
                        '--\r\n';

                    this.push(Buffer.from(`${headers}\r\n\r\n${mailBody}`));
                    return done();
                } else {
                    // encrypt (and sign)
                    headers.push(['Content-Type: multipart/encrypted; protocol="application/pgp-encrypted";'], [' boundary="' + boundary + '"']);

                    headers.push(['Content-Description: OpenPGP encrypted message']);
                    headers.push(['Content-Transfer-Encoding: 7bit']);

                    headers = headers.map(line => line.join('\r\n')).join('\r\n');
                    bodyHeaders = bodyHeaders.map(line => line.join('\r\n')).join('\r\n');

                    let body = messageParts.join('\r\n\r\n');
                    const data = `${bodyHeaders}\r\n\r\n${body}`;

                    let options = {
                        message: await openpgp.createMessage({ text: data }),
                        encryptionKeys: pubKeys
                    };

                    if (shouldSign && privKey) {
                        options.signingKeys = privKey;
                    }

                    const encrypted = await openpgp.encrypt(options);
                    const mailBody =
                        'This is an OpenPGP/MIME encrypted message\r\n\r\n' +
                        '--' +
                        boundary +
                        '\r\n' +
                        'Content-Type: application/pgp-encrypted\r\n' +
                        'Content-Transfer-Encoding: 7bit\r\n' +
                        '\r\n' +
                        'Version: 1\r\n' +
                        '\r\n' +
                        '--' +
                        boundary +
                        '\r\n' +
                        'Content-Type: application/octet-stream; name=encrypted.asc\r\n' +
                        'Content-Disposition: inline; filename=encrypted.asc\r\n' +
                        'Content-Transfer-Encoding: 7bit\r\n' +
                        '\r\n' +
                        encrypted +
                        '\r\n--' +
                        boundary +
                        '--\r\n';

                    this.push(Buffer.from(`${headers}\r\n\r\n${mailBody}`));
                    return done();
                }
            } catch (err) {
                return done(err);
            }
        })();
    }
}

/**
 * Nodemailer plugin for the 'stream' event. Caches the entire message to memory,
 * signes it and passes on
 *
 * @param {Object} [options] Optional options object
 * @returns {Function} handler for 'stream'
 */
module.exports.openpgpEncrypt = function (options) {
    return function (mail, callback) {
        if (
            (!(options && options.signingKey) || mail.data.shouldSign === false) &&
            (!mail.data.encryptionKeys || (Array.isArray(mail.data.encryptionKeys) && !mail.data.encryptionKeys.length))
        ) {
            return setImmediate(callback);
        }
        mail.message.transform(
            () =>
                new Encrypter({
                    signingKey: options && options.signingKey,
                    passphrase: options && options.passphrase,
                    encryptionKeys: mail.data.encryptionKeys,
                    shouldSign: mail.data.shouldSign
                })
        );
        setImmediate(callback);
    };
};

// Expose for testing only
module.exports.Encrypter = Encrypter;
