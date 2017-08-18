'use strict';

const openpgp = require('openpgp');
const Transform = require('stream').Transform;
const util = require('util');
const crypto = require('crypto');

/**
 * Nodemailer plugin for the 'stream' event. Caches the entire message to memory,
 * signes it and passes on
 *
 * @param {Object} [options] Optional options object
 * @returns {Function} handler for 'stream'
 */
module.exports.openpgpEncrypt = function(options) {
    return function(mail, callback) {
        if (!mail.data.encryptionKeys || (Array.isArray(mail.data.encryptionKeys) && !mail.data.encryptionKeys.length)) {
            return setImmediate(callback);
        }
        mail.message.transform(
            () =>
                new Encrypter({
                    signingKey: options && options.signingKey,
                    passphrase: options && options.passphrase,
                    encryptionKeys: mail.data.encryptionKeys
                })
        );
        setImmediate(callback);
    };
};

// Expose for testing only
module.exports.Encrypter = Encrypter;

/**
 * Creates a Transform stream for signing messages
 *
 * @constructor
 * @param {Object} options DKIM options
 */
function Encrypter(options) {
    this.options = options || {};
    Transform.call(this, this.options);

    this._messageChunks = [];
    this._messageLength = 0;
}
util.inherits(Encrypter, Transform);

/**
 * Caches all input
 */
Encrypter.prototype._transform = function(chunk, encoding, done) {
    if (encoding !== 'buffer') {
        chunk = new Buffer(chunk, encoding);
    }
    this._message += chunk;
    this._messageChunks.push(chunk);
    this._messageLength += chunk.length;
    done();
};

/**
 * Signs and emits the entire cached input at once
 */
Encrypter.prototype._flush = function(done) {
    //var signature = dkimSign(this._message, this.options);
    let message = Buffer.concat(this._messageChunks, this._messageLength);

    let privKey;
    let pubKeys = [];
    [].concat(this.options.encryptionKeys || []).forEach(pubKey => {
        let keys;
        try {
            keys = openpgp.key.readArmored(pubKey.toString()).keys;
            pubKeys = pubKeys.concat(keys);
        } catch (E) {
            // just ignore if failed
        }
    });

    if (!pubKeys.length) {
        this.push(message);
        return done();
    }

    if (this.options.signingKey) {
        try {
            privKey = openpgp.key.readArmored(this.options.signingKey.toString()).keys[0];
            if (this.options.passphrase && !privKey.decrypt(this.options.passphrase)) {
                privKey = false;
            }
        } catch (E) {
            // just ignore if failed
        }
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
    headers.push(['Content-Type: multipart/encrypted; protocol="application/pgp-encrypted";'], [' boundary="' + boundary + '"']);

    headers.push(['Content-Description: OpenPGP encrypted message']);
    headers.push(['Content-Transfer-Encoding: 7bit']);

    headers = headers.map(line => line.join('\r\n')).join('\r\n');
    bodyHeaders = bodyHeaders.map(line => line.join('\r\n')).join('\r\n');

    let body = messageParts.join('\r\n\r\n');

    let options = {
        data: bodyHeaders + '\r\n\r\n' + body,
        publicKeys: pubKeys,
        armor: true
    };

    if (privKey) {
        options.privateKeys = privKey;
    }

    openpgp
        .encrypt(options)
        .then(ciphertext => {
            let encrypted = ciphertext.data;

            let body =
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

            this.push(new Buffer(headers + '\r\n\r\n' + body));
            done();
        })
        .catch(done);
};
