'use strict';

var openpgp = require('openpgp');
var Transform = require('stream').Transform;
var util = require('util');
var crypto = require('crypto');

/**
 * Nodemailer plugin for the 'stream' event. Caches the entire message to memory,
 * signes it and passes on
 *
 * @param {Object} [options] Optional options object
 * @returns {Function} handler for 'stream'
 */
module.exports.openpgpEncrypt = function (options) {
    return function (mail, callback) {
        if (!mail.data.encryptionKeys || (Array.isArray(mail.data.encryptionKeys) && !mail.data.encryptionKeys.length)) {
            return setImmediate(callback);
        }
        mail.message.transform(function () {
            return new Encrypter({
                signingKey: options && options.signingKey,
                encryptionKeys: mail.data.encryptionKeys
            });
        });
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
Encrypter.prototype._transform = function (chunk, encoding, done) {
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
Encrypter.prototype._flush = function (done) {
    //var signature = dkimSign(this._message, this.options);
    var message = Buffer.concat(this._messageChunks, this._messageLength);

    var privKey;
    var pubKeys = [];
    [].concat(this.options.encryptionKeys || []).forEach(function (pubKey) {
        var keys;
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

    var messageParts = message.toString().split('\r\n\r\n');
    var header = messageParts.shift();
    var headers = [];
    var bodyHeaders = [];
    var lastHeader = false;
    var boundary = 'nm_' + crypto.randomBytes(14).toString('hex');
    header.split('\r\n').forEach(function (line, i) {
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
    headers.push(
        [
            'Content-Type: multipart/encrypted; protocol="application/pgp-encrypted";'
        ], [
            ' boundary="' + boundary + '"'
        ]
    );

    headers.push(['Content-Description: OpenPGP encrypted message']);
    headers.push(['Content-Transfer-Encoding: 7bit']);

    headers = headers.map(function (line) {
        return line.join('\r\n');
    }).join('\r\n');
    bodyHeaders = bodyHeaders.map(function (line) {
        return line.join('\r\n');
    }).join('\r\n');

    var body = messageParts.join('\r\n\r\n');

    var options = {
        data: bodyHeaders + '\r\n\r\n' + body,
        publicKeys: pubKeys,
        armor: true
    };

    if (privKey && privKey.length) {
        options.privateKeys = privKey;
    }

    openpgp.encrypt(options).then(function (ciphertext) {
        var encrypted = ciphertext.data;

        var body = 'This is an OpenPGP/MIME encrypted message\r\n\r\n' +
            '--' + boundary + '\r\n' +
            'Content-Type: application/pgp-encrypted\r\n' +
            'Content-Transfer-Encoding: 7bit\r\n' +
            '\r\n' +
            'Version: 1\r\n' +
            '\r\n' +
            '--' + boundary + '\r\n' +
            'Content-Type: application/octet-stream; name=encrypted.asc\r\n' +
            'Content-Disposition: inline; filename=encrypted.asc\r\n' +
            'Content-Transfer-Encoding: 7bit\r\n' +
            '\r\n' +
            encrypted + '\r\n--' + boundary + '--\r\n';

        this.push(new Buffer(headers + '\r\n\r\n' + body));
        done();
    }.bind(this)).catch(done);
};
