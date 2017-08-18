/* global describe: false, it: false */
/* eslint-disable no-unused-expressions, no-invalid-this */

'use strict';

var chai = require('chai');
var nodemailerOpenpgp = require('../lib/nodemailer-openpgp');
var stubTransport = require('nodemailer-stub-transport');
var nodemailer = require('nodemailer');
var fs = require('fs');

var expect = chai.expect;
chai.config.includeStack = true;

describe('nodemailer-openpgp tests', function () {
    it('should add encrypt message', function (done) {
        var mail = 'From: andris@node.ee\r\nTo:andris@kreata.ee\r\nSubject:\r\n Hello!\r\nContent-Type: text/plain\r\n\r\nHello world!';

        var signer = new nodemailerOpenpgp.Encrypter({
            signingKey: fs.readFileSync(__dirname + '/fixtures/test_private.pem'),
            passphrase: 'test',
            encryptionKeys: [].concat(fs.readFileSync(__dirname + '/fixtures/test_public.pem') || [])
        });

        var chunks = [];

        signer.on('data', function (chunk) {
            chunks.push(chunk);
        });

        signer.on('end', function () {
            var message = Buffer.concat(chunks).toString('utf-8');
            expect(message).to.exist;
            expect(message.indexOf('This is an OpenPGP/MIME encrypted message')).to.be.gte(0);
            done();
        });

        signer.end(mail);
    });

    it('should use keys provided by mail options', function (done) {
        var transport = nodemailer.createTransport(stubTransport());
        var openpgpEncrypt = nodemailerOpenpgp.openpgpEncrypt;
        transport.use('stream', openpgpEncrypt({
            signingKey: fs.readFileSync(__dirname + '/fixtures/test_private.pem'),
            passphrase: 'test'
        }));

        var mailOptions = {
            from: 'sender@example.com',
            to: 'receiver@example.com',
            subject: 'hello world!',
            text: 'Hello text!',
            html: 'Hello html!',
            encryptionKeys: fs.readFileSync(__dirname + '/fixtures/test_public.pem')
        };

        transport.sendMail(mailOptions, function (err, info) {
            expect(err).to.not.exist;
            expect(info.response).to.exist;
            expect(info.response.toString().indexOf('This is an OpenPGP/MIME encrypted message')).to.be.gte(0);
            done();
        });
    });

    it('should not encrypt if no keys provided', function (done) {
        var transport = nodemailer.createTransport(stubTransport());
        var openpgpEncrypt = nodemailerOpenpgp.openpgpEncrypt;
        transport.use('stream', openpgpEncrypt({
            signingKey: fs.readFileSync(__dirname + '/fixtures/test_private.pem'),
            passphrase: 'test'
        }));

        var mailOptions = {
            from: 'sender@example.com',
            to: 'receiver@example.com',
            subject: 'hello world!',
            text: 'Hello text!',
            html: 'Hello html!'
        };

        transport.sendMail(mailOptions, function (err, info) {
            expect(err).to.not.exist;
            expect(info.response).to.exist;
            expect(info.response.toString().indexOf('This is an OpenPGP/MIME encrypted message')).to.be.lte(0);
            done();
        });
    });
});
