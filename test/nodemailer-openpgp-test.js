/* eslint-disable no-unused-expressions, no-invalid-this */

'use strict';

let chai = require('chai');
let nodemailerOpenpgp = require('../lib/nodemailer-openpgp');
let stubTransport = require('nodemailer-stub-transport');
let nodemailer = require('nodemailer');
let fs = require('fs');

let expect = chai.expect;
chai.config.includeStack = true;

describe('nodemailer-openpgp tests', () => {
    it('should add an encrypt message', done => {
        let mail = 'From: andris@node.ee\r\nTo:andris@kreata.ee\r\nSubject:\r\n Hello!\r\nContent-Type: text/plain\r\n\r\nHello world!';

        let signer = new nodemailerOpenpgp.Encrypter({
            signingKey: fs.readFileSync(__dirname + '/fixtures/test_private.key'),
            passphrase: 'hello world',
            encryptionKeys: [].concat(fs.readFileSync(__dirname + '/fixtures/test_public.pem') || [])
        });

        let chunks = [];

        signer.on('data', chunk => {
            chunks.push(chunk);
        });

        signer.on('end', () => {
            let message = Buffer.concat(chunks).toString('utf-8');
            expect(message).to.exist;
            expect(message.indexOf('This is an OpenPGP/MIME encrypted message')).to.be.gte(0);
            done();
        });

        signer.end(mail);
    });

    it('should use keys provided by mail options', done => {
        let transport = nodemailer.createTransport(stubTransport());
        let openpgpEncrypt = nodemailerOpenpgp.openpgpEncrypt;
        transport.use(
            'stream',
            openpgpEncrypt({
                signingKey: fs.readFileSync(__dirname + '/fixtures/test_private.key'),
                passphrase: 'hello world'
            })
        );

        let mailOptions = {
            from: 'sender@example.com',
            to: 'receiver@example.com',
            subject: 'hello world!',
            text: 'Hello text!',
            html: 'Hello html!',
            encryptionKeys: [].concat(fs.readFileSync(__dirname + '/fixtures/test_public.pem') || [])
        };

        transport.sendMail(mailOptions, (err, info) => {
            expect(err).to.not.exist;
            expect(info.response).to.exist;
            expect(info.response.toString().indexOf('This is an OpenPGP/MIME encrypted message')).to.be.gte(0);
            done();
        });
    });

    it('should not encrypt if no keys provided', done => {
        let transport = nodemailer.createTransport(stubTransport());
        let openpgpEncrypt = nodemailerOpenpgp.openpgpEncrypt;
        transport.use(
            'stream',
            openpgpEncrypt({
                signingKey: fs.readFileSync(__dirname + '/fixtures/test_private.pem'),
                passphrase: 'test'
            })
        );

        let mailOptions = {
            from: 'sender@example.com',
            to: 'receiver@example.com',
            subject: 'hello world!',
            text: 'Hello text!',
            html: 'Hello html!'
        };

        transport.sendMail(mailOptions, (err, info) => {
            expect(err).to.not.exist;
            expect(info.response).to.exist;
            expect(info.response.toString().indexOf('This is an OpenPGP/MIME encrypted message')).to.be.lte(0);
            done();
        });
    });
});
