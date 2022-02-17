'use strict'
var nodemailer = require('nodemailer');

function _sendEmail(options) {
    if (!options) {
        throw new Error("Options can not be null");
    } else if (!options.auth) {
        throw new Error("Options.auth{user,pass} can not be null");
    } else if (!options.auth.user || !options.auth.pass) {
        throw new Error("Options.auth.user or Options.auth.password can not be null");
    }

    var transporter = nodemailer.createTransport({
        host: options.host || 'smtp.reg365.net', // Office 365 server
        port: options.port || 587,     // secure SMTP
        secure: options.secure || false, // false for TLS - as a boolean not string - but the default is false so just remove this completely
        auth: options.auth,
        tls: options.tls || { ciphers: 'SSLv3' }
    });

    transporter.sendMail({
        from: options.from,
        replyTo: options.replyTo,
        to: options.to,
        subject: options.subject,
        cc: options.cc,
        bcc: options.bcc,
        text: options.text,
        html: options.html,
        attachments: options.attachments,
    }, function (err, info) {
        if (err && options.onError) {
            console.log('Email Sending Error', err);
            options.onError(err);
        }
        else if (options.onSuccess) {
            options.onSuccess(info);
        }
    });
}


function EMailer(options) {
    if (!options) { options = {}; }
    this.user = options.user || process.env.EMAIL_FROM;
    this.pass = options.pass || process.env.EMAIL_FROM_P;

    this.send = async function (options) {
        console.log('sending 2FA email...');
        _sendEmail({
            auth: { user: this.user, pass: this.pass },
            from: this.user,
            to: options.to,
            subject: options.subject,
            html: options.body,
            onError: function (e) {
                console.log(e);
            },
            onSuccess: function (i) {
                console.log(i);
            }
        });
    }
}


module.exports = {
    get: function (options) {
        return new EMailer(options);
    }
}
