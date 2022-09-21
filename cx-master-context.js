'use strict';

const _path = require('path');
const _cx_data = require('cx-data');
const md5 = require('md5');
const _tfa = require("node-2fa");
const { toUSVString } = require('util');

const _loginStatus = {
    NOT_VERIFIED: -1,
    VERIFIED: 0,
    ACTIVE: 1,
    LOCKED: 9,
    DELETED: 99,
}


function addMinutes(d, m) {
    var value = d.getTime() + (m * 60000);
    return new Date(value);
}
function padLeft(str, size, char) {
    if (char == undefined) { char = " "; }
    var s = String(str);
    while (s.length < (size || 2)) { s = char + s; }
    return s.substring(0, size);
}

class CXMasterContext extends _cx_data.DBContext {
    constructor(pool) {
        super(pool, _path.join(__dirname, 'business'));
    }

    // createTfaKey() {
    //     const newSecret = _tfa.generateSecret({ name: 'cloud-cx' });
    //     return newSecret;
    // }

    
    async generate2Fa(loginId) {
        var tfa = 0;
        while (tfa < 10000) { tfa = Math.floor(Math.random() * 100000000) + 1; }
        tfa = padLeft(tfa, 8, '0');

        var dt = new Date();
        var dtExp = addMinutes(dt, 15);

        await this.exec({
            sql: 'insert into accountLoginAuditTFA (loginId, twoFactorAuthCode, dateCreated, dateExpiry) values (@loginId, @twoFactorAuthCode, @dateCreated, @dateExpiry)',
            params: [
                { name: 'loginId', value: loginId },
                { name: 'twoFactorAuthCode', value: tfa },
                { name: 'dateCreated', value: dt },
                { name: 'dateExpiry', value: dtExp },
            ]
        });

        return tfa;
    }

    async getMasterLoginInfo(loginId) {
        var query = {
            sql: `  select  loginId, status, tfaKey, tfaQr
                    from    accountLogin
                    where   loginId = @loginId`,
            params: [{ name: 'loginId', value: loginId }],
            noResult: 'null',
            returnFirst: true,
        }
        var res = await this.exec(query);
        return res;
    }

    async getMasterLogin(options) {
        var login = await this.fetchMasterLogin(options.email);
        if (!login) {
            login = await this.addMasterLogin(options);
        }
        await this.addLoginAccount(options.accountId, login.loginId || login);
        return {
            id: login.loginId || login,
            isNew: login.isNew || false,
        };
    }

    async fetchMasterLogin(email, returnObject) {
        var query = {
            sql: `  select  loginId
                    from    accountLogin
                    where   email = @email`,
            params: [{ name: 'email', value: email }],
            noResult: 'null',
            returnFirst: true,
        }
        var res = await this.exec(query);
        if (returnObject) { return res; }
        if (res != null) { return res.loginId; }
    }

    async addMasterLogin(options) {
        const newSecret = _tfa.generateSecret({ name: 'cloud-cx' });

        options.pass = options.email.substr(0, options.email.indexOf('@'));
        var query = {
            sql: `  insert into accountLogin
                        (loginType, email, pass, status, firstName, lastName, lastLoginAttempts, lastAccountId, tfaKey, tfaQr)
                    values 
                            (@loginType, @email, @pass, @status, @firstName, @lastName, @lastLoginAttempts, @lastAccountId, @tfaKey, @tfaQr)
                    select * from accountLogin where loginId = SCOPE_IDENTITY()`,
            params: [
                { name: 'loginType', value: 1 },
                { name: 'email', value: options.email },
                { name: 'pass', value: md5(options.pass) },
                { name: 'status', value: _loginStatus.NOT_VERIFIED },
                { name: 'firstName', value: options.firstName },
                { name: 'lastName', value: options.lastName },
                { name: 'lastLoginAttempts', value: 0 },
                { name: 'lastAccountId', value: options.accountId },
                { name: 'tfaKey', value: newSecret.secret },
                { name: 'tfaQr', value: newSecret.qr },
            ],
            noResult: 'null',
            returnFirst: true,
        }
        var res = await this.exec(query);
        if (res) {
            res.isNew = true;
        }
        return res; 
    }

    async addLoginAccount(accountId, loginId) {
        var query = {
            sql: `  select  *
                    from    accountLogins
                    where   accountId = @accountId
                    and     accountLoginId = @loginId`,
            params: [
                { name: 'accountId', value: accountId },
                { name: 'loginId', value: loginId }
            ],
            noResult: 'null',
            returnFirst: true,
        }
        var res = await this.exec(query);
        if (res == null) {
            query.sql = 'insert into accountLogins (accountId, accountLoginId) values (@accountId, @loginId)'
            await this.exec(query);
        }
    }

}




module.exports = {
    //Schema: _cx_client_schema,

    get: async function (config) {
        //var db_pool = await _cx_sql.get(config);
        var db_pool = await _cx_data.getPool(config);
        return new CXMasterContext(db_pool);
    },

    getPools: _cx_data.getPools,
    countPools: _cx_data.countPools,


}