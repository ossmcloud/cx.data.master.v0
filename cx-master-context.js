'use strict';

const _path = require('path');
const _core = require('cx-core');
const _cx_data = require('cx-data');
const md5 = require('md5');
const _tfa = require("node-2fa");


const _loginStatus = {
    NOT_VERIFIED: -1,
    VERIFIED: 0,
    ACTIVE: 1,
    LOCKED: 9,
    DELETED: 99,
}

const _loginType = {
    USER: 1,            // all client's users
    CX_SUPPORT: 8,      // gerry
    CX_MASTER: 9        // myself and Laco
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


    // @@TODO: @@CODE-REPETITION: this exact function is also here (same name):
    //                                          cx.v0\cx.sdk.v0\cx.data.master.v0\auth\auth.js
    async generate2Fa(loginId, validityInMinutes) {
        if (!validityInMinutes) { validityInMinutes = 15; }
        var tfa = 0;
        while (tfa < 10000) { tfa = Math.floor(Math.random() * 100000000) + 1; }
        tfa = padLeft(tfa, 8, '0');

        var dt = new Date();
        var dtExp = addMinutes(dt, validityInMinutes);

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

    async manualVerify(loginId) {
        var result = await this.exec({
            sql: 'update accountLogin set status = 0 where loginId = @loginId and status = -1',
            params: [{ name: 'loginId', value: loginId }]
        });

        if (result.rowsAffected == 0) { return 'your account<br />could not be verified:<br /><b>invalid status</b>'; }
    }

    async manualReset(loginId, pass) {
        await this.exec({
            sql: "update accountLogin set status = -1, pass = @pass, tfaKey = null, lastPassChange = '2000-01-01', lastLoginAttempts = 0 where loginId = @loginId",
            params: [
                { name: 'loginId', value: loginId },
                { name: 'pass', value: md5(pass) }
            ]

        });
    }

    async lockLogin(loginId) {
        await this.exec({
            sql: "update accountLogin set status = 9, tfaKey = null where loginId = @loginId",
            params: [
                { name: 'loginId', value: loginId }
            ]
        });
    }

    async getMasterLoginStatusInfo(logins) {
        var loginIds = [];
        for (var lx = 0; lx < logins.length; lx++) {
            loginIds.push(logins[lx].masterLoginId);
        }
        var query = {
            sql: `  select  loginId, status
                    from    accountLogin
                    where   loginId in (${loginIds.join(',')})`,
        }
        var res = await this.exec(query);

        for (var lx = 0; lx < res.rows.length; lx++) {
            var masterStatus = res.rows[lx];
            var login = _core.list.findInArray(logins, 'masterLoginId', masterStatus.loginId);
            if (login) {
                login.status = masterStatus.status;
            }
        }

        return res;
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
        const newSecret = _tfa.generateSecret({ name: 'cloud-cx', account: options.email });

        options.pass = options.email.substr(0, options.email.indexOf('@'));
        var query = {
            sql: `  insert into accountLogin
                        (loginType, email, pass, status, firstName, lastName, lastLoginAttempts, lastAccountId, tfaKey, tfaQr, theme)
                    values 
                            (@loginType, @email, @pass, @status, @firstName, @lastName, @lastLoginAttempts, @lastAccountId, @tfaKey, @tfaQr, 'light')
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
                //{ name: 'tfaQr', value: newSecret.qr.replace('chs=166x166', 'chs=250x250') },
                { name: 'tfaQr', value: `https://quickchart.io/qr?text=${newSecret.secret}` },
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
    LoginType: _loginType,

    get: async function (config) {
        //var db_pool = await _cx_sql.get(config);
        var db_pool = await _cx_data.getPool(config);
        return new CXMasterContext(db_pool);
    },

    getPools: _cx_data.getPools,
    countPools: _cx_data.countPools,


}