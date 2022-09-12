'use strict';

const _path = require('path');
const _cx_data = require('cx-data');
const md5 = require('md5');
//const _cx_auth = require('./auth/cx-master-auth');

class CXMasterContext extends _cx_data.DBContext {
    constructor(pool) {
        super(pool, _path.join(__dirname, 'business'));
    }


    async getMasterLogin(options) {
        var loginId = await this.fetchMasterLogin(options.email);
        if (!loginId) {
            loginId = await this.addMasterLogin(options);
        }
        await this.addLoginAccount(options.accountId, loginId);
        return loginId;
    }

    async fetchMasterLogin(email) {
        var query = {
            sql: `  select  loginId
                    from    accountLogin
                    where   email = @email`,
            params: [{ name: 'email', value: email }],
            noResult: 'null',
            returnFirst: true,
        }
        var res = await this.exec(query);
        if (res != null) { return res.loginId; }
    }

    async addMasterLogin(options) {
        options.pass = options.email.substr(0, options.email.indexOf('@'));
        var query = {
            sql: `  insert into accountLogin
                        (loginType, email, pass, status, firstName, lastName, lastLoginAttempts, lastAccountId)
                    values 
                            (@loginType, @email, @pass, @status, @firstName, @lastName, @lastLoginAttempts, @lastAccountId)
                    select SCOPE_IDENTITY() as [id] `,
            params: [
                { name: 'loginType', value: 1 },
                { name: 'email', value: options.email },
                { name: 'pass', value: md5(options.pass) },
                { name: 'status', value: 1 },
                { name: 'firstName', value: options.firstName },
                { name: 'lastName', value: options.lastName },
                { name: 'lastLoginAttempts', value: 0 },
                { name: 'lastAccountId', value: options.accountId },
            ],
            noResult: 'null',
            returnFirst: true,
        }
        var res = await this.exec(query);

        return res.id; 
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