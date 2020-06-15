'use strict';

const MSSQL = require('../../modules/db-core');

function DBAuthAccount(options) {
    this.connString = (typeof options === 'string') ? options : options.connString;

    this.getAccountConnString = async function (userId, accountId) {
        var db = new MSSQL(this.connString);
        var sql = `select	a.code, a.serverName, a.dbName
                    from	accountLogin l
                    left outer join account a on l.lastAccountId = a.id
                    where	l.lastAccountId = @lastAccountId
                    and		l.loginId = @loginId`;

        var result = await db.exec({
            query: sql,
            params: [
                { name: 'loginId', value: userId },
                { name: 'lastAccountId', value: accountId },
            ]
        });

        if (result.count == 0) { return null; }
        var connConfig = result.first();
        return {
            user: connConfig.code,
            password: process.env.DB_TENANT_PASS,
            server: connConfig.serverName,
            database: connConfig.dbName
        }
    }


}




module.exports = {
    get: function (options) {
        return new DBAuthAccount(options);
    }
}