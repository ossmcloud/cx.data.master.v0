'use strict';

const _path = require('path');
const _cx_data = require('cx-data');
//const _cx_auth = require('./auth/cx-master-auth');

class CXMasterContext extends _cx_data.DBContext {
    constructor(pool) {
        super(pool, _path.join(__dirname, 'business'));
    }

}
//CXClientContext.prototype.Schema = _cx_client_schema



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