'use strict';   

const _cx_context = require('./cx-master-context');
const _cx_auth = require('./auth/auth');
const _cx_auth_mail = require('./auth/auth-email');


module.exports = {
    //Schema: _cx_client_schema,

    get: function (config) {
        return _cx_context.get(config);
    },

    auth: function (config) {
        return _cx_auth.get(config);
    },

    authEmail: function (options) {
        return _cx_auth_mail.get(options);
    },

    getPools: _cx_context.getPools,
    countPools: _cx_context.countPools,


}