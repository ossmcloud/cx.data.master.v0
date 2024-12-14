'use strict';

const md5 = require('md5');

const _core = require('cx-core');
const _cx = require('../cx-master-context');
const _cxData = require('cx-data');
const _tfa = require("node-2fa");
const _cx_crypto = require('cx-core/core/cx-crypto');
const { config } = require('process');
const { pool, map } = require('mssql');

const errorCodes = {
    invalidUser: 'F:INVALID_USER',
    invalidPass: 'F:INVALID_PASS',
    invalidSession: 'F:INVALID_SESSION',
    inactiveUser: 'F:INACTIVE_USER',
    lockedUser: 'F:LOCKED_USER',
    deletedUser: 'F:DELETED_USER',
    notVerifiedUser: 'F:NOT_VERIFIED',
    verifiedUser: 'F:VERIFIED',
    passExpired: 'F:PASS_EXPIRED',
    newPassMismatch: 'F:NEW_PASS_MISMATCH',
    newPassNoSame: 'F:NEW_PASS_NO_SAME',
    newPassAlreadyUsed: 'F:NEW_PASS_ALREADY_USED'
}

const configs = {
    maxAttempts: 5,
    passwordAgeInDays: 90,
}

async function getUser(db, token) {
    if (!token || !token.username) { return null; }
    var sql = `select	l.*, a.[name] as accountName, a.currency as accountCurrency, a.[Code] as accountCode, a.dbName, a.serverName, a.serverPass
                from	accountLogin l
                left outer join account a on l.lastAccountId = a.id
                where   l.email = @email`
    var result = await db.exec({
        sql: sql,
        params: { name: 'email', value: token.username }
    });
    if (result.count == 0) { return null; }
    return result.first();
}

async function getUserAccounts(db, userId, excludeAccountId) {
    var sql = 'select	a.id, a.code, a.[name] ';
    sql += 'from	accountLogins l, account a ';
    sql += 'where	l.accountId = a.id ';
    sql += 'and		l.accountLoginId = @loginId ';
    sql += 'and     a.status = 1';
    if (excludeAccountId) {
        sql += 'and     a.id != ' + parseInt(excludeAccountId);
    }
    sql += 'order by a.[name]';
    var result = await db.exec({
        sql: sql,
        params: { name: 'loginId', value: userId },

    });
    if (result.count == 0) { return null; }
    var accounts = new Array();
    _core.list.each(result.rows, function (item, idx) {
        accounts.push({
            id: item.id,
            code: item.code,
            name: item.name
        });
    });
    return accounts;
}

async function getAccountDBContext(db, accountId) {
    try {
        var sql = `select	a.[name] as accountName, a.[Code] as accountCode, a.dbName, a.serverName, a.serverPass
                from	account a
                where   a.id = @id`
        var result = await db.exec({
            sql: sql,
            params: { name: 'id', value: accountId },
            returnFirst: true
        });
        if (!result) { throw new Error(`could not find account id: ${accountId}`); }

        var dbConfig = {
            name: `${result.accountCode}_TEMP`,
            noPullManager: false,
            config: {
                server: result.serverName,
                database: result.dbName,
                user: result.accountCode,
                password: _cx_crypto.Aes.decrypt(result.serverPass, result.accountCode),
                connectionTimeout: 60000,
                requestTimeout: 180000,
                pool: {
                    max: 20,
                    min: 0,
                    idleTimeoutMillis: 60000
                }
            }
        }

        var db_pool = await _cxData.getPool(dbConfig);

        return new _cxData.DBContext(db_pool, '', dbConfig);
    } catch (error) {
        throw new Error(`could not create account [id: ${accountId}] DB Context: ${error.message}`);
    }
}
async function getAccountTranTypeConfigs(db, accountId, eposProvider) {
    var cxClient = await getAccountDBContext(db, accountId);
    var res = await cxClient.exec({
        sql: `
            select  mapConfigId, eposProvider, erpProvider, name, s.shopCode, s.shopName
            from    cx_map_config map
            JOIN    cx_shop s on s.shopId = map.mapMasterShop
            WHERE   mapTypeId = 1
            and     eposProvider = @eposProvider
            order by name
        `,
        params: [{ name: 'eposProvider', value: eposProvider }]
    });
    return res.rows;
}
async function getAccountTranTypes(db, accountId, mapConfigId) {
    var cxClient = await getAccountDBContext(db, accountId);

    var res = await cxClient.exec({
        sql: `
            select  tt.*, cbt.code as cbCode, cbt.cbSection
            from    cr_tran_type_config tt
            JOIN    cr_cb_tran_type cbt on cbt.cbTranTypeId = tt.cbTranTypeId
            WHERE   mapConfigId = @mapConfigId
            order by tt.sortIndex, tt.[description]
        `,
        params: [{ name: 'mapConfigId', value: mapConfigId }]
    });

    return res.rows;
}

async function logAudit(request, db, dbUser, failureOptions, failureSessionId) {
    // build session id
    var d = new Date();
    var sessionId = (failureOptions)
        ? (failureSessionId || '')
        : dbUser.loginId.toString() + ':' + d.getTime().toString();
    // insert login audit record
    var query = 'insert into accountLoginAudit (loginId, loginIP, loginInfo, sessionId, status, accountId) ';
    query += 'values (@loginId, @loginIP, @loginInfo, @sessionId, @status, @accountId) ';
    // check failure options
    if (!failureOptions) {
        // if successful login then update login table with latest session id
        query += 'update accountLogin set lastSessionId = @sessionId, lastLoginIP = @loginIP, lastLoginInfo = @loginInfo, lastLoginAttempts = 0, lastAccessed = GETDATE() where loginId = @loginId';
    } else if (failureOptions == errorCodes.invalidPass) {
        // if password wrong then increase attempts count, if too many set user as locked
        dbUser.lastLoginAttempts += 1;
        query += 'update accountLogin set lastLoginAttempts = (lastLoginAttempts + 1)';
        if (dbUser.lastLoginAttempts >= configs.maxAttempts) { query += ', status = 9'; }
        query += ' where loginId = @loginId';
    }
    // parameters
    var params = new Array();
    params.push({ name: 'loginId', value: dbUser.loginId });
    params.push({ name: 'loginIP', value: request.info.remoteAddress });
    params.push({ name: 'loginInfo', value: request.info.id });
    params.push({ name: 'sessionId', value: sessionId });
    params.push({ name: 'status', value: (failureOptions || 'success') });
    params.push({ name: 'accountId', value: dbUser.lastAccountId });
    // exec script and return failure message or session id
    await db.exec({ sql: query, params: params });
    return failureOptions || sessionId;
}

async function getUserPassHistory(db, loginId, newPass) {
    var result = await db.exec({
        sql: 'select * from accountLoginPassHistory where loginId = @loginId and pass = @pass',
        params: [
            { name: 'loginId', value: loginId },
            { name: 'pass', value: md5(newPass) }
        ]
    });
    if (result.count == 0) { return null; }
    return result.first();
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



async function getAppStatus(db, dbUser) {
    // NOTE: do not check app status if user is from cloud-cx staff
    //if (dbUser.loginType < _cx.LoginType.CX_SUPPORT) {
    var sql = "select message, additionalInfo from appStatus where appType = 'app' and active=1 and (accountId = @accountId or accountId = -1)";
    var result = await db.exec({
        sql: sql,
        params: { name: 'accountId', value: dbUser.lastAccountId }
    });
    return result.first();
    //}
}







function DBAuth(options) {
    this.connString = options;
    this.errorCodes = errorCodes;

    this.validateOAuthCallBack = async function (accountId, userId) {
        var db = await _cx.get(this.connString);

        var sql = `select	l.*, a.[Code] as accountCode, a.dbName, a.serverName, a.serverPass
                    from	accountLogins l
                    left outer join account a on l.accountId = a.id
                    where   l.accountId = @accountId
                    and		l.accountLoginId = @accountLoginId`
        var result = await db.exec({
            sql: sql,
            params: [{ name: 'accountId', value: accountId }, { name: 'accountLoginId', value: userId }],
            returnFirst: true,
        });
        if (!result) { throw new Error('Invalid OAuth Callback Validate Request'); }

        var serverPass = _cx_crypto.Aes.decrypt(result.serverPass, result.accountCode);
        return {
            userId: userId,
            accountId: accountId,
            dbConfig: {

                // @REVIEW: this will create a pool per user, but not sure if that's what I want
                //
                name: 'cx_oauth_' + accountId + '_' + userId,
                // @@TODO: this is stored on local cookie and would not work
                config: {
                    server: result.serverName,
                    database: result.dbName,
                    user: result.accountCode,
                    password: serverPass
                }
            }
        }
    }

    this.validateUser = async function (request, token) {
        var db = await _cx.get(this.connString);
        // get user
        var dbUser = await getUser(db, token);
        if (dbUser == null) { return errorCodes.invalidUser; }
        // check user statuses
        if (dbUser.status == -1) { return await logAudit(request, db, dbUser, errorCodes.notVerifiedUser, token.id); }
        //if (dbUser.status == 0) { return await logAudit(request, db, dbUser, errorCodes.verifiedUser, token.id); }
        if (dbUser.status == 9) { return await logAudit(request, db, dbUser, errorCodes.lockedUser, token.id); }
        if (dbUser.status == 99) { return await logAudit(request, db, dbUser, errorCodes.deletedUser, token.id); }

        // if we have a token id it is an exiting session (cookie) otherwise a login token
        if (token.id === undefined) {
            if (dbUser.pass != md5(token.password)) {
                var response = await logAudit(request, db, dbUser, errorCodes.invalidPass);
                // check attempts count
                if (dbUser.lastLoginAttempts < configs.maxAttempts) {
                    // if less than max return invalid password error
                    return response;
                } else {
                    // if max attempts exceeded then log and return user licked error
                    return await logAudit(request, db, dbUser, errorCodes.lockedUser);
                }
            }
        } else {
            // the token is a valid request.auth.credentials token, check the session ID
            // this is in case the same user has logged in from another PC or from a different browser
            if (dbUser.lastSessionId != token.id) {
                return await logAudit(request, db, dbUser, errorCodes.invalidSession, token.id);
            }
        }

        //if (dbUser.status == 0) { return await logAudit(request, db, dbUser, errorCodes.inactiveUser, token.id); }

        // check for expired passwords
        var passAgeInDays = _core.date.now() - dbUser.lastPassChange;
        passAgeInDays = (((passAgeInDays / 1000) / 60) / 60) / 24;
        if (passAgeInDays > configs.passwordAgeInDays && dbUser.status > 0) {
            return await logAudit(request, db, dbUser, errorCodes.passExpired);
        }

        // create session id if we have a login-token
        if (token.id === undefined) { token.id = await logAudit(request, db, dbUser); }

        var tfaInfo = null;
        if (dbUser.status <= 0) {
            if (!dbUser.tfaKey) {
                const newSecret = _tfa.generateSecret({ name: 'cloud-cx', account: dbUser.email });
                dbUser.tfaKey = newSecret.secret;
                //dbUser.tfaQr = newSecret.qr.replace('chs=166x166', 'chs=250x250');
                dbUser.tfaQr = `https://quickchart.io/qr?text=${newSecret.secret}`;

                await db.exec({
                    sql: `update accountLogin set tfaKey = @tfaKey, tfaQr = @tfaQr where loginId = @loginId`,
                    params: [
                        { name: 'tfaKey', value: dbUser.tfaKey },
                        { name: 'tfaQr', value: dbUser.tfaQr },
                        { name: 'loginId', value: dbUser.loginId }
                    ]
                });
            }
            tfaInfo = {
                key: dbUser.tfaKey,
                qr: dbUser.tfaQr,
            }
        }
        var appStatus = await getAppStatus(db, dbUser);

        // @@TODO: this should come from db but we really only have IE and UK
        var country = dbUser.accountCurrency == 'GBP' ? 'UK' : 'IE';

        // return new/edited token
        var serverPass = null;
        if (dbUser.serverPass) { serverPass = _cx_crypto.Aes.decrypt(dbUser.serverPass, dbUser.accountCode); }
        return {
            username: dbUser.email,
            name: dbUser.firstName + ' ' + dbUser.lastName,
            id: token.id,
            userId: dbUser.loginId,
            userType: dbUser.loginType,
            accountId: dbUser.lastAccountId,
            accountName: dbUser.accountName,
            accountCode: dbUser.accountCode,
            accountCurrency: dbUser.accountCurrency,
            accountCountry: country,
            theme: dbUser.theme || 'light',
            requireTfa: true,
            tfaInfo: tfaInfo,
            status: dbUser.status,
            dbConfig: {
                // @REVIEW: this will create a pool per user, but not sure if that's what I want
                //
                //name: 'cx_' + dbUser.lastAccountId,
                name: 'cx_' + dbUser.lastAccountId + '_' + dbUser.loginId,

                // @@TODO: this is stored on local cookie and would not work
                config: {
                    server: dbUser.serverName,
                    database: dbUser.dbName,
                    user: dbUser.accountCode,
                    password: serverPass,
                }
            },
            appStatus: appStatus
        };
    }

    this.logoutUser = async function (request) {
        // @WILLDO: ADD AUDIT FOR LOG OUT


    }

    this.changePassword = async function (request) {
        var db = await _cx.get(this.connString);
        // get user
        var dbUser = await getUser(db, request.payload);
        if (dbUser == null) { return await logAudit(request, db, dbUser, errorCodes.invalidUser); }
        // check user statuses
        if (dbUser.status == 9) { return await logAudit(request, db, dbUser, errorCodes.lockedUser); }
        if (dbUser.status == 99) { return await logAudit(request, db, dbUser, errorCodes.deletedUser); }
        //
        var token = request.payload;
        // validate old password
        if (dbUser.pass != md5(token.passwordOld)) { return await logAudit(request, db, dbUser, errorCodes.invalidPass); }
        // new pass and confirm new pass must match
        if (token.passwordNew != token.passwordNew2) { return errorCodes.newPassMismatch; }
        // cannot set same password
        if (token.passwordNew == token.passwordOld) { return errorCodes.newPassNoSame; }

        try {
            // check password history
            if (await getUserPassHistory(db, dbUser.loginId, token.passwordNew) != null) { return errorCodes.newPassAlreadyUsed; }

            // set new password
            var query = 'update accountLogin set pass = @newPass, lastPassChange = GetDate() where loginId = @loginId';
            query += ' insert into accountLoginPassHistory (loginId, dateSet, pass) values (@loginId, GetDate(), @newPass)'


            await db.exec({
                sql: query,
                params: [
                    { name: 'newPass', value: md5(token.passwordNew) },
                    { name: 'loginId', value: dbUser.loginId }
                ]
            });
        } catch (error) {
            console.log(error);
            return 'F:ERROR';
        }

        return true;
    }


    this.verifyViaTfa = async function (tfaCode, verifiedInfo) {
        try {
            var db = await _cx.get(this.connString);
            var result = await db.exec({
                sql: 'select loginAuditTFAId, dateExpiry, l.loginId, l.email, l.tfaKey, l.tfaQr from accountLoginAuditTFA a, accountLogin l where a.loginId = l.loginId and twoFactorAuthCode = @twoFactorAuthCode',
                params: [{ name: 'twoFactorAuthCode', value: tfaCode }]
            });
            if (result.count == 0) { throw new Error('your account<br />could not be verified:<br /><b>invalid key</b>'); }

            var tfaInfo = result.first();
            if (tfaInfo.dateExpiry < new Date()) { throw new Error('your account<br />could not be verified:<br /><b>link expired</b>'); }

            var message = '';
            if (verifiedInfo) {

                var result = await db.exec({
                    sql: 'update accountLogin set status = 1, pass = @pass, lastPassChange = GetDate() where loginId = @loginId and status = -1',
                    params: [
                        { name: 'loginId', value: tfaInfo.loginId },
                        { name: 'pass', value: md5(verifiedInfo.password) },
                    ]
                });

                if (result.rowsAffected == 0) { throw new Error('your account<br />could not be verified:<br /><b>invalid status</b>'); }

                await db.exec({
                    sql: 'update accountLoginAuditTFA set dateUsed = GETDATE() where loginAuditTFAId = @loginAuditTFAId',
                    params: [{ name: 'loginAuditTFAId', value: tfaInfo.loginAuditTFAId }]
                });
                message = '<span style="color: darkgreen;">account successfully verified</span>';

            } else {
                message = '<span style="color: darkgreen;">set a password<br />store the 2fa barcode</span>';

                if (!tfaInfo.tfaKey) {
                    const newSecret = _tfa.generateSecret({ name: 'cloud-cx', account: tfaInfo.email });
                    tfaInfo.tfaKey = newSecret.secret;
                    //tfaInfo.tfaQr = newSecret.qr.replace('chs=166x166', 'chs=250x250');
                    tfaInfo.tfaQr = `https://quickchart.io/qr?text=${newSecret.secret}`;

                    await db.exec({
                        sql: `update accountLogin set tfaKey = @tfaKey, tfaQr = @tfaQr where loginId = @loginId`,
                        params: [
                            { name: 'tfaKey', value: tfaInfo.tfaKey },
                            { name: 'tfaQr', value: tfaInfo.tfaQr },
                            { name: 'loginId', value: tfaInfo.loginId }
                        ]
                    });
                }
            }

            return {
                verifyKey: tfaCode,
                email: tfaInfo.email,
                loginId: tfaInfo.loginId,
                tfaKey: tfaInfo.tfaKey,
                tfaQr: tfaInfo.tfaQr,
                message: message
            }
        } catch (error) {
            return {
                loginId: null,
                message: error.message,
            }
        }
    }

    this.validateUser2fa = async function (request) {
        var token = request.payload;
        var db = await _cx.get(this.connString);

        if (token.emailSend === 'true') {
            return 'sendTfaCode';

        } else if (token.emailSent === 'true') {
            var result = await db.exec({
                sql: 'select loginAuditTFAId, dateExpiry from accountLoginAuditTFA where loginId = @loginId and twoFactorAuthCode = @twoFactorAuthCode',
                params: [
                    { name: 'loginId', value: request.auth.credentials.userId },
                    { name: 'twoFactorAuthCode', value: token.tfaCode }
                ]
            });
            if (result.count == 0) { return 'F:INVALID_2FA_CODE'; }
            if (result.first().dateExpiry < new Date()) { return 'F:EXPIRED_2FA_CODE'; }

            await db.exec({
                sql: 'update accountLoginAuditTFA set dateUsed = GETDATE() where loginAuditTFAId = @loginAuditTFAId',
                params: [
                    { name: 'loginAuditTFAId', value: result.first().loginAuditTFAId }
                ]
            });
        } else {
            var result = await db.exec({
                sql: 'select tfaKey from accountLogin where loginId = @loginId',
                params: [
                    { name: 'loginId', value: request.auth.credentials.userId },
                ]
            });
            if (result.count == 0) { return 'F:INVALID_2FA_LOGIN'; }

            var resp = _tfa.verifyToken(result.first().tfaKey, token.tfaCode);
            if (!resp) { return 'F:INVALID_2FA_CODE'; }
            if (resp.delta < 0) { return 'F:EXPIRED_2FA_CODE'; }
            if (resp.delta > 0) { return 'F:UNBORN_2FA_CODE'; }

        }

        return true;
    }

    // @@TODO: @@CODE-REPETITION: this exact function is also here (same name):
    //                                          cx.v0\cx.sdk.v0\cx.data.master.v0\cx-master-context.js
    this.generate2Fa = async function (token, validityInMinutes) {
        if (!validityInMinutes) { validityInMinutes = 15; }

        var tfa = 0;
        while (tfa < 10000) { tfa = Math.floor(Math.random() * 100000000) + 1; }
        tfa = padLeft(tfa, 8, '0');

        var dt = new Date();
        var dtExp = addMinutes(dt, validityInMinutes);

        var db = await _cx.get(this.connString);
        await db.exec({
            sql: 'insert into accountLoginAuditTFA (loginId, twoFactorAuthCode, dateCreated, dateExpiry) values (@loginId, @twoFactorAuthCode, @dateCreated, @dateExpiry)',
            params: [
                { name: 'loginId', value: token.userId },
                { name: 'twoFactorAuthCode', value: tfa },
                { name: 'dateCreated', value: dt },
                { name: 'dateExpiry', value: dtExp },
            ]
        });

        return tfa;
    }

    this.setLoginActive = async function (userId) {
        var db = await _cx.get(this.connString);
        await db.exec({
            sql: 'update accountLogin set status = 1 where loginId = @loginId',
            params: [{ name: 'loginId', value: userId }]
        });
    }

    this.getAccountTranTypeConfigs = async function (accountId, eposProvider) {
        var db = await _cx.get(this.connString);
        return await getAccountTranTypeConfigs(db, accountId, eposProvider);
    }
    this.getAccountTranTypes = async function (accountId, mapConfigId) {
        var db = await _cx.get(this.connString);
        return await getAccountTranTypes(db, accountId, mapConfigId);
    }

    this.getUserAccounts = async function (userId, excludeAccountId) {
        var db = await _cx.get(this.connString);
        return await getUserAccounts(db, userId, excludeAccountId);
    };

    this.setUserAccountId = async function (userId, accountId) {
        var db = await _cx.get(this.connString);

        var result = await db.exec({
            sql: 'select * from accountLogins where accountLoginId = @accountLoginId and accountId = @accountId',
            params: [
                { name: 'accountLoginId', value: userId },
                { name: 'accountId', value: accountId }
            ]
        });
        if (result.count == 0) { throw new Error(`you do not have access to this account [${accountId}], please contact your system administrator.`); }

        await db.exec({
            sql: 'update accountLogin set lastAccountId = @lastAccountId where loginId = @loginId',
            params: [
                { name: 'loginId', value: userId },
                { name: 'lastAccountId', value: accountId }
            ]
        });
    }

    this.getAccountLogin = async function (db, email, accountId) {
        var query = 'select loginId from accountLogin where email = @email';
        if (accountId) {
            query = 'select a.loginId from accountLogin a, accountLogins b where a.loginId = b.accountLoginId and a.email = @email and b.accountId = @accountId';
        }
        var result = await db.exec({
            sql: query,
            params: [
                { name: 'email', value: email },
                { name: 'accountId', value: accountId }
            ]
        });
        if (result.count == 0) { return null; }
        return result.first().loginId;
    }
    this.addAccountLogin = async function (accountId, email, firstName, lastName) {
        var db = await _cx.get(this.connString);
        var isNew = false;
        var loginId = await this.getAccountLogin(db, email);
        if (!loginId) {
            isNew = true;
            var query = 'insert into accountLogin (loginType, email, pass, status, firstName, lastName, lastAccountId, lastLoginAttempts)';
            query += ' values (@loginType, @email, @pass, @status, @firstName, @lastName, @accountId, @lastLoginAttempts)';
            query += " insert into accountLogins (accountId, accountLoginId) values (@accountId, IDENT_CURRENT('accountLogin'))";
            await db.exec({
                sql: query,
                params: [
                    { name: 'accountId', value: accountId },
                    { name: 'loginType', value: 1 },
                    { name: 'email', value: email },
                    { name: 'pass', value: '63aced15f8d9f62ec5f861aa2808dc4d' },
                    { name: 'status', value: 0 },
                    { name: 'firstName', value: firstName },
                    { name: 'lastName', value: lastName },
                    { name: 'lastLoginAttempts', value: 0 },
                ]
            });
        };

        var accountLoginId = await this.getAccountLogin(db, email, accountId);

        if (!accountLoginId) {
            var query = "insert into accountLogins (accountId, accountLoginId) values (@accountId, @loginId)";
            await db.exec({
                sql: query,
                params: [
                    { name: 'accountId', value: accountId },
                    { name: 'loginId', value: loginId },
                ]
            });
        }

        return {
            isNew: isNew,
            loginId: loginId
        }
    }

    this.loginResetByUser = async function (email) {
        var db = await _cx.get(this.connString);
        var isNew = false;
        var loginId = await this.getAccountLogin(db, email);
        if (!loginId) { throw new Error('Unknown email address'); }

        await db.manualReset(loginId, email.substr(0, email.indexOf('@')));

        var verifyCode = await db.generate2Fa(loginId);

        return verifyCode;
    }

}


module.exports = {
    get: function (options) {
        return new DBAuth(options);
    }
}