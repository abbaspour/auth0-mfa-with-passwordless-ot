function globalFunctions(user, context, callback) {

    if (!global.createToken) {
        global.createToken = function (clientId, clientSecret, issuer, payload) {
            const options = {
                expiresIn: 5 * 60,
                audience: clientId,
                issuer: issuer
            };
            return jwt.sign(payload, clientSecret, options);
        };
    }

    if (!global.verifyToken) {
        global.verifyToken = function (clientId, clientSecret, issuer, token, cb) {
            jwt.verify(
                token,
                clientSecret, {
                    audience: clientId,
                    issuer: issuer
                },
                cb
            );
        };
    }

    if (!global.sendSMS) {
        global.sendSMS = function (clientId, clientSecret, phone_number, callback) {
            let AuthenticationClient = require('auth0@2.27.0').AuthenticationClient;
            let auth0 = new AuthenticationClient({
                domain: 'abbaspour.auth0.com',
                clientId: clientId,
                clientSecret: clientSecret
            });

            let data = {
                phone_number: phone_number
            };

            auth0.passwordless.sendSMS(data, function (err) {
                if (err) {
                    console.log(err);
                    return callback('failed to send MFA SMS, please try again later');
                }
            });
        };
    }

    callback(null, user, context);
}
