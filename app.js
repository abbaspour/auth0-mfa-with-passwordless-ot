'use strict'

const path = require('path');
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const request = require("request");

const awsServerlessExpressMiddleware = require('aws-serverless-express/middleware')

const app = express()

//const baseURL = "https://k47zz7whsj.execute-api.ap-southeast-2.amazonaws.com/Prod";
const clientId = "6awtx57XeNg8M5SAiUo1tViox6IeeJC7";
const clientSecret = "wUApSWguhg9s-rFZtU0vZclf9O5V_dXrKUN7fKHDWONFSIZLbDs4QrUOosCU6Xsm";

const auth0Domain = 'abbaspour.auth0.com';
const issuer = `https://${auth0Domain}`;

const router = express.Router();

router.use(cors());
router.use(bodyParser.json());
router.use(bodyParser.json());
router.use(bodyParser.urlencoded({extended: true}));

//router.use(awsServerlessExpressMiddleware.eventContext());

// NOTE: tests can't find the views directory without this
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

function renderChallengePage(res, state, token, error = '') {
    res.render('challenge', {state: state, token: token, error: error});
}

function createToken(clientId, clientSecret, issuer, payload) {
    const options = {
        expiresIn: 60,
        audience: clientId,
        issuer: issuer
    };
    return jwt.sign(payload, clientSecret, options);
}

function passwordlessSignIn(phone_number, otp, cb) {
    var request = require("request");

    var options = {
        method: 'POST',
        url: `https://${auth0Domain}/oauth/token`,
        headers: {'content-type': 'application/json'},
        body: {
            grant_type: 'http://auth0.com/oauth/grant-type/passwordless/otp',
            client_id: clientId,
            client_secret: clientSecret,
            username: phone_number,
            otp: otp,
            realm: 'sms',
            //audience: 'your-api-audience',
            scope: 'openid profile email'
        },
        json: true
    };

    request(options, function (error, response, body) {
        if (error) {
            console.log('error in sign in ' + error);
            return cb(error);
        }
        if (response.statusCode !== 200) {
            return cb(body);
        }

        var jwksClient = require('jwks-rsa');
        var client = jwksClient({
            jwksUri: `https://${auth0Domain}/.well-known/jwks.json`
        });

        function getKey(header, callback) {
            client.getSigningKey(header.kid, function (err, key) {
                var signingKey = key.publicKey || key.rsaPublicKey;
                callback(null, signingKey);
            });
        }

        console.log(body);

        jwt.verify(body.id_token, getKey, options, function (err, decoded) {
            if (err) {
                console.log('invalid id_token');
                return cb('invalid id_token');
            }

            console.log('id_token decoded: ' + JSON.stringify(decoded));
            return cb(null, decoded);
        });

    });

}

router.get('/', (req, res) => {
    console.log('starting GET / with req.query: ' + JSON.stringify(req.query));
    renderChallengePage(res, req.query.state, req.query.token);
});

router.post('/resume', (req, res) => {
    let decoded;
    try {
        decoded = jwt.verify(req.body.token, clientSecret, {
                audience: clientId,
                issuer: issuer
            },
        );
    } catch (e) {
        res.redirect(`https://abbaspour.auth0.com/continue?state=${state}&error=invalid_token`);
        return;
    }

    passwordlessSignIn(decoded.phone_number, req.body.otp, function (err, userData) {
        if (err) {
            console.log('error in sign in ' + JSON.stringify(err));
            return renderChallengePage(res, req.body.state, req.body.token, 'invalid OTP. try again');
        }

        console.log('SMS validation data: ' + JSON.stringify(userData));

        if (userData.sub !== decoded.sub) {
            throw new Error('not the same user');
        }

        let state = req.body.state;

        const responseToken = createToken(clientId, clientSecret, issuer, {sub: decoded.sub, success: true});

        res.redirect(`https://abbaspour.auth0.com/continue?state=${state}&token=${responseToken}`);

    });

});

// The aws-serverless-express library creates a server and listens on a Unix
// Domain Socket for you, so you can remove the usual call to app.listen.
console.log('starting on port 3000');
app.listen(3000);

app.use('/', router);

// Catch 404 and forward to error handler
/*
app.use(function (req, res, next) {
    const err = new Error('Not Found');
    err.status = 404;
    next(err);
});
*/

// Error handlers
/*
app.use(function (err, req, res, next) {
    res.status(err.status || 500);
    res.render('error', {
        message: err.message,
        error: process.env.NODE_ENV !== 'production' ? err : {}
    });
});
*/

// Export your express server so you can import it in the lambda function.
module.exports = app;
