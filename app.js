'use strict'

const path = require('path');
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const request = require('request');
const jwksClient = require('jwks-rsa');

//const awsServerlessExpressMiddleware = require('aws-serverless-express/middleware')
//router.use(awsServerlessExpressMiddleware.eventContext());

const app = express();

//const baseURL = "https://k47zz7whsj.execute-api.ap-southeast-2.amazonaws.com/Prod";
const clientId = process.env.CLIENT_ID;
const clientSecret = process.env.CLIENT_SECRET;
const issuer = `https://${process.env.AUTH0_DOMAIN}`;

const router = express.Router();

router.use(cors());
router.use(bodyParser.json());
router.use(bodyParser.urlencoded({extended: true}));


// NOTE: tests can't find the views directory without this
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

function createToken(clientId, clientSecret, issuer, payload) {
    const options = {
        expiresIn: 60,
        audience: clientId,
        issuer: issuer
    };
    return jwt.sign(payload, clientSecret, options);
}

const jwks_client = jwksClient({
    jwksUri: `${issuer}/.well-known/jwks.json`,
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
});

function getKey(header, callback) {
    jwks_client.getSigningKey(header.kid, function (err, key) {
        let signingKey = key.publicKey || key.rsaPublicKey;
        callback(null, signingKey);
    });
}

function passwordlessSignIn(phone_number, otp, cb) {
    // raw passwordless sign-in until we get support in node sdk:
    // https://auth0team.atlassian.net/servicedesk/customer/portal/34/ESD-8225
    let options = {
        method: 'POST',
        url: `${issuer}/oauth/token`,
        headers: {'content-type': 'application/json'},
        body: {
            grant_type: 'http://auth0.com/oauth/grant-type/passwordless/otp',
            client_id: clientId,
            client_secret: clientSecret,
            username: phone_number,
            otp: otp,
            realm: 'sms',
            //audience: 'your-api-audience',
            scope: 'openid profile'
        },
        json: true
    };

    request(options, function (error, response, body) {
        if (error) {
            console.log('error in pwdless sign in', error);
            return cb(error);
        }
        if (response.statusCode !== 200) {
            return cb(body);
        }

        //console.log(body);

        jwt.verify(body.id_token, getKey, options, function (err, decoded) {
            if (err) {
                console.log('invalid id_token', err);
                return cb('invalid id_token');
            }

            //console.log('id_token decoded: ' + JSON.stringify(decoded));
            return cb(null, decoded);
        });

    });

}

function decodeToken(res, state, token) {
    try {
        let {sub, phone_number} = jwt.verify(token, clientSecret, {audience: clientId, issuer: issuer});

        if (!phone_number || !sub) {
            console.error('missing phone number or sub');
            return_error(res, state, 'invalid_token');
        } else {
            return {sub, phone_number, masked_phone_number: mask(phone_number)};
        }
    } catch (e) {
        console.error('invalid token. returning to rules.', e);
        return_error(res, state, 'invalid_token');
    }
}

function return_error(res, state, error) {
    res.redirect(`${issuer}/continue?state=${state}&error=invalid_token`);
}

function mask(phone_number) {
    return 'xxxx' + phone_number.substr(phone_number.length / 2 + 1);
}

router.get('/', (req, res) => {
    console.log('starting GET / with req.query: ' + JSON.stringify(req.query));
    let {sub, phone_number, masked_phone_number} = decodeToken(res, req.query.state, req.query.token);
    res.render('challenge', {
        state: req.query.state,
        token: req.query.token,
        phone_number: masked_phone_number,
        error: ''
    });
});

router.post('/resume', (req, res) => {
    let {sub, phone_number, masked_phone_number} = decodeToken(res, req.body.state, req.body.token);

    passwordlessSignIn(phone_number, req.body.otp, function (err, userData) {
        if (err) {
            console.log('error in sign in ' + JSON.stringify(err));
            res.render('challenge', {
                state: req.query.state,
                token: req.query.token,
                phone_number: masked_phone_number,
                error: 'invalid OTP'
            });
            return;
        }

        //console.log('SMS validation data: ' + JSON.stringify(userData));

        if (userData.sub !== sub) {
            console.error(`not the same user; pwdless sub ${userData.sub} != tokebn sub ${sub}`);
            return_error(res, req.body.state, 'sub_mismatch');
        }

        const responseToken = createToken(clientId, clientSecret, issuer, {sub: sub, success: true});
        res.redirect(`${issuer}/continue?state=${req.body.state}&token=${responseToken}`);
    });

});

app.use('/', router);
module.exports = app;
