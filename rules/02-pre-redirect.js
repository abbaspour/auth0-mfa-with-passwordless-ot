function preRedirect(user, context, callback) {

    if(context.protocol === "redirect-callback")
        return callback(null, user, context);

    const securedClient = configuration.HIGH_PRIVILEGED_CLIENT_IDS.indexOf(context.clientID) !== -1;
    const companionAppClientId = configuration.COMPANION_APP_CLIENT_ID;
    const companionAppClientSecret = configuration.COMPANION_APP_CLIENT_SECRET;
    const issuer = `https://${auth0.domain}`;

    if(context.connection === 'sms' && context.clientID !== companionAppClientId) {
        return callback('sms connection is for companion app only', user, context);
    }

    console.log(`${configuration.HIGH_PRIVILEGED_CLIENT_IDS} ${context.clientID} ${securedClient} ${context.protocol}`);

    if (!securedClient)
        return callback(null, user, context);

    let presentMFA = securedClient;
    let phone_number = user.app_metadata.phone_number;

    if (presentMFA) {
        if(!phone_number) {
            return callback('Unable to MFA. User has no registered phone number', user, context);
        }

        console.log('going to MFA for user: ' + user.email + ", phone number: " + phone_number);

        const data = {sub: user.user_id, phone_number: phone_number};
        const token = global.createToken(companionAppClientId, companionAppClientSecret, issuer, data);

        global.sendSMS(companionAppClientId, companionAppClientSecret, phone_number, callback);

        context.redirect = {
          	url: "http://app.localtest.me:3000?token=" + token
        };
    }

    callback(null, user, context);
}
