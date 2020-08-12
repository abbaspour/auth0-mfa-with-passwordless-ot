function postRedirect(user, context, callback) {
    if (context.protocol !== "redirect-callback") {
        return callback(null, user, context);
    }

    const securedClient = configuration.HIGH_PRIVILEGED_CLIENT_IDS.indexOf(context.clientID) !== -1;
    const companionAppClientId = configuration.COMPANION_APP_CLIENT_ID;
    const companionAppClientSecret = configuration.COMPANION_APP_CLIENT_SECRET;
    const issuer = `https://${auth0.domain}`;

    console.log(`${configuration.HIGH_PRIVILEGED_CLIENT_IDS} ${context.clientID} ${securedClient} ${context.protocol}`);

    if (!securedClient)
        return callback(null, user, context);

    function postVerify(err, decoded) {
        if (err) {
            return callback(new UnauthorizedError("MFA failed"));
        } else if (decoded.sub !== user.user_id) {
            return callback(new UnauthorizedError("Token does not match the current user"));
        } else if (!decoded.success) {
            return callback(new UnauthorizedError("MFA was not confirmed"));
        } else {
            return callback(null, user, context);
        }
    }

    verifyToken(
        companionAppClientId,
        companionAppClientSecret,
        issuer,
        context.request.query.token,
        postVerify
    );


}
