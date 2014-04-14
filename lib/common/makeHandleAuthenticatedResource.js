"use strict";

function hasBearerToken(req) {
    return req.authorization && req.authorization.scheme === "Bearer" && req.authorization.credentials.length > 0;
}

function getBearerToken(req) {
    return hasBearerToken(req) ? req.authorization.credentials : null;
}

module.exports = function makeHandleAuthenticatedResource(errorSenders) {
    return function handleAuthenticatedResource(req, res, next, options) {
        var token = getBearerToken(req);
        if (!token) {
            return errorSenders.tokenRequired(res, next, options);
        }

        req.pause();
        options.hooks.authenticateToken(token, req, function (error, authenticated) {
            req.resume();

            if (error) {
                return errorSenders.sendWithHeaders(res, next, options, error);
            }

            if (!authenticated) {
                return errorSenders.tokenInvalid(res, next, options);
            }

            next();
        });
    };
};
