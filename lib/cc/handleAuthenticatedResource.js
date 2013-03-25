"use strict";

var errorSenders = require("./errorSenders");

function hasBearerToken(req) {
    return req.authorization && req.authorization.scheme === "Bearer" && req.authorization.credentials.length > 0;
}

function getBearerToken(req) {
    return hasBearerToken(req) ? req.authorization.credentials : null;
}

module.exports = function handleAuthenticatedResource(req, res, next, options) {
    var token = getBearerToken(req);
    if (!token) {
        return errorSenders.tokenRequired(res, options);
    }

    req.pause();
    options.hooks.authenticateToken(token, function (error, clientId) {
        req.resume();

        if (error) {
            return errorSenders.sendWithUnauthorizedHeaders(error, res, options);
        }

        if (!clientId) {
            return errorSenders.tokenInvalid(res, options);
        }

        req.clientId = clientId;
        next();
    });
};
