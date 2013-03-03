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
        return errorSenders.tokenRequired(res, next, options);
    }

    req.pause();
    options.hooks.authenticateToken(token, function (error, username) {
        req.resume();

        if (error) {
            return errorSenders.sendWithUnauthorizedHeaders(error, res, next, options);
        }

        if (!username) {
            return errorSenders.tokenInvalid(res, next, options);
        }

        req.username = username;
        next();
    });
};
