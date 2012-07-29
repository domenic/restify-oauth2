"use strict";

var restify = require("restify");

module.exports = function handleAuthenticatedResource(req, res, next, options) {
    function getBearerToken() {
        return req.authorization && req.authorization.scheme === "Bearer" && req.authorization.credentials.length > 0 ?
            req.authorization.credentials : null;
    }

    function setUnauthorizedHeaders() {
        res.header("WWW-Authenticate", "Bearer realm=\"" + options.wwwAuthenticateRealm + "\"");
        res.header("Link", "<" + options.tokenEndpoint + ">; rel=\"oauth2-token\"");
    }

    function sendAuthenticateError(error) {
        if (error.statusCode === 401) {
            setUnauthorizedHeaders(res);
        }

        next(error);
    }

    function sendTokenRequiredError() {
        var message = "Bearer token required. Follow the oauth2-token link to get one!";
        sendAuthenticateError(new restify.UnauthorizedError(message));
    }

    function sendTokenInvalidError() {
        var message = "Bearer token invalid. Follow the oauth2-token link to get a valid one!";
        sendAuthenticateError(new restify.UnauthorizedError(message));
    }


    var token = getBearerToken();
    if (!token) {
        return sendTokenRequiredError();
    }

    req.pause();
    options.authenticateToken(token, req, function (error, username) {
        req.resume();

        if (error) {
            return sendAuthenticateError(error);
        }

        if (!username) {
            return sendTokenInvalidError();
        }

        req.username = username;
        next();
    });
};
