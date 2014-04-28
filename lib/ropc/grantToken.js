"use strict";

var _ = require("underscore");
var validateGrantTokenRequest = require("../common/validateGrantTokenRequest");
var finishGrantingToken = require("../common/finishGrantingToken");
var makeOAuthError = require("../common/makeOAuthError");

module.exports = function grantToken(req, res, next, options) {
    var validateAuthorization = options.hooks.validateClient !== "allow public clients";
    if (!validateGrantTokenRequest("password", req, next, { validateAuthorization: validateAuthorization })) {
        return;
    }

    var username = req.body.username;
    var password = req.body.password;

    if (!username) {
        return next(makeOAuthError("BadRequest", "invalid_request", "Must specify username field."));
    }

    if (!password) {
        return next(makeOAuthError("BadRequest", "invalid_request", "Must specify password field."));
    }

    if (options.hooks.validateClient === "allow public clients") {
        validateUser({});
    } else {
        var clientId = req.authorization.basic.username;
        var clientSecret = req.authorization.basic.password;
        var clientCredentials = { clientId: clientId, clientSecret: clientSecret };

        options.hooks.validateClient(clientCredentials, req, function (error, result) {
            if (error) {
                return next(error);
            }

            if (!result) {
                return sendUnauthorizedError("invalid_client", "Client ID and secret did not validate.");
            }

            validateUser({ clientId: clientId, clientSecret: clientSecret });
        });
    }

    function validateUser(credentials) {
        credentials.username = username;
        credentials.password = password;

        options.hooks.grantUserToken(credentials, req, function (error, token) {
            if (error) {
                return next(error);
            }

            if (!token) {
                return sendUnauthorizedError("invalid_grant", "Username and password did not authenticate.");
            }

            var allCredentials = _.extend({ token: token }, credentials);
            finishGrantingToken(allCredentials, token, options, req, res, next);
        });
    }

    function sendUnauthorizedError(type, description) {
        res.header("WWW-Authenticate", "Basic realm=\"" + description + "\"");
        next(makeOAuthError("Unauthorized", type, description));
    }
};
