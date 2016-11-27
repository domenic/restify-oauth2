"use strict";

var validateGrantTokenRequest = require("../common/validateGrantTokenRequest");
var finishGrantingToken = require("../common/finishGrantingToken");
var makeOAuthError = require("../common/makeOAuthError");

module.exports = function grantToken(req, res, next, options) {
    function sendUnauthorizedError(type, description) {
        res.header("WWW-Authenticate", "Basic realm=\"" + description + "\"");
        next(makeOAuthError("Unauthorized", type, description));
    }

    if (!validateGrantTokenRequest("password", req, next)) {
        return;
    }

    if (!req.body.username) {
        return next(makeOAuthError("BadRequest", "invalid_request", "Must specify username field."));
    }

    if (!req.body.password) {
        return next(makeOAuthError("BadRequest", "invalid_request", "Must specify password field."));
    }

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

        var allCredentials = { clientId: clientId, clientSecret: clientSecret };
        for (var i in req.body) {
            allCredentials[i] = req.body[i];
        }

        options.hooks.grantUserToken(allCredentials, req, function (error, token) {
            if (error) {
                return next(error);
            }

            if (!token) {
                return sendUnauthorizedError("invalid_grant", "Username and password did not authenticate.");
            }

            finishGrantingToken(allCredentials, token, options, req, res, next);
        });
    });
};
