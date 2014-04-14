"use strict";

var restify = require("restify");
var _ = require("underscore");
var validateGrantTokenRequest = require("../common/validateGrantTokenRequest");
var makeOAuthError = require("../common/makeOAuthError");

module.exports = function grantToken(req, res, next, options) {
    if (!validateGrantTokenRequest("client_credentials", "confidential", req, next)) {
        return;
    }

    var clientId = req.authorization.basic.username;
    var clientSecret = req.authorization.basic.password;

    options.hooks.grantClientToken(clientId, clientSecret, function (error, token) {
        if (error) {
            return next(error);
        }

        if (!token) {
            res.header("WWW-Authenticate", "Basic realm=\"Client ID and secret did not authenticate.\"");
            return next(makeOAuthError("Unauthorized", "invalid_client", "Client ID and secret did not authenticate."));
        }

        res.send({
            access_token: token,
            token_type: "Bearer",
            expires_in: options.tokenExpirationTime
        });
        next();
    });
};
