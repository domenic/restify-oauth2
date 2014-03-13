"use strict";

var restify = require("restify");
var _ = require("underscore");
var validateGrantTokenRequest = require("../common/validateGrantTokenRequest");
var makeOAuthError = require("../common/makeOAuthError");

module.exports = function grantToken(req, res, next, options) {
    if (!validateGrantTokenRequest("client_credentials", req, next)) {
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

        if ('grantScopes' in options.hooks) {
            //we space-split the scopes of the request, if any
            var scopesRequested = [];
            if ('scope' in req.body) {
                scopesRequested = req.body.scope.split(" ");
            }
            
            options.hooks.grantScopes(clientId, clientSecret, token, scopesRequested, function (error, scopesGranted) {
                if (error) {
                    return next(error);
                }
                var scopes = scopesRequested;
                if (scopesGranted instanceof Array) {
                    scopes = scopesGranted;
                }
                res.send({
                    access_token: token,
                    token_type: "Bearer",
                    expires_in: options.tokenExpirationTime,
                    scopes: scopes
                });
            });
        } else {
            res.send({
                access_token: token,
                token_type: "Bearer",
                expires_in: options.tokenExpirationTime
            });
        }
    });
};
