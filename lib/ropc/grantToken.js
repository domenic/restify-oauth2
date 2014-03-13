"use strict";

var restify = require("restify");
var _ = require("underscore");
var validateGrantTokenRequest = require("../common/validateGrantTokenRequest");
var makeOAuthError = require("../common/makeOAuthError");

module.exports = function grantToken(req, res, next, options) {
    function sendUnauthorizedError(type, description) {
        res.header("WWW-Authenticate", "Basic realm=\"" + description + "\"");
        next(makeOAuthError("Unauthorized", type, description));
    }


    if (!validateGrantTokenRequest("password", req, next)) {
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

    var clientId = req.authorization.basic.username;
    var clientSecret = req.authorization.basic.password;

    options.hooks.validateClient(clientId, clientSecret, function (error, result) {
        if (error) {
            return next(error);
        }

        if (!result) {
            return sendUnauthorizedError("invalid_client", "Client ID and secret did not validate.");
        }

        options.hooks.grantUserToken(username, password, function (error, token) {
            if (error) {
                return next(error);
            }

            if (!token) {
                return sendUnauthorizedError("invalid_grant", "Username and password did not authenticate.");
            }

            if ('grantScopes' in options.hooks) {
                //we space-split the scopes of the request, if any
                var scopesRequested = [];
                if ('scope' in req.body) {
                    scopesRequested = req.body.scope.split(" ");
                }
                
                options.hooks.grantScopes(clientId, clientSecret, username, password, token, scopesRequested, function (error, scopesGranted) {
                    if (error) {
                        return next(error);
                    }
                    //by default, we grant all the scopes requested
                    var scopes = scopesRequested;
                    //...unless the callback has something to say
                    if (scopesGranted instanceof Array) {
                        scopes = scopesGranted;
                    }
                    res.send({
                        access_token: token,
                        token_type: "Bearer",
                        expires_in: options.tokenExpirationTime,
                        scopes: scopes
                    });
                    next();
                });
            } else {
                res.send({
                    access_token: token,
                    token_type: "Bearer",
                    expires_in: options.tokenExpirationTime
                });
                next();
            }
        });
    });
};
