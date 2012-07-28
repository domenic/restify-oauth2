"use strict";

var _ = require("underscore");
var restify = require("restify");

function hasBearerToken(req) {
    return req.authorization && req.authorization.scheme === "Bearer";
}

module.exports = function createOauth2Plugin(options) {
    if (typeof options.authenticateToken !== "function") {
        throw new Error("Must supply authenticateToken option.");
    }

    options = _.defaults(options, {
        tokenEndpoint: "/token",
        wwwAuthenticateRealm: "Who goes there?",
        authenticatedRequestPredicate: function (req) { return true; }
    });

    function setUnauthorizedHeaders(res) {
        res.header("WWW-Authenticate", "Bearer realm=\"" + options.wwwAuthenticateRealm + "\"");
        res.header("Link", "<" + options.tokenEndpoint + ">; rel=\"oauth2-token\"");
    }

    function sendUnauthorizedError(res, message) {
        setUnauthorizedHeaders(res);
        res.send(new restify.UnauthorizedError(message));
    }

    return function oauth2Plugin(req, res, next) {
        if (req.method === "POST" && req.path === options.tokenEndpoint) {
            // TODO grant token
        } else if (options.authenticatedRequestPredicate(req)) {
            if (!hasBearerToken(req)) {
                return sendUnauthorizedError(res, "Bearer token required. Follow the oauth2-token link to get one!");
            }

            var token = req.authorization.credentials;
            if (!token) {
                return sendUnauthorizedError(res, "Bearer token is missing.");
            }

            req.pause();
            options.authenticateToken(token, req, function (error, username) {
                if (error) {
                    if (error.statusCode === 401) {
                        setUnauthorizedHeaders(res);
                    }
                    return next(error);
                }

                req.username = username;
                req.resume();
                next();
            });
        } else {
            next();
        }
    };
};
