"use strict";

var _ = require("underscore");
var restify = require("restify");

function getBearerToken(req) {
    return req.authorization && req.authorization.scheme === "Bearer" && req.authorization.credentials.length > 0 ?
        req.authorization.credentials : null;
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

    function sendTokenRequiredError(res) {
        setUnauthorizedHeaders(res);
        res.send(new restify.UnauthorizedError("Bearer token required. Follow the oauth2-token link to get one!"));
    }

    return function oauth2Plugin(req, res, next) {
        if (req.method === "POST" && req.path === options.tokenEndpoint) {
            // TODO grant token
        } else if (options.authenticatedRequestPredicate(req)) {
            var token = getBearerToken(req);
            if (!token) {
                return sendTokenRequiredError(res);
            }

            req.pause();
            options.authenticateToken(token, req, function (error, username) {
                req.resume();

                if (error) {
                    if (error.statusCode === 401) {
                        setUnauthorizedHeaders(res);
                    }

                    return next(error);
                }

                req.username = username;
                next();
            });
        } else {
            next();
        }
    };
};
