"use strict";

var _ = require("underscore");
var grantToken = require("./grantToken");
var handleAuthenticatedResource = require("./handleAuthenticatedResource");
var errorSenders = require("./errorSenders");

module.exports = function restifyOAuth2(server, options) {
    if (typeof options.hooks !== "object" || options.hooks === null) {
        throw new Error("Must supply hooks.");
    }
    if (typeof options.hooks.validateClient !== "function") {
        throw new Error("Must supply validateClient hook.");
    }
    if (typeof options.hooks.grantToken !== "function") {
        throw new Error("Must supply grantToken hook.");
    }
    if (typeof options.hooks.authenticateToken !== "function") {
        throw new Error("Must supply authenticateToken hook.");
    }

    options = _.defaults(options, {
        tokenEndpoint: "/token",
        wwwAuthenticateRealm: "Who goes there?",
        tokenExpirationTime: Infinity
    });

    // Allow `tokenExpirationTime: Infinity` (like above), but translate it into `undefined` so that `JSON.stringify`
    // omits it entirely when we write out the response as `JSON.stringify({ expires_in: tokenExpirationTime, ... })`.
    if (options.tokenExpirationTime === Infinity) {
        options.tokenExpirationTime = undefined;
    }

    server.post(options.tokenEndpoint, function (req, res, next) {
        grantToken(req, res, next, options);
    });

    server.use(function oauth2Plugin(req, res, next) {
        res.sendUnauthorized = function (message) {
            errorSenders.tokenRequired(res, options, message);
        };

        if (req.method === "POST" && req.path() === options.tokenEndpoint) {
            // This is handled by the route installed above, so do nothing.
            next();
        } else if (req.authorization.scheme) {
            handleAuthenticatedResource(req, res, next, options);
        } else {
            req.username = null;
            next();
        }
    });
};
