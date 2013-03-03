"use strict";

var _ = require("underscore");
var grantToken = require("./grantToken");
var handleAuthenticatedResource = require("./handleAuthenticatedResource");

module.exports = function createOauth2Plugin(options) {
    if (typeof options.validateClient !== "function") {
        throw new Error("Must supply validateClient option.");
    }
    if (typeof options.grantToken !== "function") {
        throw new Error("Must supply grantToken option.");
    }
    if (typeof options.authenticateToken !== "function") {
        throw new Error("Must supply authenticateToken option.");
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

    return function oauth2Plugin(req, res, next) {
        if (req.method === "POST" && req.path === options.tokenEndpoint) {
            grantToken(req, res, next, options);
        } else if (req.authorization) {
            handleAuthenticatedResource(req, res, next, options);
        } else {
            req.username = null;
            next();
        }
    };
};
