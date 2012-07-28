"use strict";

var _ = require("underscore");
var handleAuthenticatedResource = require("./handleAuthenticatedResource");

module.exports = function createOauth2Plugin(options) {
    if (typeof options.authenticateToken !== "function") {
        throw new Error("Must supply authenticateToken option.");
    }

    options = _.defaults(options, {
        tokenEndpoint: "/token",
        wwwAuthenticateRealm: "Who goes there?",
        authenticatedRequestPredicate: function (req) { return true; }
    });

    return function oauth2Plugin(req, res, next) {
        if (req.method === "POST" && req.path === options.tokenEndpoint) {
            // TODO grant token
        } else if (options.authenticatedRequestPredicate(req)) {
            handleAuthenticatedResource(req, res, next, options);
        } else {
            next();
        }
    };
};
