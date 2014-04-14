"use strict";

var _ = require("underscore");

module.exports = function makeSetup(grantTypes, requiredHooks, grantToken) {
    var errorSenders = require("./makeErrorSenders")(grantTypes);
    var handleAuthenticatedResource = require("./makeHandleAuthenticatedResource")(errorSenders);

    return function restifyOAuth2Setup(server, options) {
        if (typeof options.hooks !== "object" || options.hooks === null) {
            throw new Error("Must supply hooks.");
        }
        requiredHooks.forEach(function (hookName) {
            if (typeof options.hooks[hookName] !== "function") {
                throw new Error("Must supply " + hookName + " hook.");
            }
        });

        if (typeof options.hooks.grantScopes !== "function") {
            // By default, grant no scopes.
            options.hooks.grantScopes = function (credentials, scopesRequested, req, cb) {
                cb(null, []);
            };
        }

        options = _.defaults(options, {
            tokenEndpoint: "/token",
            wwwAuthenticateRealm: "Who goes there?",
            tokenExpirationTime: Infinity
        });

        // Allow `tokenExpirationTime: Infinity` (like above), but translate it into `undefined` so that
        // `JSON.stringify` omits it entirely when we write out the response as
        // `JSON.stringify({ expires_in: tokenExpirationTime, ... })`.
        if (options.tokenExpirationTime === Infinity) {
            options.tokenExpirationTime = undefined;
        }

        server.post(options.tokenEndpoint, function (req, res, next) {
            grantToken(req, res, next, options);
        });

        server.use(function ccOAuth2Plugin(req, res, next) {
            res.sendUnauthenticated = function (message) {
                errorSenders.authenticationRequired(res, res.send.bind(res), options, message);
            };

            res.sendUnauthorized = function (message) {
                errorSenders.insufficientAuthorization(res, res.send.bind(res), options, message);
            };

            if (req.method === "POST" && req.path() === options.tokenEndpoint) {
                // This is handled by the route installed above, so do nothing.
                next();
            } else if (req.authorization.scheme) {
                handleAuthenticatedResource(req, res, next, options);
            } else {
                // Otherwise Restify will set it by default, which gives false positives for application code.
                req.username = null;
                next();
            }
        });
    };
};
