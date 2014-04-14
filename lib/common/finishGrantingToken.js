"use strict";

var _ = require("underscore");
var makeOAuthError = require("./makeOAuthError");

module.exports = function finishGrantingToken(allCredentials, token, options, req, res, next) {
    var shouldIncludeScopeInResponse = false;
    var scopesRequested = [];
    if (_.has(req.body, "scope")) {
        if (typeof req.body.scope !== "string") {
            var message = "The scope value must be a space-delimited string, if present.";
            return next(makeOAuthError("BadRequest", "invalid_scope", message));
        }
        shouldIncludeScopeInResponse = true;
        scopesRequested = req.body.scope.split(" ");
    }

    options.hooks.grantScopes(allCredentials, scopesRequested, req, function (error, scopesGranted) {
        if (error) {
            return next(error);
        }

        if (!scopesGranted) {
            var message = "The requested scopes are invalid, unknown, or exceed the set of scopes appropriate for " +
                          "these credentials.";
            return next(makeOAuthError("BadRequest", "invalid_scope", message));
        }

        if (scopesGranted === true) {
            scopesGranted = scopesRequested;
        }

        var responseBody = {
            access_token: token,
            token_type: "Bearer",
            expires_in: options.tokenExpirationTime
        };
        if (shouldIncludeScopeInResponse) {
            responseBody.scope = scopesGranted.join(" ");
        }

        res.send(responseBody);
        next();
    });
};
