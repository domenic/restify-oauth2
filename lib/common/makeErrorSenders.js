"use strict";

var restify = require("restify");

module.exports = function makeErrorSenders(grantTypes) {
    function setUnauthorizedHeaders(res, options) {
        res.header("WWW-Authenticate", "Bearer realm=\"" + options.wwwAuthenticateRealm + "\"");
        res.header("Link",
            "<" + options.tokenEndpoint + ">; rel=\"oauth2-token\"; " +
            "grant-types=\"" + grantTypes + "\"; token-types=\"bearer\"");
    }

    function sendWithUnauthorizedHeaders(error, res, options) {
        if (error.statusCode === 401) {
            setUnauthorizedHeaders(res, options);
        }
        res.send(error);
    }

    return {
        sendWithUnauthorizedHeaders: sendWithUnauthorizedHeaders,

        tokenRequired: function (res, options, message) {
            if (message === undefined) {
                message = "Bearer token required. Follow the oauth2-token link to get one!";
            }

            sendWithUnauthorizedHeaders(new restify.UnauthorizedError(message), res, options);
        },

        tokenInvalid: function (res, options, message) {
            if (message === undefined) {
                message = "Bearer token invalid. Follow the oauth2-token link to get a valid one!";
            }

            sendWithUnauthorizedHeaders(new restify.UnauthorizedError(message), res, options);
        }
    };
};
