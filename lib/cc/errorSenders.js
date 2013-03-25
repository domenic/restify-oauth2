"use strict";

var restify = require("restify");

function setUnauthorizedHeaders(res, options) {
    res.header("WWW-Authenticate", "Bearer realm=\"" + options.wwwAuthenticateRealm + "\"");
    res.header("Link",
        "<" + options.tokenEndpoint + ">; rel=\"oauth2-token\"; grant-types=\"client_credentials\"; token-types=\"bearer\"");
}

exports.sendWithUnauthorizedHeaders = function (error, res, options) {
    if (error.statusCode === 401) {
        setUnauthorizedHeaders(res, options);
    }
    res.send(error);
};

exports.tokenRequired = function (res, options, message) {
    if (message === undefined) {
        message = "Bearer token required. Follow the oauth2-token link to get one!";
    }

    exports.sendWithUnauthorizedHeaders(new restify.UnauthorizedError(message), res, options);
};

exports.tokenInvalid = function (res, options, message) {
    if (message === undefined) {
        message = "Bearer token invalid. Follow the oauth2-token link to get a valid one!";
    }

    exports.sendWithUnauthorizedHeaders(new restify.UnauthorizedError(message), res, options);
};
