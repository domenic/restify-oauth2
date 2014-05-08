"use strict";

var _ = require("underscore");
var makeOAuthError = require("./makeOAuthError");

module.exports = function validateGrantTokenRequest(grantTypes, req, next) {
    function sendBadRequestError(type, description) {
        next(makeOAuthError("BadRequest", type, description));
    }

    if (!req.body || typeof req.body !== "object") {
        sendBadRequestError("invalid_request", "Must supply a body.");
        return false;
    }

    if (!_.has(req.body, "grant_type")) {
        sendBadRequestError("invalid_request", "Must specify grant_type field.");
        return false;
    }

    if (grantTypes.indexOf(req.body.grant_type) === -1) {
        sendBadRequestError("unsupported_grant_type", "Grant type is not supported.");
        return false;
    }

    if (!req.authorization || !req.authorization.basic) {
        sendBadRequestError("invalid_request", "Must include a basic access authentication header.");
        return false;
    }

    if (_.has(req.body, "scope")) {
        if (typeof req.body.scope !== "string") {
            sendBadRequestError("invalid_request", "Must specify a space-delimited string for the scope field.");
            return false;
        }
    }

    return true;
};
