"use strict";

var _ = require("underscore");
var makeOAuthError = require("./makeOAuthError");

module.exports = function validateGrantTokenRequest(grantType, req, next) {
    function sendBadRequestError(type, description) {
      next(makeOAuthError(type, description));
    }

    if (!req.body || typeof req.body !== "object") {
        sendBadRequestError("InvalidRequest", "Must supply a body.");
        return false;
    }

    if (!_.has(req.body, "grant_type")) {
        sendBadRequestError("InvalidRequest", "Must specify grant_type field.");
        return false;
    }

    if (req.body.grant_type !== grantType) {
        sendBadRequestError("UnsupportedGrantType", "Only grant_type=" + grantType + " is supported.");
        return false;
    }

    if (!req.authorization || !req.authorization.basic) {
        sendBadRequestError("InvalidRequest", "Must include a basic access authentication header.");
        return false;
    }

    if (_.has(req.body, "scope")) {
        if (typeof req.body.scope !== "string") {
            sendBadRequestError("InvalidRequest", "Must specify a space-delimited string for the scope field.");
            return false;
        }
    }

    return true;
};
