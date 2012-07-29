"use strict";

exports.hasBearerToken = function (req) {
    return req.authorization && req.authorization.scheme === "Bearer" && req.authorization.credentials.length > 0;
};

exports.getBearerToken = function (req) {
    return exports.hasBearerToken(req) ? req.authorization.credentials : null;
};
