"use strict";

var restify = require("restify");
var _ = require("underscore");

module.exports = function grantToken(req, res, next, options) {
    function sendOAuthError(errorClass, errorType, errorDescription) {
        var body = { error: errorType, error_description: errorDescription };
        var error = new restify[errorClass + "Error"]({ message: errorDescription, body: body });
        next(error);
    }

    function sendBadRequestError(type, description) {
        sendOAuthError("BadRequest", type, description);
    }

    function sendUnauthorizedError(description) {
        res.header("WWW-Authenticate", "Basic realm=\"" + description + "\"");
        sendOAuthError("Unauthorized", "invalid_client", description);
    }


    var clientId = null;
    var clientSecret = null;
    
    if (!req.body || typeof req.body !== "object") {
        return sendBadRequestError("invalid_request", "Must supply a body.");
    }

    if (!_.has(req.body, "grant_type")) {
        return sendBadRequestError("invalid_request", "Must specify grant_type field.");
    }

    if (req.body.grant_type !== "client_credentials") {
        return sendBadRequestError("unsupported_grant_type", "Only grant_type=client_credentials is supported.");
    }

    if (_.has(req.body, "client_id") && _.has(req.body, "client_secret")) {
        clientId = req.body.client_id;
        clientSecret = req.body.client_secret;
    }
    else if (req.authorization && req.authorization.basic) {
        clientId = req.authorization.basic.username;
        clientSecret = req.authorization.basic.password;        
    }
    else {
        return sendBadRequestError("invalid_request", "Must include a basic access authentication header.");
    }

    options.hooks.grantClientToken(clientId, clientSecret, function (error, token) {
        if (error) {
            return next(error);
        }

        if (!token) {
            return sendUnauthorizedError("Client ID and secret did not authenticate.");
        }

        res.send({
            access_token: token,
            token_type: "Bearer",
            expires_in: options.tokenExpirationTime
        });
    });
};
