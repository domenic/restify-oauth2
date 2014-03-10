"use strict";

var restify = require("restify");

module.exports = function makeOAuthError(errorClass, errorType, errorDescription) {
    var body = { error: errorType, error_description: errorDescription };
    return new restify[errorClass + "Error"]({ message: errorDescription, body: body });
};
