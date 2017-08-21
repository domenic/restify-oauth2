"use strict";

var restify = require("restify");
var errs = require("restify-errors");

errs.makeConstructor('InvalidRequestError', {
    statusCode: 400
});

errs.makeConstructor('InvalidScopeError', {
    statusCode: 400
});

errs.makeConstructor('UnsupportedGrantTypeError', {
    statusCode: 400
});

errs.makeConstructor('InvalidClientError', {
    statusCode: 401
});

errs.makeConstructor('InvalidGrantError', {
    statusCode: 401
});

module.exports = function makeOAuthError(errorClass, errorDescription) {
    return new errs[errorClass + "Error"]({ message: errorDescription });
};
