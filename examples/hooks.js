"use strict";

var _ = require("underscore");
var crypto = require("crypto");

function generateToken(data) {
    var random = Math.floor(Math.random() * 100001);
    var timestamp = (new Date()).getTime();
    var sha256 = crypto.createHmac("sha256", random + "WOO" + timestamp);

    return sha256.update(data).digest("base64");
}

var tokenToUsernameMap = {};

exports.validateClient = function (clientId, clientSecret, cb) {
    // Call back with `true` to signal that the client is valid, and `false` otherwise.
    // Call back with an error if you encounter an internal server error situation while trying to validate.
    cb(null, clientId === "legit" && clientSecret === "C0FFEE");
};

exports.grantToken = function (username, password, cb) {
    if ((username === "AzureDiamond" && password === "hunter2") ||
        (username === "Cthon98" && password === "*********")) {
        // If the user authenticates, generate a token for them and store it so `exports.authenticateToken` below
        // can look it up later.

        var token = generateToken(username + ":" + password);
        tokenToUsernameMap[token] = username;

        // Call back with the token so Restify-OAuth2 can pass it on to the client.
        return cb(null, token);
    }

    // Call back with `false` to signal the username/password combination did not authenticate.
    // Calling back with an error would be reserved for internal server error situations.
    cb(null, false);
};

exports.authenticateToken = function (token, cb) {
    if (_.has(tokenToUsernameMap, token)) {
        // If the token authenticates, call back with the corresponding username. Restify-OAuth2 will put it in the
        // request's `username` property.
        var username = tokenToUsernameMap[token];
        return cb(null, username);
    }

    // If the token does not authenticate, call back with `false` to signal that.
    // Calling back with an error would be reserved for internal server error situations.
    cb(null, false);
};
