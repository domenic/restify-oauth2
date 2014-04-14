"use strict";

var _ = require("underscore");
var crypto = require("crypto");

var database = {
    clients: {
        officialApiClient: { secret: "C0FFEE" },
        unofficialClient: { secret: "DECAF" }
    },
    users: {
        AzureDiamond: { password: "hunter2" },
        Cthon98: { password: "*********" }
    },
    tokensToUsernames: {}
};

function generateToken(data) {
    var random = Math.floor(Math.random() * 100001);
    var timestamp = (new Date()).getTime();
    var sha256 = crypto.createHmac("sha256", random + "WOO" + timestamp);

    return sha256.update(data).digest("base64");
}

exports.validateClient = function (credentials, req, cb) {
    // Call back with `true` to signal that the client is valid, and `false` otherwise.
    // Call back with an error if you encounter an internal server error situation while trying to validate.

    var isValid = _.has(database.clients, credentials.clientId) &&
                  database.clients[credentials.clientId].secret === credentials.clientSecret;
    cb(null, isValid);
};

exports.grantUserToken = function (credentials, req, cb) {
    var isValid = _.has(database.users, credentials.username) &&
                  database.users[credentials.username].password === credentials.password;
    if (isValid) {
        // If the user authenticates, generate a token for them and store it so `exports.authenticateToken` below
        // can look it up later.

        var token = generateToken(credentials.username + ":" + credentials.password);
        database.tokensToUsernames[token] = credentials.username;

        // Call back with the token so Restify-OAuth2 can pass it on to the client.
        return cb(null, token);
    }

    // Call back with `false` to signal the username/password combination did not authenticate.
    // Calling back with an error would be reserved for internal server error situations.
    cb(null, false);
};

exports.authenticateToken = function (token, req, cb) {
    if (_.has(database.tokensToUsernames, token)) {
        // If the token authenticates, call back with the corresponding username. Restify-OAuth2 will put it in the
        // request's `username` property.
        var username = database.tokensToUsernames[token];
        return cb(null, username);
    }

    // If the token does not authenticate, call back with `false` to signal that.
    // Calling back with an error would be reserved for internal server error situations.
    cb(null, false);
};
