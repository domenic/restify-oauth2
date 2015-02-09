"use strict";

var _ = require("underscore");
var crypto = require("crypto");

var database = {
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

exports.validateClient = "allow public clients";

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
        // If the token authenticates, set the corresponding property on the request, and call back with `true`.
        // The routes can now use these properties to check if the request is authorized and authenticated.
        req.username = database.tokensToUsernames[token];
        return cb(null, true);
    }

    // If the token does not authenticate, call back with `false` to signal that.
    // Calling back with an error would be reserved for internal server error situations.
    cb(null, false);
};
