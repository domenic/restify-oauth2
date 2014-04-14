"use strict";

var _ = require("underscore");
var crypto = require("crypto");

var database = {
    clients: {
        officialApiClient: { secret: "C0FFEE", scopesGranted: ["one:read", "two"] },
        unofficialClient: { secret: "DECAF" }
    },
    tokensToClientIds: {},
    tokensToScopes: {}
};

function generateToken(data) {
    var random = Math.floor(Math.random() * 100001);
    var timestamp = (new Date()).getTime();
    var sha256 = crypto.createHmac("sha256", random + "WOO" + timestamp);

    return sha256.update(data).digest("base64");
}

exports.grantClientToken = function (credentials, req, cb) {
    var isValid = _.has(database.clients, credentials.clientId) &&
                  database.clients[credentials.clientId].secret === credentials.clientSecret;
    if (isValid) {
        // If the client authenticates, generate a token for them and store it so `exports.authenticateToken` below
        // can look it up later.

        var token = generateToken(credentials.clientId + ":" + credentials.clientSecret);
        database.tokensToClientIds[token] = credentials.clientId;

        // Call back with the token so Restify-OAuth2 can pass it on to the client.
        return cb(null, token);
    }

    // Call back with `false` to signal the username/password combination did not authenticate.
    // Calling back with an error would be reserved for internal server error situations.
    cb(null, false);
};

exports.grantScopes = function (credentials, scopesRequested, req, cb) {
    // In this example, we will allow at most only the scopes defined in the database. We will not give an error if
    // other scopes are requested, instead simply returning the allowed scopes.
    var scopesGranted = _.intersection(scopesRequested, database.clients[credentials.clientId].scopesGranted);
    database.tokensToScopes[credentials.token] = scopesGranted;

    // Call back with the actual set of scopes granted.
    cb(null, scopesGranted);

    // We could also call back with `false` to signal that the requested scopes are invalid, unknown, or mismatched with
    // the given credentials. Or we could call back with an error for an internal server error situation.
};

exports.authenticateToken = function (token, req, cb) {
    if (_.has(database.tokensToClientIds, token)) {
        // If the token authenticates, set the corresponding properties on the request, and call back with `true`.
        // The routes can now use these properties to check if the request is authorized and authenticated.
        req.clientId = database.tokensToClientIds[token];
        req.scopesGranted = database.tokensToScopes[token];
        return cb(null, true);
    }

    // If the token does not authenticate, call back with `false` to signal that.
    // Calling back with an error would be reserved for internal server error situations.
    cb(null, false);
};
