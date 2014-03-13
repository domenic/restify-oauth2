    "use strict";

var _ = require("underscore");
var crypto = require("crypto");

var database = {
    clients: {
        officialApiClient: { secret: "C0FFEE", scopesGranted: ["one:read", "two"] },
        unofficialClient: { secret: "DECAF" }
    },
    tokensToClientIds: {},
    tokenScopes: {}
};

function generateToken(data) {
    var random = Math.floor(Math.random() * 100001);
    var timestamp = (new Date()).getTime();
    var sha256 = crypto.createHmac("sha256", random + "WOO" + timestamp);

    return sha256.update(data).digest("base64");
}

exports.grantClientToken = function (clientId, clientSecret, cb) {
    var isValid = _.has(database.clients, clientId) && database.clients[clientId].secret === clientSecret;
    if (isValid) {
        // If the client authenticates, generate a token for them and store it so `exports.authenticateToken` below
        // can look it up later.

        var token = generateToken(clientId + ":" + clientSecret);
        database.tokensToClientIds[token] = clientId;

        // Call back with the token so Restify-OAuth2 can pass it on to the client.
        return cb(null, token);
    }

    // Call back with `false` to signal the username/password combination did not authenticate.
    // Calling back with an error would be reserved for internal server error situations.
    cb(null, false);
};

exports.grantScopes = function (clientId, clientSecret, token, scopesRequested, cb) {
    //in this example, we will allow at most only the scopes defined in the database
    var scopesGranted = _.intersection(scopesRequested, database.clients[clientId].scopesGranted);
    database.tokenScopes[token] = scopesGranted;

    //just for the sake of the demo, if you authorize all the scopesRequested, you can just pass `true` to the callback
    if (scopesGranted === scopesRequested) {
        return cb(null, true);
    }

    cb(null, scopesGranted);
};

exports.authenticateToken = function (token, cb) {
    if (_.has(database.tokensToClientIds, token)) {
        // If the token authenticates, call back with the corresponding client ID. Restify-OAuth2 will put it in the
        // request's `clientId` property.
        var username = database.tokensToClientIds[token];
        var scopes_granted = database.tokenScopes[token];

        return cb(null, username, scopes_granted);
    }

    // If the token does not authenticate, call back with `false` to signal that.
    // Calling back with an error would be reserved for internal server error situations.
    cb(null, false);
};
