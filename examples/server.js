"use strict";

var restify = require("restify");
var restifyOAuth2 = require("..");
var hooks = require("./hooks");

// NB: we're using [HAL](http://stateless.co/hal_specification.html) here to communicate RESTful links among our
// resources, but you could use any JSON linking format, or XML, or even just Link headers.

var server = restify.createServer({
    name: "Example Restify-OAuth2 Server",
    version: require("../package.json").version,
    formatters: {
        "application/hal+json": function (req, res, body) {
            return res.formatters["application/json"](req, res, body);
        }
    }
});

var RESOURCES = Object.freeze({
    INITIAL: "/",
    TOKEN: "/token",
    PUBLIC: "/public",
    SECRET: "/secret"
});

var oauth2Plugin = restifyOAuth2({
    tokenEndpoint: RESOURCES.TOKEN,
    // Checks that this API client is authorized to use your API, and has the correct secret
    validateClient: hooks.validateClient,
    // Checks that the API client is authenticating on behalf of a real user with correct credentials, and if so,
    // gives a token for that user
    grantToken: hooks.grantToken,
    // Checks that an incoming token is valid, and if so, maps it to a username
    authenticateToken: hooks.authenticateToken,
    // Checks that a given request requires an access token or not.
    requiresTokenPredicate: function (req) {
        return req.path !== "/public" && req.path !== "/";
    }
});

server.use(restify.authorizationParser());
server.use(restify.bodyParser({ mapParams: false }));
server.use(oauth2Plugin);



server.get(RESOURCES.INITIAL, function (req, res, next) {
    var response = {
        _links: {
            self: { href: RESOURCES.INITIAL },
            "http://rel.example.com/public": { href: RESOURCES.PUBLIC }
        }
    };

    if (req.username) {
        response._links["http://rel.example.com/secret"] = { href: RESOURCES.SECRET };
    } else {
        response._links["oauth2-token"] = { href: RESOURCES.TOKEN };
    }

    res.contentType = "application/hal+json";
    res.send(response);
});

server.get(RESOURCES.PUBLIC, function (req, res, next) {
    res.send({
        "public resource": "is public",
        "it's not even": "a linked HAL resource",
        "just plain": "application/json"
    });
});

server.get(RESOURCES.SECRET, function (req, res, next) {
    var response = {
        "anyone with a token": "has access to this",
        _links: {
            self: { href: RESOURCES.SECRET },
            parent: { href: RESOURCES.INITIAL }
        }
    };

    res.contentType = "application/hal+json";
    res.send(response);
});

server.listen(8080);
