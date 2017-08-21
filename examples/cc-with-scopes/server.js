"use strict";

var restify = require("restify");
var restifyOAuth2 = require("../..");
var hooks = require("./hooks");

// NB: we're using [HAL](http://stateless.co/hal_specification.html) here to communicate RESTful links among our
// resources, but you could use any JSON linking format, or XML, or even just Link headers.

var server = restify.createServer({
    name: "Example Restify-OAuth2 Client Credentials Server",
    version: require("../../package.json").version,
    formatters: {
        "application/hal+json": function (req, res, body, cb) {
            return res.formatters["application/json"](req, res, body, cb);
        }
    }
});

var RESOURCES = Object.freeze({
    INITIAL: "/",
    TOKEN: "/token",
    PUBLIC: "/public",
    SECRET: "/secret",
    SCOPED: "/scoped"
});

server.use(restify.plugins.authorizationParser());
server.use(restify.plugins.bodyParser({ mapParams: false }));
restifyOAuth2.cc(server, { tokenEndpoint: RESOURCES.TOKEN, hooks: hooks });



server.get(RESOURCES.INITIAL, function (req, res) {
    var response = {
        _links: {
            self: { href: RESOURCES.INITIAL },
            "http://rel.example.com/public": { href: RESOURCES.PUBLIC }
        }
    };

    if (req.clientId) {
        response._links["http://rel.example.com/secret"] = { href: RESOURCES.SECRET };

        if (req.scopesGranted.indexOf("two") !== -1) {
            response._links["http://rel.example.com/scoped"] = { href: RESOURCES.SCOPED };
        }
    } else {
        response._links["oauth2-token"] = {
            href: RESOURCES.TOKEN,
            "grant-types": "client_credentials",
            "token-types": "bearer"
        };
    }

    res.contentType = "application/hal+json";
    res.send(response);
});

server.get(RESOURCES.PUBLIC, function (req, res) {
    res.send({
        "public resource": "is public",
        "it's not even": "a linked HAL resource",
        "just plain": "application/json",
        "personalized message": req.clientId ? "hi, " + req.clientId + "!" : "hello stranger!"
    });
});

server.get(RESOURCES.SECRET, function (req, res) {
    if (!req.clientId) {
        return res.sendUnauthenticated();
    }

    var response = {
        "clients with a token": "have access to this secret data",
        _links: {
            self: { href: RESOURCES.SECRET },
            parent: { href: RESOURCES.INITIAL }
        }
    };

    res.contentType = "application/hal+json";
    res.send(response);
});

server.get(RESOURCES.SCOPED, function (req, res) {
    if (!req.clientId) {
        return res.sendUnauthenticated();
    }

    if (req.scopesGranted.indexOf("two") === -1) {
        return res.sendUnauthorized();
    }

    var response = {
        "clients with a token that is scoped correctly": "have access to this scoped data",
        _links: {
            self: { href: RESOURCES.SCOPED },
            parent: { href: RESOURCES.INITIAL }
        }
    };

    res.contentType = "application/hal+json";
    res.send(response);
});

server.post('/close', function(req, res){
    res.send(200);
    server.close();
});

server.listen(8080);
