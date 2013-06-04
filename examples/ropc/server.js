"use strict";

var restify = require("restify");
var restifyOAuth2 = require("../..");
var hooks = require("./hooks");

// NB: we're using [HAL](http://stateless.co/hal_specification.html) here to communicate RESTful links among our
// resources, but you could use any JSON linking format, or XML, or even just Link headers.

var server = restify.createServer({
    name: "Example Restify-OAuth2 Resource Owner Password Credentials Server",
    version: require("../../package.json").version,
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
    SECRET: "/secret",
    BASICAUTH: "/basicauth" //but requires some other basic auth
});

server.use(restify.authorizationParser());
server.use(restify.bodyParser({ mapParams: false }));
restifyOAuth2.ropc(server, { tokenEndpoint: RESOURCES.TOKEN, hooks: hooks });



server.get(RESOURCES.INITIAL, function (req, res) {
    var response = {
        _links: {
            self: { href: RESOURCES.INITIAL },
            "http://rel.example.com/public": { href: RESOURCES.PUBLIC }
        }
    };

    if (req.username) {
        response._links["http://rel.example.com/secret"] = { href: RESOURCES.SECRET };
    } else {
        response._links["oauth2-token"] = {
            href: RESOURCES.TOKEN,
            "grant-types": "password",
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
        "personalized message": req.username ? "hi, " + req.username + "!" : "hello stranger!"
    });
});

server.get(RESOURCES.SECRET, function (req, res) {
    if (!req.username) {
        return res.sendUnauthorized();
    }

    var response = {
        "users with a token": "have access to this secret data",
        _links: {
            self: { href: RESOURCES.SECRET },
            parent: { href: RESOURCES.INITIAL }
        }
    };

    res.contentType = "application/hal+json";
    res.send(response);
});

/*
    This is an endpoint that requires a valid client through
    basic auth OR a valid oauth token (such as a resource
    availible to a client or a verified user)
 */
server.get(RESOURCES.BASICAUTH, function (req, res) {
    
    var response;

    if (!req.username) {

        if (req.authorization.scheme === "Basic") {

            hooks.validateClient(req.authorization.basic.username, req.authorization.basic.password, function (err, valid) {
                if (valid) {
                    response = {
                        "message" : "valid client basic auth"
                    };
                } else {
                    return res.sendUnauthorized();
                }
            });
            
        } else {
            return res.sendUnauthorized();
        }


    } else {
        response = {
            "message": "valid oauth token"
        };
    }

    res.contentType = "application/hal+json";
    res.send(response);

});

server.listen(8080);
