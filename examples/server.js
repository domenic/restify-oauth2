var restify = require("restify");
var restifyOauth2 = require("..");
var backend = require("./fakeBackend");

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
    SECRET: "/secret",
    SUPER_SECRET: "/secret/super-secret"
});

var oauth2Plugin = restifyOauth2({
    tokenEndpoint: RESOURCES.TOKEN,
    // Checks that this API client is authorized to use your API, and has the correct secret
    validateClient: backend.validateClient,
    // Checks that the API client is authenticating on behalf of a real user with correct credentials, and if so,
    // gives a token for that user
    grantToken: backend.grantToken,
    // Checks that an incoming token is valid, and if so, maps it to a username
    authenticateToken: backend.authenticateToken,
    // Checks that we need to perform authentication on a given request
    requiresTokenPredicate: function (req) {
        return req.path !== "/public";
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
            self: { href: RESOURCES.SECRET }
        }
    };

    if (backend.userCanAccess(req.username, RESOURCES.SUPER_SECRET)) {
        response._links["http://rel.example.com/super-secret"] = { href: RESOURCES.SUPER_SECRET };
    }

    res.contentType = "application/hal+json";
    res.send(response);
});

server.get(RESOURCES.SUPER_SECRET, function (req, res, next) {
    if (!backend.userCanAccess(req.username, RESOURCES.SUPER_SECRET)) {
        return next(new restify.ForbiddenError("You're not cool enough to access the super-secret resource!"));
    }

    res.contentType = "application/hal+json";
    res.send({
        "only special people": "have access to this",
        _links: {
            self: { href: RESOURCES.SUPER_SECRET },
            parent: { href: RESOURCES.SECRET }
        }
    });
});
