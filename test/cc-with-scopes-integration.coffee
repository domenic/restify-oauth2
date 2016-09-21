"use strict"

apiEasy = require("api-easy")
require("chai").should()

require("../examples/cc-with-scopes/server") # starts the server

[unofficialClientKey, unofficialClientSecret] = ["unofficialClient", "DECAF"]
unofficialBasicAuth = (new Buffer("#{unofficialClientKey}:#{unofficialClientSecret}")).toString("base64")

[officialClientKey, officialClientSecret] = ["officialApiClient", "C0FFEE"]
officialBasicAuth = (new Buffer("#{officialClientKey}:#{officialClientSecret}")).toString("base64")


# State modified by some tests, and then used by later ones
accessToken = null


suite = apiEasy.describe("Restify–OAuth2 Example Server")

suite.before "Set token if available", (outgoing) ->
    if accessToken and outgoing.uri.indexOf("/token") is -1
        outgoing.headers.Authorization = "Bearer #{accessToken}"

    return outgoing

suite
    .use("localhost", 8080) # TODO: https!!
    .get("/secret")
        .expect(401)
        .expect("should respond with WWW-Authenticate and Link headers", (err, res, body) ->
            expectedLink = '</token>; rel="oauth2-token"; grant-types="client_credentials"; token-types="bearer"'

            res.headers.should.have.property("www-authenticate").that.equals('Bearer realm="Who goes there?"')
            res.headers.should.have.property("link").that.equals(expectedLink)
        )
    .next()
    .get("/")
        .expect(
            200,
            _links:
                self: href: "/"
                "http://rel.example.com/public": href: "/public"
                "oauth2-token":
                    href: "/token"
                    "grant-types": "client_credentials"
                    "token-types": "bearer"
        )
    .next()
    .get("/public")
        .expect(200)
    .next()
    .path("/token")
        .discuss("with client credentials not authorized to access scoped resources")
            .setHeader("Authorization", "Basic #{unofficialBasicAuth}")
            .setHeader("Content-Type", "application/json")
            .post({ grant_type: "client_credentials" })
                .expect(200)
                .expect("should respond with the token but no scopes", (err, res, body) ->
                    result = JSON.parse(body)

                    result.should.have.property("token_type", "Bearer")
                    result.should.have.property("access_token")
                    result.should.not.have.property("scope")
                )
        .undiscuss()
        .discuss("with client credentials authorized to access scoped resources, only requesting some scopes")
            .setHeader("Authorization", "Basic #{officialBasicAuth}")
            .setHeader("Content-Type", "application/json")
            .post({ grant_type: "client_credentials", scope: "one:read abc" })
                .expect(200)
                .expect("should respond with the token and all valid scopes requested", (err, res, body) ->
                    result = JSON.parse(body)

                    result.should.have.property("token_type", "Bearer")
                    result.should.have.property("access_token")
                    result.should.have.property("scope", "one:read")

                    accessToken = result.access_token
                )
        .undiscuss()
        .discuss("with invalid client credentials")
            .setHeader("Authorization", "Basic MTIzOjQ1Ng==")
            .setHeader("Content-Type", "application/json")
            .post({ grant_type: "client_credentials" })
                .expect(401)
                .expect("should respond with error: invalid_client", (err, res, body) ->
                    JSON.parse(body).should.have.property("error", "invalid_client")
                )
        .undiscuss()
    .unpath().next()
    .discuss("using the token without access to scope two")
        .get("/")
            .expect(
                200,
                _links:
                    self: href: "/"
                    "http://rel.example.com/public": href: "/public"
                    "http://rel.example.com/secret": href: "/secret"
            )
        .get("/public")
            .expect(200)
        .next()
        .get("/secret")
            .expect(200)
        .next()
        .get("/scoped")
            .expect(403)
        .next()
    .undiscuss()
    .path("/token")
        .discuss("with client credentials authorized to access scoped resources, requesting all scopes")
            .setHeader("Authorization", "Basic #{officialBasicAuth}")
            .setHeader("Content-Type", "application/json")
            .post({ grant_type: "client_credentials", scope: "one:read two 123" })
                .expect(200)
                .expect("should respond with the token and all valid scopes", (err, res, body) ->
                    result = JSON.parse(body)

                    result.should.have.property("token_type", "Bearer")
                    result.should.have.property("access_token")
                    result.should.have.property("scope", "one:read two")

                    accessToken = result.access_token
                )
        .undiscuss()
    .unpath().next()
    .discuss("using the token with access to scope two")
        .get("/")
            .expect(
                200,
                _links:
                    self: href: "/"
                    "http://rel.example.com/public": href: "/public"
                    "http://rel.example.com/secret": href: "/secret"
                    "http://rel.example.com/scoped": href: "/scoped"
            )
        .get("/public")
            .expect(200)
        .next()
        .get("/secret")
            .expect(200)
        .next()
        .get("/scoped")
            .expect(200)
        .next()
    .undiscuss()
    .discuss('test cleanup')
        .post("/close")
            .expect(200)
                .next()
.export(module)
