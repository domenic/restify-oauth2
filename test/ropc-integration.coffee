"use strict"

apiEasy = require("api-easy")
require("chai").should()

require("../examples/ropc/server") # starts the server

[clientKey, clientSecret] = ["officialApiClient", "C0FFEE"]
[username, password] = ["AzureDiamond", "hunter2"]
basicAuth = (new Buffer("#{clientKey}:#{clientSecret}")).toString("base64")

# State modified by some tests, and then used by later ones
accessToken = null

suite = apiEasy.describe("Restify–OAuth2 Example Server")

suite.before "Set token if available", (outgoing) ->
    if accessToken
        outgoing.headers.Authorization = "Bearer #{accessToken}"

    return outgoing

suite
    .use("localhost", 8080) # TODO: https!!
    .get("/secret")
        .expect(401)
        .expect("should respond with WWW-Authenticate and Link headers", (err, res, body) ->
            expectedLink = '</token>; rel="oauth2-token"; grant-types="password"; token-types="bearer"'

            res.headers.should.have.property("www-authenticate").that.equals('Bearer realm="Who goes there?"')
            res.headers.should.have.property("link").that.equals(expectedLink)
        )
    .next()
    .path("/basicauth")
        .discuss("with no basic auth or token")
        .get()
            .expect(401)
            .expect("should respond with WWW-Authenticate and Link headers", (err, res, body) ->
                expectedLink = '</token>; rel="oauth2-token"; grant-types="password"; token-types="bearer"'

                res.headers.should.have.property("www-authenticate").that.equals('Bearer realm="Who goes there?"')
                res.headers.should.have.property("link").that.equals(expectedLink)
            )
        .undiscuss()
        .discuss("with valid client basic auth")
            .setHeader("Authorization", "Basic #{basicAuth}")
            .setHeader("Content-Type", "application/json")
            .get()
                .expect(200)
                .expect("should respond successfully", (err, res, body) =>
                    result = JSON.parse(body)

                    result.should.have.property("message", "valid client basic auth")
                )
        .undiscuss()
    .unpath()
    .next()
    .get("/")
        .expect(
            200,
            _links:
                self: href: "/"
                "http://rel.example.com/public": href: "/public"
                "oauth2-token":
                    href: "/token"
                    "grant-types": "password"
                    "token-types": "bearer"
        )
    .next()
    .get("/public")
        .expect(200)
    .next()
    .path("/token")
        .discuss("with valid client credentials")
            .setHeader("Authorization", "Basic #{basicAuth}")
            .setHeader("Content-Type", "application/json")
            .discuss("and valid user credentials")
                .post({ grant_type: "password", username, password })
                    .expect(200)
                    .expect("should respond with the token", (err, res, body) ->
                        result = JSON.parse(body)

                        result.should.have.property("token_type", "Bearer")
                        result.should.have.property("access_token")

                        accessToken = result.access_token
                    )
            .undiscuss()
            .discuss("but invalid user credentials")
                .post({ grant_type: "password", username: "blargh", password: "asdf" })
                    .expect(401)
                    .expect("should respond with error: invalid_grant", (err, res, body) ->
                        JSON.parse(body).should.have.property("error", "invalid_grant")
                    )
            .undiscuss()
        .undiscuss()
        .discuss("with invalid client credentials")
            .setHeader("Authorization", "Basic MTIzOjQ1Ng==")
            .setHeader("Content-Type", "application/json")
            .post({ grant_type: "password", username, password })
                .expect(401)
                .expect("should respond with error: invalid_client", (err, res, body) ->
                    JSON.parse(body).should.have.property("error", "invalid_client")
                )
        .undiscuss()
    .unpath().next()
    .get("/")
        .expect(
            200,
            _links:
                self: href: "/"
                "http://rel.example.com/public": href: "/public"
                "http://rel.example.com/secret": href: "/secret"
        )
    .get("/secret")
        .expect(200)
    .next()
    .get("/basicauth")
        .expect(200)
        .expect("should respond successfully", (err, res, body) =>
            result = JSON.parse(body)

            result.should.have.property("message", "valid oauth token")
        )
    .next()
    .get("/public")
        .expect(200)
    .next()
.export(module)
