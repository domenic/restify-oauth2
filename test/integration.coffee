"use strict"

apiEasy = require("api-easy")
require("chai").should()

require("../examples/server") # starts the server

[clientKey, clientSecret] = ["officialApiClient", "C0FFEE"]
[username, password] = ["AzureDiamond", "hunter2"]

basicAuth = (new Buffer("#{clientKey}:#{clientSecret}")).toString("base64")

# State modified by some tests, and then used by later ones
accessToken = null

suite = apiEasy.describe("Get a token")

suite.before "Set token if available", (outgoing) ->
    if accessToken
        outgoing.headers.Authorization = "Bearer #{accessToken}"

    return outgoing

suite
    .use("localhost", 8080) # TODO: https!!
    .get("/")
        .expect(200)
        .expect("should respond with self, public, and oauth2-token links", (err, res, body) ->
            result = JSON.parse(body)

            result.should.have.property("_links")
            result._links.should.deep.equal(
                "self": href: "/"
                "http://rel.example.com/public": href: "/public"
                "oauth2-token": href: "/token"
            )
        )
    .path("/token")
        .discuss("with valid client credentials")
            .setHeader("Authorization", "Basic #{basicAuth}")
            .setHeader("Content-Type", "application/json")
            .post({ grant_type: "password", username, password })
                .expect(200)
                .expect("should respond with the token", (err, res, body) ->
                    result = JSON.parse(body)

                    result.should.have.property("token_type", "Bearer")
                    result.should.have.property("access_token")

                    accessToken = result.access_token
                )
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
    .path("/")
        .get()
            .expect(
                200,
                _links:
                    self: href: "/"
                    "http://rel.example.com/public": href: "/public"
                    "http://rel.example.com/secret": href: "/secret"
            )
.export(module)
