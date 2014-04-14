"use strict"

require("chai").use(require("sinon-chai"))
sinon = require("sinon")
should = require("chai").should()
Assertion = require("chai").Assertion
restify = require("restify")
restifyOAuth2 = require("..")

tokenEndpoint = "/token-uri"
wwwAuthenticateRealm = "Realm string"
tokenExpirationTime = 12345

Assertion.addMethod("unauthorized", (message, options) ->
    expectedLink = '<' + tokenEndpoint + '>; rel="oauth2-token"; grant-types="client_credentials"; token-types="bearer"'
    expectedWwwAuthenticate = 'Bearer realm="' +  wwwAuthenticateRealm + '"'

    if not options?.noWwwAuthenticateErrors
        expectedWwwAuthenticate += ', error="invalid_token", error_description="' + message + '"'

    spyToTest = if options?.send then @_obj.send else @_obj.nextSpy

    @_obj.header.should.have.been.calledWith("WWW-Authenticate", expectedWwwAuthenticate)
    @_obj.header.should.have.been.calledWith("Link", expectedLink)
    spyToTest.should.have.been.calledOnce
    spyToTest.should.have.been.calledWith(sinon.match.instanceOf(restify.UnauthorizedError))
    spyToTest.should.have.been.calledWith(sinon.match.has("message", sinon.match(message)))
)

Assertion.addMethod("bad", (message) ->
    expectedLink = '<' + tokenEndpoint + '>; rel="oauth2-token"; grant-types="client_credentials"; token-types="bearer"'
    expectedWwwAuthenticate = 'Bearer realm="' +  wwwAuthenticateRealm + '", error="invalid_request", ' +
                              'error_description="' + message + '"'

    @_obj.header.should.have.been.calledWith("WWW-Authenticate", expectedWwwAuthenticate)
    @_obj.header.should.have.been.calledWith("Link", expectedLink)
    @_obj.nextSpy.should.have.been.calledOnce
    @_obj.nextSpy.should.have.been.calledWith(sinon.match.instanceOf(restify.BadRequestError))
    @_obj.nextSpy.should.have.been.calledWith(sinon.match.has("message", sinon.match(message)))
)

Assertion.addMethod("oauthError", (errorClass, errorType, errorDescription) ->
    desiredBody = { error: errorType, error_description: errorDescription }
    @_obj.nextSpy.should.have.been.calledOnce
    @_obj.nextSpy.should.have.been.calledWith(sinon.match.instanceOf(restify[errorClass + "Error"]))
    @_obj.nextSpy.should.have.been.calledWith(sinon.match.has("message", errorDescription))
    @_obj.nextSpy.should.have.been.calledWith(sinon.match.has("body", desiredBody))
)

beforeEach ->
    @req = { pause: sinon.spy(), resume: sinon.spy(), username: "anonymous", authorization: {} }
    @res = { header: sinon.spy(), send: sinon.spy() }
    @tokenNext = sinon.spy()
    @pluginNext = sinon.spy()

    @server =
        post: sinon.spy((path, handler) => @postToTokenEndpoint = => handler(@req, @res, @tokenNext))
        use: (plugin) => plugin(@req, @res, @pluginNext)

    @authenticateToken = sinon.stub()
    @grantClientToken = sinon.stub()

    options = {
        tokenEndpoint
        wwwAuthenticateRealm
        tokenExpirationTime
        hooks: {
            @authenticateToken
            @grantClientToken
        }
    }

    @doIt = => restifyOAuth2.cc(@server, options)

describe "Client Credentials flow", ->
    it "should set up the token endpoint", ->
        @doIt()

        @server.post.should.have.been.calledWith(tokenEndpoint)

    describe "For POST requests to the token endpoint", ->
        beforeEach ->
            @req.method = "POST"
            @req.path = => tokenEndpoint
            @res.nextSpy = @tokenNext

            baseDoIt = @doIt
            @doIt = =>
                baseDoIt()
                @postToTokenEndpoint()

        describe "with a body", ->
            beforeEach -> @req.body = {}

            describe "that has grant_type=client_credentials", ->
                beforeEach -> @req.body.grant_type = "client_credentials"

                describe "with a basic access authentication header", ->
                    beforeEach ->
                        [@clientId, @clientSecret] = ["clientId123", "clientSecret456"]
                        @req.authorization =
                            scheme: "Basic"
                            basic: { username: @clientId, password: @clientSecret }

                    it "should use the client ID and secret  values to grant a token", ->
                        @doIt()

                        @grantClientToken.should.have.been.calledWith({ @clientId, @clientSecret }, @req)

                    describe "when `grantClientToken` calls back with a token", ->
                        beforeEach ->
                            @token = "token123"
                            @grantClientToken.yields(null, @token)

                        it "should send a response with access_token, token_type, and expires_in set", ->
                            @doIt()

                            @res.send.should.have.been.calledWith(
                                access_token: @token,
                                token_type: "Bearer"
                                expires_in: tokenExpirationTime
                            )
                        it "should call `next`", ->
                            @doIt()

                            @tokenNext.should.have.been.calledWithExactly()

                    describe "when `grantClientToken` calls back with `false`", ->
                        beforeEach -> @grantClientToken.yields(null, false)

                        it "should send a 401 response with error_type=invalid_client", ->
                            @doIt()

                            @res.should.be.an.oauthError("Unauthorized", "invalid_client",
                                                         "Client ID and secret did not authenticate.")

                    describe "when `grantClientToken` calls back with `null`", ->
                        beforeEach -> @grantClientToken.yields(null, null)

                        it "should send a 401 response with error_type=invalid_client", ->
                            @doIt()

                            @res.should.be.an.oauthError("Unauthorized", "invalid_client",
                                                         "Client ID and secret did not authenticate.")

                    describe "when `grantClientToken` calls back with an error", ->
                        beforeEach ->
                            @error = new Error("Bad things happened, internally.")
                            @grantClientToken.yields(@error)

                        it "should call `next` with that error", ->
                            @doIt()

                            @tokenNext.should.have.been.calledWithExactly(@error)

                describe "without an authorization header", ->
                    it "should send a 400 response with error_type=invalid_request", ->
                        @doIt()

                        @res.should.be.an.oauthError("BadRequest", "invalid_request",
                                                     "Must include a basic access authentication header.")

                    it "should not call the `grantClientToken` hook", ->
                        @doIt()

                        @grantClientToken.should.not.have.been.called

                describe "with an authorization header that does not contain basic access credentials", ->
                    beforeEach ->
                        @req.authorization =
                            scheme: "Bearer"
                            credentials: "asdf"

                    it "should send a 400 response with error_type=invalid_request", ->
                        @doIt()

                        @res.should.be.an.oauthError("BadRequest", "invalid_request",
                                                     "Must include a basic access authentication header.")

                    it "should not call the `grantClientToken` hook", ->
                        @doIt()

                        @grantClientToken.should.not.have.been.called

            describe "that has grant_type=authorization_code", ->
                beforeEach -> @req.body.grant_type = "authorization_code"

                it "should send a 400 response with error_type=unsupported_grant_type", ->
                    @doIt()

                    @res.should.be.an.oauthError("BadRequest", "unsupported_grant_type",
                                                 "Only grant_type=client_credentials is supported.")

                it "should not call the `grantClientToken` hook", ->
                    @doIt()

                    @grantClientToken.should.not.have.been.called

            describe "that has no grant_type value", ->
                it "should send a 400 response with error_type=invalid_request", ->
                    @doIt()

                    @res.should.be.an.oauthError("BadRequest", "invalid_request", "Must specify grant_type field.")

                it "should not call the `grantClientToken` hook", ->
                    @doIt()

                    @grantClientToken.should.not.have.been.called

        describe "without a body", ->
            beforeEach -> @req.body = null

            it "should send a 400 response with error_type=invalid_request", ->
                @doIt()

                @res.should.be.an.oauthError("BadRequest", "invalid_request", "Must supply a body.")

            it "should not call the `grantClientToken` hook", ->
                @doIt()

                @grantClientToken.should.not.have.been.called

        describe "without a body that has been parsed into an object", ->
            beforeEach -> @req.body = "Left as a string or buffer or something"

            it "should send a 400 response with error_type=invalid_request", ->
                @doIt()

                @res.should.be.an.oauthError("BadRequest", "invalid_request", "Must supply a body.")

            it "should not call the `grantClientToken` hook", ->
                @doIt()

                @grantClientToken.should.not.have.been.called

    describe "For other requests", ->
        beforeEach ->
            @req.path = => "/other-resource"
            @res.nextSpy = @pluginNext

        describe "with an authorization header that contains a valid bearer token", ->
            beforeEach ->
                @token = "TOKEN123"
                @req.authorization = { scheme: "Bearer", credentials: @token }

            it "should pause the request and authenticate the token", ->
                @doIt()

                @req.pause.should.have.been.called
                @authenticateToken.should.have.been.calledWith(@token)

            describe "when the `authenticateToken` calls back with a client ID", ->
                beforeEach ->
                    @clientId = "client123"
                    @authenticateToken.yields(null, @clientId)

                it "should resume the request, set the `clientId` property on the request, and call `next`", ->
                    @doIt()

                    @req.resume.should.have.been.called
                    @req.should.have.property("clientId", @clientId)
                    @pluginNext.should.have.been.calledWithExactly()

            describe "when the `authenticateToken` calls back with `false`", ->
                beforeEach -> @authenticateToken.yields(null, false)

                it "should resume the request and send a 401 response, along with WWW-Authenticate and Link headers", ->
                    @doIt()

                    @req.resume.should.have.been.called
                    @res.should.be.unauthorized(
                        "Bearer token invalid. Follow the oauth2-token link to get a valid one!"
                    )

            describe "when the `authenticateToken` calls back with a 401 error", ->
                beforeEach ->
                    @errorMessage = "The authentication failed for some reason."
                    @authenticateToken.yields(new restify.UnauthorizedError(@errorMessage))

                it "should resume the request and send the error, along with WWW-Authenticate and Link headers", ->
                    @doIt()

                    @req.resume.should.have.been.called
                    @res.should.be.unauthorized(@errorMessage)

            describe "when the `authenticateToken` calls back with a non-401 error", ->
                beforeEach ->
                    @error = new restify.ForbiddenError("The authentication succeeded but this resource is forbidden.")
                    @authenticateToken.yields(@error)

                it "should resume the request and send the error, but no headers", ->
                    @doIt()

                    @req.resume.should.have.been.called
                    @pluginNext.should.have.been.calledWith(@error)
                    @res.header.should.not.have.been.called

        describe "without an authorization header", ->
            beforeEach -> @req.authorization = {}

            it "should not set `req.clientId`, and simply call `next`", ->
                @doIt()

                should.not.exist(@req.clientId)
                @pluginNext.should.have.been.calledWithExactly()

        describe "with an authorization header that does not contain a bearer token", ->
            beforeEach ->
                @req.authorization =
                    scheme: "basic"
                    credentials: "asdf"
                    basic: { username: "aaa", password: "bbb" }

            it "should send a 400 response with WWW-Authenticate and Link headers", ->
                @doIt()

                @res.should.be.bad("Bearer token required. Follow the oauth2-token link to get one!")

        describe "with an authorization header that contains an empty bearer token", ->
            beforeEach ->
                @req.authorization =
                    scheme: "Bearer"
                    credentials: ""

            it "should send a 400 response with WWW-Authenticate and Link headers", ->
                @doIt()

                @res.should.be.bad("Bearer token required. Follow the oauth2-token link to get one!")

    describe "`res.sendUnauthenticated`", ->
        beforeEach ->
            @req.path = => "/other-resource"
            @res.nextSpy = @pluginNext
            @doIt()

        describe "with no arguments", ->
            beforeEach -> @res.sendUnauthenticated()

            it "should send a 401 response with WWW-Authenticate (but with no error code) and Link headers, plus the " +
               "default message", ->
                @res.should.be.unauthorized(
                    "Authentication via bearer token required. Follow the oauth2-token link to get one!"
                    { noWwwAuthenticateErrors: true, send: true }
                )

        describe "with a message passed", ->
            message = "You really should go get a bearer token"
            beforeEach -> @res.sendUnauthenticated(message)

            it "should send a 401 response with WWW-Authenticate (but with no error code) and Link headers, plus the " +
               "specified message", ->
                @res.should.be.unauthorized(message, { noWwwAuthenticateErrors: true, send: true })
