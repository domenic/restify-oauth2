"use strict"

sinon = require("sinon")
should = require("chai").should()
Assertion = require("chai").Assertion
restify = require("restify")
restifyOAuth2 = require("..")

tokenEndpoint = "/token-uri"
wwwAuthenticateRealm = "Realm string"
tokenExpirationTime = 12345

Assertion.addMethod("unauthorized", (message) ->
    @_obj.header.should.have.been.calledWith("WWW-Authenticate", "Bearer realm=\"#{wwwAuthenticateRealm}\"")
    @_obj.header.should.have.been.calledWith("Link", "<#{tokenEndpoint}>; rel=\"oauth2-token\"")
    @_obj.send.should.have.been.calledWith(sinon.match.instanceOf(restify.UnauthorizedError))
    @_obj.send.should.have.been.calledWith(sinon.match.has("message", sinon.match(message)))
)

Assertion.addMethod("oauthError", (errorClass, errorType, errorDescription) ->
    desiredBody = { error: errorType, error_description: errorDescription }
    @_obj.send.should.have.been.calledWith(sinon.match.instanceOf(restify[errorClass + "Error"]))
    @_obj.send.should.have.been.calledWith(sinon.match.has("message", errorDescription))
    @_obj.send.should.have.been.calledWith(sinon.match.has("body", desiredBody))
)

beforeEach ->
    @req = { pause: sinon.spy(), resume: sinon.spy(), username: "anonymous" }
    @res = { header: sinon.spy(), send: sinon.spy() }
    @next = sinon.spy((x) => if x? then @res.send(x))

    @authenticateToken = sinon.stub()
    @validateClient = sinon.stub()
    @grantToken = sinon.stub()

    options = {
        tokenEndpoint
        wwwAuthenticateRealm
        tokenExpirationTime
        @authenticateToken
        @validateClient
        @grantToken
    }
    @plugin = restifyOAuth2(options)

    @doIt = => @plugin(@req, @res, @next)

describe "For POST requests to the token endpoint", ->
    beforeEach ->
        @req.method = "POST"
        @req.path = tokenEndpoint

    describe "with a body", ->
        beforeEach -> @req.body = {}

        describe "that has grant_type=password", ->
            beforeEach -> @req.body.grant_type = "password"

            describe "and has a username field", ->
                beforeEach ->
                    @username = "username123"
                    @req.body.username = @username

                describe "and a password field", ->
                    beforeEach ->
                        @password = "password456"
                        @req.body.password = @password

                    describe "with a basic access authentication header", ->
                        beforeEach ->
                            [@clientId, @clientSecret] = ["clientId123", "clientSecret456"]
                            @req.authorization =
                                scheme: "Basic"
                                basic: { username: @clientId, password: @clientSecret }

                        it "should validate the client, with client ID/secret from the basic authentication", ->
                            @doIt()

                            @validateClient.should.have.been.calledWith(@clientId, @clientSecret)

                        describe "when `validateClient` calls back with `true`", ->
                            beforeEach -> @validateClient.yields(null, true)

                            it "should use the username and password body fields to grant a token", ->
                                @doIt()

                                @grantToken.should.have.been.calledWith(@username, @password)

                            describe "when `grantToken` calls back with a token", ->
                                beforeEach ->
                                    @token = "token123"
                                    @grantToken.yields(null, @token)

                                it "should send a response with access_token, token_type, and expires_in set", ->
                                    @doIt()

                                    @res.send.should.have.been.calledWith(
                                        access_token: @token,
                                        token_type: "Bearer"
                                        expires_in: tokenExpirationTime
                                    )

                            describe "when `grantToken` calls back with `false`", ->
                                beforeEach -> @grantToken.yields(null, false)

                                it "should send a 401 response with error_type=invalid_client", ->
                                    @doIt()

                                    @res.should.be.an.oauthError("Unauthorized", "invalid_client",
                                                                 "Username and password did not authenticate.")

                            describe "when `grantToken` calls back with `null`", ->
                                beforeEach -> @grantToken.yields(null, null)

                                it "should send a 401 response with error_type=invalid_client", ->
                                    @doIt()

                                    @res.should.be.an.oauthError("Unauthorized", "invalid_client",
                                                                 "Username and password did not authenticate.")

                            describe "when `grantToken` calls back with an error", ->
                                beforeEach ->
                                    @error = new Error("Bad things happened, internally.")
                                    @grantToken.yields(@error)

                                it "should call `next` with that error", ->
                                    @doIt()

                                    @next.should.have.been.calledWithExactly(@error)

                        describe "when `validateClient` calls back with `false`", ->
                            beforeEach -> @validateClient.yields(null, false)

                            it "should send a 401 response with error_type=invalid_client and a WWW-Authenticate " +
                               "header", ->
                                @doIt()

                                @res.header.should.have.been.calledWith(
                                    "WWW-Authenticate",
                                    'Basic realm="Client ID and secret did not validate."'
                                )
                                @res.should.be.an.oauthError("Unauthorized", "invalid_client",
                                                             "Client ID and secret did not validate.")

                        describe "when `validateClient` calls back with an error", ->
                            beforeEach ->
                                @error = new Error("Bad things happened, internally.")
                                @validateClient.yields(@error)

                            it "should call `next` with that error", ->
                                @doIt()

                                @next.should.have.been.calledWithExactly(@error)

                    describe "without an authorization header", ->
                        beforeEach -> @req.authorization = null

                        it "should send a 400 response with error_type=invalid_request", ->
                            @doIt()

                            @res.should.be.an.oauthError("BadRequest", "invalid_request",
                                                         "Must include a basic access authentication header.")

                    describe "with an authorization header that does not contain basic access credentials", ->
                        beforeEach ->
                            @req.authorization =
                                scheme: "Bearer"
                                credentials: "asdf"

                        it "should send a 400 response with error_type=invalid_request", ->
                            @doIt()

                            @res.should.be.an.oauthError("BadRequest", "invalid_request",
                                                         "Must include a basic access authentication header.")

                describe "that has no password field", ->
                    beforeEach -> @req.body.password = null

                    it "should send a 400 response with error_type=invalid_request", ->
                        @doIt()

                        @res.should.be.an.oauthError("BadRequest", "invalid_request",
                                                     "Must specify password field.")

            describe "that has no username field", ->
                beforeEach -> @req.body.username = null

                it "should send a 400 response with error_type=invalid_request", ->
                    @doIt()

                    @res.should.be.an.oauthError("BadRequest", "invalid_request", "Must specify username field.")

        describe "that has grant_type=authorization_code", ->
            beforeEach -> @req.body.grant_type = "authorization_code"

            it "should send a 400 response with error_type=unsupported_grant_type", ->
                @doIt()

                @res.should.be.an.oauthError("BadRequest", "unsupported_grant_type",
                                             "Only grant_type=password is currently supported.")

        describe "that has no grant_type value", ->
            it "should send a 400 response with error_type=invalid_request", ->
                @doIt()

                @res.should.be.an.oauthError("BadRequest", "invalid_request", "Must specify grant_type field.")

    describe "without a body", ->
        beforeEach -> @req.body = null

        it "should send a 400 response with error_type=invalid_request", ->
            @doIt()

            @res.should.be.an.oauthError("BadRequest", "invalid_request", "Must supply a body.")

    describe "without a body that has been parsed into an object", ->
        beforeEach -> @req.body = "Left as a string or buffer or something"

        it "should send a 400 response with error_type=invalid_request", ->
            @doIt()

            @res.should.be.an.oauthError("BadRequest", "invalid_request", "Must supply a body.")

describe "For other requests", ->
    beforeEach -> @req.path = "/other-resource"

    describe "with an authorization header that contains a valid bearer token", ->
        beforeEach ->
            @token = "TOKEN123"
            @req.authorization = { scheme: "Bearer", credentials: @token }

        it "should pause the request and authenticate the token", ->
            @doIt()

            @req.pause.should.have.been.called
            @authenticateToken.should.have.been.calledWith(@token)

        describe "when the `authenticateToken` calls back with a username", ->
            beforeEach ->
                @username = "user123"
                @authenticateToken.yields(null, @username)

            it "should resume the request, set the `username` property on the request, and call `next`", ->
                @doIt()

                @req.resume.should.have.been.called
                @req.should.have.property("username", @username)
                @next.should.have.been.calledWithExactly()

        describe "when the `authenticateToken` calls back with `false`", ->
            beforeEach -> @authenticateToken.yields(null, false)

            it "should resume the request and send a 401 response, along with WWW-Authenticate and Link headers", ->
                @doIt()

                @req.resume.should.have.been.called
                @res.should.be.unauthorized("Bearer token invalid.")

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
                @res.send.should.have.been.calledWith(@error)
                @res.header.should.not.have.been.called

    describe "without an authorization header", ->
        beforeEach -> @req.authorization = null

        it "should remove `req.username`, and simply call `next`", ->
            @doIt()

            should.not.exist(@req.username)
            @next.should.have.been.calledWithExactly()

    describe "with an authorization header that does not contain a bearer token", ->
        beforeEach ->
            @req.authorization =
                scheme: "basic"
                credentials: "asdf"
                basic: { username: "aaa", password: "bbb" }

        it "should send a 401 response with WWW-Authenticate and Link headers", ->
            @doIt()

            @res.should.be.unauthorized("Bearer token required.")

    describe "with an authorization header that contains an empty bearer token", ->
        beforeEach ->
            @req.authorization =
                scheme: "Bearer"
                credentials: ""

        it "should send a 401 response with WWW-Authenticate and Link headers", ->
            @doIt()

            @res.should.be.unauthorized("Bearer token required.")
