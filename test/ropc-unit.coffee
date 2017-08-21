"use strict"

require("chai").use(require("sinon-chai"))
sinon = require("sinon")
should = require("chai").should()
Assertion = require("chai").Assertion
restify = require("restify")
errs = require("restify-errors")
restifyOAuth2 = require("..")

tokenEndpoint = "/token-uri"
wwwAuthenticateRealm = "Realm string"
tokenExpirationTime = 12345

Assertion.addMethod("unauthorized", (message, options) ->
    expectedLink = '<' + tokenEndpoint + '>; rel="oauth2-token"; grant-types="password"; token-types="bearer"'
    expectedWwwAuthenticate = 'Bearer realm="' + wwwAuthenticateRealm + '"'

    if not options?.noWwwAuthenticateErrors
        expectedWwwAuthenticate += ', error="invalid_token", error_description="' + message + '"'

    spyToTest = if options?.send then @_obj.send else @_obj.nextSpy

    @_obj.header.should.have.been.calledWith("WWW-Authenticate", expectedWwwAuthenticate)
    @_obj.header.should.have.been.calledWith("Link", expectedLink)
    spyToTest.should.have.been.calledOnce
    spyToTest.should.have.been.calledWith(sinon.match.instanceOf(errs.UnauthorizedError))
    spyToTest.should.have.been.calledWith(sinon.match.has("message", sinon.match(message)))
)

Assertion.addMethod("unauthenticated", (message) ->
    expectedLink = '<' + tokenEndpoint + '>; rel="oauth2-token"; grant-types="password"; token-types="bearer"'

    @_obj.header.should.have.been.calledWith("Link", expectedLink)
    @_obj.send.should.have.been.calledOnce
    @_obj.send.should.have.been.calledWith(sinon.match.instanceOf(errs.ForbiddenError))
    @_obj.send.should.have.been.calledWith(sinon.match.has("message", sinon.match(message)))
)

Assertion.addMethod("bad", (message) ->
    expectedLink = '<' + tokenEndpoint + '>; rel="oauth2-token"; grant-types="password"; token-types="bearer"'
    expectedWwwAuthenticate = 'Bearer realm="' + wwwAuthenticateRealm + '", error="invalid_request", ' +
                              'error_description="' + message + '"'

    @_obj.header.should.have.been.calledWith("WWW-Authenticate", expectedWwwAuthenticate)
    @_obj.header.should.have.been.calledWith("Link", expectedLink)
    @_obj.nextSpy.should.have.been.calledOnce
    @_obj.nextSpy.should.have.been.calledWith(sinon.match.instanceOf(errs.BadRequestError))
    @_obj.nextSpy.should.have.been.calledWith(sinon.match.has("message", sinon.match(message)))
)

Assertion.addMethod("oauthError", (errorClass, errorDescription) ->
    @_obj.nextSpy.should.have.been.calledOnce
    @_obj.nextSpy.should.have.been.calledWith(sinon.match.instanceOf(errs[errorClass + "Error"]))
    @_obj.nextSpy.should.have.been.calledWith(sinon.match.has("message", errorDescription))
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
    @validateClient = sinon.stub()
    @grantUserToken = sinon.stub()
    @grantScopes = sinon.stub()

    options = {
        tokenEndpoint
        wwwAuthenticateRealm
        tokenExpirationTime
        hooks: {
            @authenticateToken
            @validateClient
            @grantUserToken
        }
    }

    optionsWithScope = {
        tokenEndpoint
        wwwAuthenticateRealm
        tokenExpirationTime
        hooks: {
            @authenticateToken
            @validateClient
            @grantUserToken
            @grantScopes
        }
    }

    @doItBase = => restifyOAuth2.ropc(@server, options)
    @doIt = => @doItBase
    @doItWithScopes = => restifyOAuth2.ropc(@server, optionsWithScope)

describe "Resource Owner Password Credentials flow", ->
    it "should set up the token endpoint", ->
        @doItBase()

        @server.post.should.have.been.calledWith(tokenEndpoint)

    describe "For POST requests to the token endpoint", ->
        beforeEach ->
            @req.method = "POST"
            @req.path = => tokenEndpoint
            @res.nextSpy = @tokenNext

            baseDoIt = @doItBase
            @doIt = =>
                baseDoIt()
                @postToTokenEndpoint()

        describe "with a body", ->
            beforeEach -> @req.body = {}

            describe "that has grant_type=password", ->
                beforeEach -> @req.body.grant_type = "password"

                describe "with a basic access authentication header", ->
                    beforeEach ->
                        [@clientId, @clientSecret] = ["clientId123", "clientSecret456"]
                        @req.authorization =
                            scheme: "Basic"
                            basic: { username: @clientId, password: @clientSecret }

                    describe "and has a username field", ->
                        beforeEach ->
                            @username = "username123"
                            @req.body.username = @username

                        describe "and a password field", ->
                            beforeEach ->
                                @password = "password456"
                                @req.body.password = @password

                            it "should validate the client, with client ID/secret from the basic authentication", ->
                                @doIt()

                                @validateClient.should.have.been.calledWith({ @clientId, @clientSecret }, @req)

                            describe "when `validateClient` calls back with `true`", ->
                                beforeEach -> @validateClient.yields(null, true)

                                it "should use the username and password body fields to grant a token", ->
                                    @doIt()

                                    @grantUserToken.should.have.been.calledWith(
                                        { @clientId, @clientSecret, @username, @password },
                                        @req
                                    )

                                describe "when `grantUserToken` calls back with a token", ->
                                    beforeEach ->
                                        @token = "token123"
                                        @grantUserToken.yields(null, @token)

                                    describe "and a `grantScopes` hook is defined", ->
                                        beforeEach ->
                                            baseDoIt = @doItWithScopes
                                            @doIt = =>
                                                baseDoIt()
                                                @postToTokenEndpoint()
                                            @requestedScopes = ["one", "two"]
                                            @req.body.scope = @requestedScopes.join(" ")

                                        it "should use credentials and requested scopes to grant scopes", ->
                                            @doIt()

                                            @grantScopes.should.have.been.calledWith(
                                                { @clientId, @clientSecret, @username, @password, @token },
                                                @requestedScopes
                                            )

                                        describe "when `grantScopes` calls back with an array of granted scopes", ->
                                            beforeEach ->
                                                @grantedScopes = ["three"]
                                                @grantScopes.yields(null, @grantedScopes)

                                            it "should send a response with access_token, token_type, scope, and " +
                                               "expires_in set, where scope is limited to the granted scopes", ->
                                                @doIt()

                                                @res.send.should.have.been.calledWith(
                                                    access_token: @token,
                                                    token_type: "Bearer"
                                                    expires_in: tokenExpirationTime,
                                                    scope: @grantedScopes.join(" ")
                                                )

                                            it "should call `next`", ->
                                                @doIt()

                                                @tokenNext.should.have.been.calledWithExactly()

                                        describe "when `grantScopes` calls back with `true`", ->
                                            beforeEach -> @grantScopes.yields(null, true)

                                            it "should send a response with access_token, token_type, scope, and " +
                                               "expires_in set, where scope is the same as the requested scopes", ->
                                                @doIt()

                                                @res.send.should.have.been.calledWith(
                                                    access_token: @token,
                                                    token_type: "Bearer"
                                                    expires_in: tokenExpirationTime,
                                                    scope: @requestedScopes.join(" ")
                                                )

                                            it "should call `next`", ->
                                                @doIt()

                                                @tokenNext.should.have.been.calledWithExactly()

                                        describe "when `grantScopes` calls back with `false`", ->
                                            beforeEach -> @grantScopes.yields(null, false)

                                            it "should send a 400 response with error_type=invalid_scope", ->
                                                @doIt()

                                                message = "The requested scopes are invalid, unknown, or exceed the " +
                                                          "set of scopes appropriate for these credentials."
                                                @res.should.be.an.oauthError("InvalidScope", message)

                                        describe "when `grantScopes` calls back with an error", ->
                                            beforeEach ->
                                                @error = new Error("Bad things happened, internally.")
                                                @grantScopes.yields(@error)

                                            it "should call `next` with that error", ->
                                                @doIt()

                                                @tokenNext.should.have.been.calledWithExactly(@error)

                                    describe "and a `grantScopes` hook is not defined", ->
                                        beforeEach -> @grantScopes = undefined

                                        it "should send a response with access_token, token_type, and expires_in " +
                                           "set", ->
                                            @doIt()

                                            @res.send.should.have.been.calledWith(
                                                access_token: @token,
                                                token_type: "Bearer"
                                                expires_in: tokenExpirationTime
                                            )

                                        it "should call `next`", ->
                                            @doIt()

                                            @tokenNext.should.have.been.calledWithExactly()

                                describe "when `grantUserToken` calls back with `false`", ->
                                    beforeEach -> @grantUserToken.yields(null, false)

                                    it "should send a 401 response with error_type=invalid_grant", ->
                                        @doIt()

                                        @res.should.be.an.oauthError("InvalidGrant",
                                                                     "Username and password did not authenticate.")

                                describe "when `grantUserToken` calls back with `null`", ->
                                    beforeEach -> @grantUserToken.yields(null, null)

                                    it "should send a 401 response with error_type=invalid_grant", ->
                                        @doIt()

                                        @res.should.be.an.oauthError("InvalidGrant",
                                                                     "Username and password did not authenticate.")

                                describe "when `grantUserToken` calls back with an error", ->
                                    beforeEach ->
                                        @error = new Error("Bad things happened, internally.")
                                        @grantUserToken.yields(@error)

                                    it "should call `next` with that error", ->
                                        @doIt()

                                        @tokenNext.should.have.been.calledWithExactly(@error)

                            describe "when `validateClient` calls back with `false`", ->
                                beforeEach -> @validateClient.yields(null, false)

                                it "should send a 401 response with error_type=invalid_client and a WWW-Authenticate " +
                                   "header", ->
                                    @doIt()

                                    @res.header.should.have.been.calledWith(
                                        "WWW-Authenticate",
                                        'Basic realm="Client ID and secret did not validate."'
                                    )
                                    @res.should.be.an.oauthError("InvalidClient",
                                                                 "Client ID and secret did not validate.")

                                it "should not call the `grantUserToken` hook", ->
                                    @doIt()

                                    @grantUserToken.should.not.have.been.called

                            describe "when `validateClient` calls back with an error", ->
                                beforeEach ->
                                    @error = new Error("Bad things happened, internally.")
                                    @validateClient.yields(@error)

                                it "should call `next` with that error", ->
                                    @doIt()

                                    @tokenNext.should.have.been.calledWithExactly(@error)

                                it "should not call the `grantUserToken` hook", ->
                                    @doIt()

                                    @grantUserToken.should.not.have.been.called

                        describe "that has no password field", ->
                            beforeEach -> @req.body.password = null

                            it "should send a 400 response with error_type=invalid_request", ->
                                @doIt()

                                @res.should.be.an.oauthError("InvalidRequest",
                                                             "Must specify password field.")

                            it "should not call the `validateClient` or `grantUserToken` hooks", ->
                                @doIt()

                                @validateClient.should.not.have.been.called
                                @grantUserToken.should.not.have.been.called

                    describe "that has no username field", ->
                        beforeEach -> @req.body.username = null

                        it "should send a 400 response with error_type=invalid_request", ->
                            @doIt()

                            @res.should.be.an.oauthError("InvalidRequest", "Must specify username field.")

                        it "should not call the `validateClient` or `grantUserToken` hooks", ->
                            @doIt()

                            @validateClient.should.not.have.been.called
                            @grantUserToken.should.not.have.been.called

                describe "without an authorization header", ->
                    it "should send a 400 response with error_type=invalid_request", ->
                        @doIt()

                        @res.should.be.an.oauthError("InvalidRequest",
                                                     "Must include a basic access authentication header.")

                    it "should not call the `validateClient` or `grantUserToken` hooks", ->
                        @doIt()

                        @validateClient.should.not.have.been.called
                        @grantUserToken.should.not.have.been.called

                describe "with an authorization header that does not contain basic access credentials", ->
                    beforeEach ->
                        @req.authorization =
                            scheme: "Bearer"
                            credentials: "asdf"

                    it "should send a 400 response with error_type=invalid_request", ->
                        @doIt()

                        @res.should.be.an.oauthError("InvalidRequest",
                                                     "Must include a basic access authentication header.")

                    it "should not call the `validateClient` or `grantUserToken` hooks", ->
                        @doIt()

                        @validateClient.should.not.have.been.called
                        @grantUserToken.should.not.have.been.called

            describe "that has grant_type=authorization_code", ->
                beforeEach -> @req.body.grant_type = "authorization_code"

                it "should send a 400 response with error_type=unsupported_grant_type", ->
                    @doIt()

                    @res.should.be.an.oauthError("UnsupportedGrantType",
                                                 "Only grant_type=password is supported.")

                it "should not call the `validateClient` or `grantUserToken` hooks", ->
                    @doIt()

                    @validateClient.should.not.have.been.called
                    @grantUserToken.should.not.have.been.called

            describe "that has no grant_type value", ->
                it "should send a 400 response with error_type=invalid_request", ->
                    @doIt()

                    @res.should.be.an.oauthError("InvalidRequest", "Must specify grant_type field.")

                it "should not call the `validateClient` or `grantUserToken` hooks", ->
                    @doIt()

                    @validateClient.should.not.have.been.called
                    @grantUserToken.should.not.have.been.called

        describe "without a body", ->
            beforeEach -> @req.body = null

            it "should send a 400 response with error_type=invalid_request", ->
                @doIt()

                @res.should.be.an.oauthError("InvalidRequest", "Must supply a body.")

            it "should not call the `validateClient` or `grantUserToken` hooks", ->
                @doIt()

                @validateClient.should.not.have.been.called
                @grantUserToken.should.not.have.been.called

        describe "without a body that has been parsed into an object", ->
            beforeEach -> @req.body = "Left as a string or buffer or something"

            it "should send a 400 response with error_type=invalid_request", ->
                @doIt()

                @res.should.be.an.oauthError("InvalidRequest", "Must supply a body.")

            it "should not call the `validateClient` or `grantUserToken` hooks", ->
                @doIt()

                @validateClient.should.not.have.been.called
                @grantUserToken.should.not.have.been.called

    describe "For other requests", ->
        beforeEach ->
            @req.path = => "/other-resource"
            @res.nextSpy = @pluginNext

        describe "with an authorization header that contains a valid bearer token", ->
            beforeEach ->
                @token = "TOKEN123"
                @req.authorization = { scheme: "Bearer", credentials: @token }

            it "should pause the request and authenticate the token", ->
                @doItBase()

                @req.pause.should.have.been.called
                @authenticateToken.should.have.been.calledWith(@token, @req)

            describe "when the `authenticateToken` calls back with `true`", ->
                beforeEach -> @authenticateToken.yields(null, true)

                it "should resume the request and call `next`", ->
                    @doItBase()

                    @req.resume.should.have.been.called
                    @pluginNext.should.have.been.calledWithExactly()

            describe "when the `authenticateToken` calls back with `false`", ->
                beforeEach -> @authenticateToken.yields(null, false)

                it "should resume the request and send a 401 response, along with WWW-Authenticate and Link headers", ->
                    @doItBase()

                    @req.resume.should.have.been.called
                    @res.should.be.unauthorized(
                        "Bearer token invalid. Follow the oauth2-token link to get a valid one!"
                    )

            describe "when the `authenticateToken` calls back with a 401 error", ->
                beforeEach ->
                    @errorMessage = "The authentication failed for some reason."
                    @authenticateToken.yields(new errs.UnauthorizedError(@errorMessage))

                it "should resume the request and send the error, along with WWW-Authenticate and Link headers", ->
                    @doItBase()

                    @req.resume.should.have.been.called
                    @res.should.be.unauthorized(@errorMessage)

            describe "when the `authenticateToken` calls back with a non-401 error", ->
                beforeEach ->
                    @error = new errs.ForbiddenError("The authentication succeeded but this resource is forbidden.")
                    @authenticateToken.yields(@error)

                it "should resume the request and send the error, but no headers", ->
                    @doItBase()

                    @req.resume.should.have.been.called
                    @pluginNext.should.have.been.calledWith(@error)
                    @res.header.should.not.have.been.called

        describe "without an authorization header", ->
            beforeEach -> @req.authorization = {}

            it "should remove `req.username`, and simply call `next`", ->
                @doItBase()

                should.not.exist(@req.username)
                @pluginNext.should.have.been.calledWithExactly()

        describe "with an authorization header that does not contain a bearer token", ->
            beforeEach ->
                @req.authorization =
                    scheme: "basic"
                    credentials: "asdf"
                    basic: { username: "aaa", password: "bbb" }

            it "should send a 400 response with WWW-Authenticate and Link headers", ->
                @doItBase()

                @res.should.be.bad("Bearer token required. Follow the oauth2-token link to get one!")

        describe "with an authorization header that contains an empty bearer token", ->
            beforeEach ->
                @req.authorization =
                    scheme: "Bearer"
                    credentials: ""

            it "should send a 400 response with WWW-Authenticate and Link headers", ->
                @doItBase()

                @res.should.be.bad("Bearer token required. Follow the oauth2-token link to get one!")

    describe "`res.sendUnauthenticated`", ->
        beforeEach ->
            @req.path = => "/other-resource"
            @res.nextSpy = @pluginNext
            @doItBase()

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

    describe "`res.sendUnauthorized`", ->
        beforeEach ->
            @req.path = => "/other-resource"
            @res.nextSpy = @pluginNext
            @doItBase()

        describe "with no arguments", ->
            beforeEach -> @res.sendUnauthorized()

            it "should send a 403 response with Link headers, plus the default message", ->
                @res.should.be.unauthenticated(
                    "Insufficient authorization. Follow the oauth2-token link to get a token with more authorization!"
                )

        describe "with a message passed", ->
            message = "You really should go get a bearer token with more scopes"
            beforeEach -> @res.sendUnauthorized(message)

            it "should send a 403 response with WWW-Authenticate (but with no error code) and Link headers, plus the " +
               "specified message", ->
                @res.should.be.unauthenticated(message)
