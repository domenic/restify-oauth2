"use strict"

sinon = require("sinon")
Assertion = require("chai").Assertion
restify = require("restify")
restifyOAuth2 = require("..")

describe "Authenticating private URIs", ->
    tokenEndpoint = "/token-uri"
    wwwAuthenticateRealm = "Realm string"

    Assertion.addMethod("unauthorized", (message) ->
        @_obj.header.should.have.been.calledWith("WWW-Authenticate", "Bearer realm=\"#{wwwAuthenticateRealm}\"")
        @_obj.header.should.have.been.calledWith("Link", "<#{tokenEndpoint}>; rel=\"oauth2-token\"")
        @_obj.send.should.have.been.calledWith(sinon.match.instanceOf(restify.UnauthorizedError))
        @_obj.send.should.have.been.calledWith(sinon.match.has("message", sinon.match(message)))
    )

    beforeEach ->
        @authenticateToken = sinon.stub()
        @authenticatedRequestPredicate = sinon.stub()

        @authenticatedRequestPredicate.returns(true)
        @authenticatedRequestPredicate.withArgs(sinon.match.has("path", "/public")).returns(false)

        options = { tokenEndpoint, wwwAuthenticateRealm, @authenticateToken, @authenticatedRequestPredicate }
        @plugin = restifyOAuth2(options)

    describe "For the token endpoint", ->
        beforeEach ->
            @req = { method: "POST", path: tokenEndpoint }
            @res = null
            @next = sinon.spy()

        # TODO

    describe "For public requests", ->
        beforeEach ->
            @req = { path: "/public" }
            @res = null
            @next = sinon.spy()

        it "should simply call `next`", ->
            @plugin(@req, @res, @next)

            @next.should.have.been.calledWithExactly()

    describe "For requests to authenticate resources", ->
        beforeEach ->
            @req = { path: "/private" }
            @res = { header: sinon.spy(), send: sinon.spy() }
            @next = sinon.spy()

        describe "without an authorization header", ->
            beforeEach ->
                @req.authorization = null

            it "should send a 401 response with WWW-Authenticate and Link headers", ->
                @plugin(@req, @res, @next)

                @res.should.be.unauthorized("Bearer token required.")

        describe "with an authorization header that does not contain a bearer token", ->
            beforeEach ->
                @req.authorization =
                    scheme: "basic"
                    credentials: "asdf"
                    basic: { username: "aaa", password: "bbb" }

            it "should send a 401 response with WWW-Authenticate and Link headers", ->
                @plugin(@req, @res, @next)

                @res.should.be.unauthorized("Bearer token required.")

        describe "with an authorization header that contains an empty bearer token", ->
            beforeEach ->
                @req.authorization = { scheme: "bearer", credentials: "" }

            it "should send a 401 response with WWW-Authenticate and Link headers", ->
                @plugin(@req, @res, @next)

                @res.should.be.unauthorized("Bearer token required.")
