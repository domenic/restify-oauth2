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

    describe "For requests to authenticated resources", ->
        beforeEach ->
            @req = { path: "/private", pause: sinon.spy(), resume: sinon.spy() }
            @res = { header: sinon.spy(), send: sinon.spy() }
            @next = sinon.spy((x) => if x? then @res.send(x))

        describe "with an authorization header that contains a valid bearer token", ->
            beforeEach ->
                @token = "TOKEN123"
                @req.authorization = { scheme: "Bearer", credentials: @token }

            it "should pause the request and authenticate the token", ->
                @plugin(@req, @res, @next)

                @req.pause.should.have.been.called
                @authenticateToken.should.have.been.calledWith(@token, @req)

            describe "when the `authenticateToken` callback gives a username", ->
                beforeEach ->
                    @username = "user123"
                    @authenticateToken.yields(null, @username)

                it "should resume the request, set the `username` property on the request, and call `next`", ->
                    @plugin(@req, @res, @next)

                    @req.resume.should.have.been.called
                    @req.should.have.property("username", @username)
                    @next.should.have.been.calledWithExactly()

            describe "when the `authenticateToken` callback gives a 401 error", ->
                beforeEach ->
                    @errorMessage = "The authentication failed for some reason."
                    @authenticateToken.yields(new restify.UnauthorizedError(@errorMessage))

                it "should resume the request and send the error, along with WWW-Authenticate and Link headers", ->
                    @plugin(@req, @res, @next)

                    @req.resume.should.have.been.called
                    @res.should.be.unauthorized(@errorMessage)

            describe "when the `authenticateToken` callback gives a non-401 error", ->
                beforeEach ->
                    @error = new restify.ForbiddenError("The authentication succeeded but this resource is forbidden.")
                    @authenticateToken.yields(@error)

                it "should resume the request and send the error, but no headers", ->
                    @plugin(@req, @res, @next)

                    @req.resume.should.have.been.called
                    @res.send.should.have.been.calledWith(@error)
                    @res.header.should.not.have.been.called

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
                @req.authorization = { scheme: "Bearer", credentials: "" }

            it "should send a 401 response with WWW-Authenticate and Link headers", ->
                @plugin(@req, @res, @next)

                @res.should.be.unauthorized("Bearer token required.")
