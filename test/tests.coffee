"use strict"

sinon = require("sinon")
restifyOAuth2 = require("..")

describe "Authenticating private URIs", ->
    plugin = null
    tokenEndpoint = "/token"
    authenticateToken = null
    authenticatedRequestPredicate = null

    beforeEach ->
        @tokenEndpoint = "/token"
        @authenticateToken = sinon.stub()
        @authenticatedRequestPredicate = sinon.stub()

        @authenticatedRequestPredicate.returns(true)
        @authenticatedRequestPredicate.withArgs(sinon.match.has("path", "/public")).returns(false)

        @plugin = restifyOAuth2({ @tokenEndpoint, @authenticateToken, @authenticatedRequestPredicate })

    describe "For the token endpoint", ->
        beforeEach ->
            @req = { method: "POST", path: @tokenEndpoint }
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

