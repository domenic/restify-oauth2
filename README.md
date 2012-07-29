# An OAuth 2 Endpoint Plugin for Restify

This package provides a *very simple* plugin for the [Restify][] framework, giving your RESTful server OAuth 2.0
endpoint capabilities. In particular, it implements the [Resource Owner Password Credentials flow][ropc] only.

## What You Get

If you provide this plugin with the appropriate hooks, it will:

* Set up a [token endpoint][], which returns [access token responses][token-endpoint-success] or
  [correctly-formatted error responses][token-endpoint-error]. It will accept either
  `"application/x-www-form-urlencoded"` as specified, or `"application/json"` as described in some RFC I can't find
  anymore.
* Protect all other resources that you specify, verifying that a bearer token is sent and that it passes your
  authentication hooks.
  * If it does, the request object will get the `username` property returned from your authentication hook.
  * Otherwise, a 401 error will be sent with an appropriate `"WWW-Authenticate"` header as well as a
    [`"Link"` header][web-linking] with [`rel="oauth2-token"`][oauth2-token-rel] pointing to the token endpoint.

## What Does That Look Like?

OK, let's try something a bit more concrete. If you check out the example server used in the integration tests, you'll
see our setup:


[Restify]: http://mcavage.github.com/node-restify/
[ropc]: http://tools.ietf.org/html/draft-ietf-oauth-v2-30#section-1.3.3
[token endpoint]: http://tools.ietf.org/html/draft-ietf-oauth-v2-30#section-4.3.2
[token-endpoint-success]: http://tools.ietf.org/html/draft-ietf-oauth-v2-30#section-5.1
[token-endpoint-error]: http://tools.ietf.org/html/draft-ietf-oauth-v2-30#section-5.2
[web-linking]: http://tools.ietf.org/html/rfc5988
[oauth2-token-rel]: http://tools.ietf.org/html/draft-wmills-oauth-lrdd-01#section-4.1.2
