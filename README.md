# An OAuth 2 Endpoint Plugin for Restify

This package provides a *very simple* plugin for the [Restify][] framework, giving your RESTful server OAuth 2.0
endpoint capabilities. In particular, it implements the [Resource Owner Password Credentials flow][ropc] only.

The idea behind this OAuth 2 flow is that your API clients will prompt the user for their username and password, and
send those to your API in exchange for an access token. This has some advantages over simply sending the user's
credentials to the server directly. For example, it obviates the need for the client to store the credentials, and
allows expiration and revocation of tokens. However, it does imply that you trust your API clients, since they will
have at least one-time access to the user's credentials.

## What You Get

If you provide this plugin with the appropriate hooks, it will:

* Set up a [token endpoint][], which returns [access token responses][token-endpoint-success] or
  [correctly-formatted error responses][token-endpoint-error].
* For all other resources, when an access token is sent, it will validate it:
  * If the token fails validation, it will send an appropriate 401 error response, with a
    [`WWW-Authenticate`][www-authenticate] header and a [`Link`][web-linking] [`rel="oauth2-token"`][oauth2-token-rel]
    header pointing to the token endpoint.
  * Otherwise, it will set `req.username` to the username corresponding to that access token.
* If no access token is sent, it simply sets `req.username` to `null`:
  * You can check for this whenever there is a resource you want to protect.
  * If the user tries to access a protected resource, you can use Restify–OAuth2's `res.sendUnauthorized()` to send
    appropriate 401 errors with `WWW-Authenticate` and `Link` headers as above.

## Use and Configuration

To use Restify–OAuth2, you'll need to instantiate a new instance of the plugin and call `server.use` on your Restify
server. Restify–OAuth2 also depends on the built-in `authorizationParser` and `bodyParser` plugins. So in short, it
looks like this:

```js
var restify = require("restify");
var restifyOAuth2 = require("restify-oauth2");

var server = restify.createServer({ name: "My cool server", version: "1.0.0" });
server.use(restify.authorizationParser());
server.use(restify.bodyParser());
server.use(restifyOAuth2(options));
```

### Hooks

To hook Restify–OAuth2 up to your infrastructure, you will need to provide it with the following hooks in the
`options.hooks` hash. Basically, if you can provide these, you get the OAuth 2 implementation for free.

The demo application contains some [example hooks][].

#### `validateClient(clientId, clientSecret, cb)`

Checks that the API client is authorized to use your API, and has the correct secret. It should call back with `true` or
`false` depending on the result of the check. It can also call back with an error if there was some internal server
error while doing the check.

#### `grantToken(username, password, cb)`

Checks that the API client is authenticating on behalf of a real user with correct credentials. It should call back with
a new token for that user if so, or `false` if the credentials are incorrect. It can also call back with an error if
there was some internal server error while validating the credentials.

#### `authenticateToken(token, cb)`

Checks that a token is valid, i.e. that it was granted in the past by `grantToken`. It should call back with the
username for that token if so, or `false` if the token is invalid. It can also call back with an error if there was some
internal server error while looking up the token.

### Other Options

The `hooks` hash is the only required option, but the following are also available for tweaking:

* `tokenEndpoint`: the location at which the token endpoint should be created. Defaults to `"/token"`.
* `wwwAuthenticateRealm`: the value of the "Realm" challenge in the `WWW-Authenticate` header.
  Defaults to `"Who goes there?"`.
* `tokenExpirationTime`: the value returned for the `expires_in` component of the response from the token endpoint.
  Note that this is *only* the value reported; you are responsible for keeping track of token expiration yourself and
  calling back with `false` from `authenticateToken` when the token expires. Defaults to `Infinity`.

## What Does That Look Like?

OK, let's try something a bit more concrete. If you check out the [example server][] used in the integration tests,
you'll see our setup:

## /

The initial resource, at which people enter the server.

* If a valid token is supplied, `req.username` is truthy, and the app responds with links to `/public` and `/secret`.
* If no token is supplied, the app responds with links to `/token` and `/public`.
* If an invalid token is supplied, Restify–OAuth2 intercepts the request before it gets to the application, and sends an
  appropriate 401 error.

## /token

The token endpoint, managed entirely by Restify–OAuth2. It generates tokens for a given client ID/client
secret/username/password combination.

The client validation and token-generation logic is provided by the application, but none of the ceremony necessary for
OAuth 2 conformance, error handling, etc. is present in the application code: Restify–OAuth2 takes care of all of that.

## /public

A public resource anyone can access.

* If a valid token is supplied, `req.username` contains the username, and the app uses that to send a personalized
  response.
* If no token is supplied, `req.username` is `null`. The app still sends a response, just without personalizing.
* If an invalid token is supplied, Restify–OAuth2 intercepts the request before it gets to the application, and sends an
  appropriate 401 error.

## /secret

A secret resource that only authenticated users can access.

* If a valid token is supplied, `req.username` is truthy, and the app sends the secret data.
* If no token is supplied, `req.username` is `null`, so the application uses `res.sendUnauthorized()` to send a nice 401
  error with `WWW-Authenticate` and `Link` headers.
* If an invalid token is supplied, Restify–OAuth2 intercepts the request before it gets to the application, and sends an
  appropriate 401 error.

[Restify]: http://mcavage.github.com/node-restify/
[ropc]: http://tools.ietf.org/html/rfc6749#section-1.3.3
[token endpoint]: http://tools.ietf.org/html/rfc6749#section-3.2
[token-endpoint-success]: http://tools.ietf.org/html/rfc6749#section-5.1
[token-endpoint-error]: http://tools.ietf.org/html/rfc6749#section-5.2
[oauth2-token-rel]: http://tools.ietf.org/html/draft-wmills-oauth-lrdd-07#section-3.2
[web-linking]: http://tools.ietf.org/html/rfc5988
[www-authenticate]: http://tools.ietf.org/html/rfc2617#section-3.2.1
[example hooks]: https://github.com/domenic/restify-oauth2/blob/master/examples/hooks.js
[example server]: https://github.com/domenic/restify-oauth2/blob/master/examples/server.js
