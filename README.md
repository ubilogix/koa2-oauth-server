Koa 2 OAuth Server
==================

*Koa 2 wrapper for [node-oauth2-server][noa2s]*

The wrapper is based on [express-oauth-server][eoas].


Installation
------------

TODO: Installation instructions, when published on npmjs.


Configuration
-------------

A complete reference implementation is available in the `/examples` directory.
The sample implements the following grant flows:

* Password (resource owner password credentials)
* Authorization code
* Refresh token
* Client credentials


Additional features
-------------------

This middleware extends upon the base oauth2 library by providing the following:

### Scope verification middleware

Allows for protecting individual routes or routers with scope keys.
If no method is provided, a default method performing substring matching will
be used.

### `model.checkScope(requiredScope, token) => Boolean|String`

Takes `requiredScope` and `token` as input, should return boolean `true` to
indicate that the required scope was encountered, or boolean `false` or a 
string to indicate that it was not.

If `false` is returned, the default error message will read:
> "Required scope: \`{requiredScope}\`"

##### Example

Note: The below corresponds to the fallback `checkScope` implementation.

```js
model.checkScope = (requiredScope, token) => {
    return token.scope.indexOf(requiredScope) !== -1;
};
```

```js
const protected = new Router(),
      account   = new Router();

protected.use(oauth.authenticate()); // Requires bearer token
account.use(oauth.scope('account')); // Requires `account` scope

account.get('/edit', oauth.scope('edit'), (...) => { // Requires `edit` too
    // Update account information
});

protected.use(account);
```

### Token grant metadata access

Exposes the `ctx.request` object to the model, allowing for processing and
storage of metadata (IP, User Agent, etc.).

#### `model.saveTokenMetadata(token, data) => Promise`

Takes `token` and `data` objects as input, should return a Promise that
resolves with the `token` object on completion.

##### Example

Use some geolocation service to look up the user, then update the token entry.

```js
model.saveTokenMetadata = (token, data) => {
    return geoDataLookup(data.ip).then((geoData) => {
        return token.update({ geoData: geoData });
    });
};
```

[noa2s]: https://github.com/thomseddon/node-oauth2-server
[eoas]: https://github.com/seegno/express-oauth-server
