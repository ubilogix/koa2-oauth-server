Koa 2 OAuth Server
==================

*Koa 2 wrapper for the upcoming version of [node-oauth2-server][noa2s]
(see [PR 203][pr203] for details).*

The wrapper is based on [express-oauth-server][eoas].

Quick Start
-----------

TODO: Outline usage here.



Features
--------

### Scope verification middleware

WIP

### Save token metadata

Exposes the `ctx.request` object to the model, allowing for processing and
storage of metadata (IP, User Agent, etc.).

#### `model.saveTokenMetadata(token, data) => Promise`

Takes `token` and `data` objects as input, should return a Promise that
resolves with the `token` object on completion.

##### Example

Supposing that the `token` object is an ORM instance with an `update` method:

```js
model.saveTokenMetadata = (token, data) => {
    return token.update({ metadata: data });
};
```




[noa2s]: https://github.com/thomseddon/node-oauth2-server
[pr203]: https://github.com/thomseddon/node-oauth2-server/pull/203
[eoas]: https://github.com/seegno/express-oauth-server
