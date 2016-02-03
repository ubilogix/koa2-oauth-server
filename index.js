'use strict';

const debug       = require('debug')('koa:oauth2-server'),
      OAuthServer = require('node-oauth2-server'),
      Request     = OAuthServer.Request,
      Response    = OAuthServer.Response;

const ePath                    = 'node-oauth2-server/lib/errors/',
      InvalidArgumentError     = require(ePath + 'invalid-argument-error'),
      UnauthorizedRequestError = require(ePath + 'unauthorized-request-error');

class KoaOAuthServer {
    constructor(options) {
        this.options = options || {};

        if(!options.model) {
            throw new InvalidArgumentError('Missing parameter: `model`');
        }

        this.server = new OAuthServer(options);
    }

    // Returns token authentication middleware
    authenticate() {
        debug('Creating authentication endpoint middleware');
        return (ctx, next) => {
            const request  = new Request(ctx.request),
                  response = new Response(ctx.response);

            return this.server
                .authenticate(request, response)
                .then((token) => {
                    ctx.state.oauth = { token: token };
                    return next();
                })
                .catch((err) => { handleError(err, ctx); });
        };
    }

    // Returns authorization endpoint middleware
    // Used by the client to obtain authorization from the resource owner
    authorize() {
        debug('Creating authorization endpoint middleware');
        return (ctx, next) => {
            const request  = new Request(ctx.request),
                  response = new Response(ctx.response);

            return this.server
                .authorize(request, response)
                .then((code) => {
                    ctx.state.oauth = { code: code };
                    handleResponse(ctx, response);
                    return next();
                })
                .catch((err) => { handleError(err, ctx); });
        };
    }

    // Returns token endpoint middleware
    // Used by the client to exchange authorization grant for access token
    token() {
        debug('Creating token endpoint middleware');
        return (ctx, next) => {
            const request  = new Request(ctx.request),
                  response = new Response(ctx.response);

            return this.server
                .token(request, response)
                .then((token) => {
                    ctx.state.oauth = { token: token };
                    handleResponse(ctx, response);
                    return next();
                })
                .catch((err) => { handleError(err, ctx, response); });
        };
    }
}

function handleResponse(ctx, response) {
    ctx.set(response.headers);
    ctx.status = response.status;
    ctx.body   = response.body;
}

function handleError(err, ctx, response) {
    debug(err);

    ctx.status = err.code;
    if(response) { ctx.set(response.headers); }
    if(err instanceof UnauthorizedRequestError) { return; }

    ctx.body = { error: err.name, error_description: err.message };
}

module.exports = KoaOAuthServer;
