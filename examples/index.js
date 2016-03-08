'use strict';

// Exhaustive sample implementing password (ropc), authorization code,
// client credentials, and refresh token grant flows.
// Run with `DEBUG=koa:oauth*,example node index.js`

const Koa         = require('koa'),
      debug       = require('debug')('example'),
      Router      = require('koa-router'),
      session     = require('koa-session'),
      convert     = require('koa-convert'), // convert session for koa2
      bodyParser  = require('koa-bodyparser'),
      OAuthServer = require('../');

const db    = require('./db'), // Mock data
      model = {};              // OAuth2 model container

// Client lookup - Note that for *authcode* grants, the secret is not provided
model.getClient = (id, secret) => {
    debug(`Looking up client ${id}:${secret}`);

    const lookupMethod = typeof secret === 'undefined'
        ? (client) => { return client.id === id; }
        : (client) => { return client.id === id && client.secret === secret };

    return db.clients.find(lookupMethod);
};

model.getUser = (username, password) => {
    debug(`Looking up user ${username}:${password}`);

    return db.users.find((user) => {
        return user.username === username && user.password === password;
    });
};

// In the client credentials grant flow, the client itself needs to be related
// with some form of user representation
model.getUserFromClient = (client) => {
    debug(`Looking up user for client ${client.name}`);
    return { name: client.name, isClient: true };
};

// Performs a lookup on the provided string and returns a token object
model.getAccessToken = (accessToken) => {
    debug(`Get access token ${accessToken}`);

    const token = db.tokens.find((token) => {
        return token.accessToken === accessToken;
    });

    if(!token) { return false; }

    // Populate with user and client model instances
    token.user = db.users.find((user) => {
        return user.id === token.user.id;
    });

    token.client = db.clients.find((client) => {
        return client.id === token.client.id;
    });

    return token;
};

// Performs a lookup on the provided string and returns a token object
model.getRefreshToken = (refreshToken) => {
    debug(`Get refresh token ${refreshToken}`);
    const token = db.tokens.find((token) => {
        return token.refreshToken === refreshToken;
    });

    if(!token) { return false; }

    // Populate with user and client model instances
    token.user = db.users.find((user) => {
        return user.id === token.user.id;
    });

    token.client = db.clients.find((client) => {
        return client.id === token.client.id;
    });

    return token;
};

// Saves the newly generated token object
model.saveToken = (token, client, user) => {
    debug(`Save token ${token.accessToken}`);

    token.user   = { id: user.id }; 
    token.client = { id: client.id };

    db.tokens.push(token);
    return token;
};

// Revoke refresh token after use - note ExpiresAt detail!
model.revokeToken = (token) => {
    debug(`Revoke token ${token.refreshToken}`);

    // Note: This is normally the DB object instance from getRefreshToken, so
    // just token.delete() or similar rather than the below findIndex.
    const idx = db.tokens.findIndex((item) => {
        return item.refreshToken === token.refreshToken;
    });

    db.tokens.splice(idx, 1);

    // Note: Presently, this method must return the revoked token object with
    // an expired date. This is currently being discussed in
    // https://github.com/thomseddon/node-oauth2-server/issues/251
    
    token.refreshTokenExpiresAt = new Date(1984);
    return token;
};

// Retrieves an authorization code
model.getAuthorizationCode = (code) => {
    debug(`Retrieving authorization code ${code}`);

    return db.authCodes.find((authCode) => {
        return authCode.authorizationCode === code;
    });
};

// Saves the newly generated authorization code object
model.saveAuthorizationCode = (code, client, user) => {
    debug(`Saving authorization code ${code.authorizationCode}`);
    code.user   = { id: user.id };
    code.client = { id: client.id };

    db.authCodes.push(code);
    return code;
};

// Revokes the authorization code after use - note ExpiresAt detail!
model.revokeAuthorizationCode = (code) => {
    debug(`Revoking authorization code ${code.authorizationCode}`);
    
    const idx = db.authCodes.findIndex((authCode) => {
        return authCode.authorizationCode === code.authorizationCode;
    });

    if(!idx) { return false; }

    db.authCodes.splice(idx, 1);
    code.expiresAt.setYear(1984); // Same as for `revokeToken()`

    return code;
};

// Called in `authenticate()` - basic check for scope existance
// `scope` corresponds to the oauth server configuration option, which
// could either be a string or boolean true.
// Since we utilize router-based scope check middleware, here we simply check
// for scope existance.
model.verifyScope = (token, scope) => {
    debug(`Verify scope ${scope} in token ${token.accessToken}`);
    if(scope && !token.scope) { return false; }
    return token;
};

// Can be used to sanitize or purely validate requested scope string
model.validateScope = (user, client, scope) => {
    debug(`Validating requested scope: ${scope}`);

    const validScope = (scope || '').split(' ').filter((key) => {
        return client.validScopes.indexOf(key) !== -1;
    });

    if(!validScope.length) { return false; }

    return validScope.join(' ');
};

// OAuth server initialization

const oauth = new OAuthServer({
    scope: true, // Alternatively string with required scopes (see verifyScope)
    model: model,
    allowBearerTokensInQueryString: true,
    accessTokenLifetime: 3600,   // 1 hour
    refreshTokenLifetime: 604800 // 1 week
});

// Application setup

const app      = new Koa(),
      rPublic  = new Router(),
      rPrivate = new Router(),
      rAccount = new Router();

rPublic.get('/', (ctx) => {
    ctx.response.body = { message: 'I am a public resource!' };
});

rPublic.get('/login', (ctx) => {
    ctx.response.body = '<html><body><form action="/login" method="post">'
        + '<h1>Ye olde login form</h1>'
        + '<p>Sign in as foo@example.com:hunter2</p>'
        + '<input type="email" name="username" value="foo@example.com">'
        + '<input type="password" name="password" value="hunter2">'
        + '<input type="submit" value="Sign in">'
        + '</form></body></html>';
});

rPublic.post('/login', (ctx) => {
    const creds = ctx.request.body;
    debug(`Authenticating ${creds.username}`);

    const user = db.users.find((user) => {
        return user.username === creds.username
            && user.password === creds.password;
    });

    if(!user) {
        debug('Invalid credentials');
        ctx.redirect('/login');
        return;
    }

    debug(`Success!`);
    ctx.session.userId = user.id;

    // If we were sent here from grant page, redirect back
    if(ctx.session.hasOwnProperty('query')) {
        debug('Redirecting back to grant dialog');
        ctx.redirect('/oauth/authorize');
        return;
    }

    // If not do whatever you fancy
    ctx.redirect('/');
});

rPublic.get('/logout', (ctx) => {
    ctx.session.userId = null;
    ctx.redirect('/login');
});

// Token acquisition endpoint
rPublic.all('/oauth/token', oauth.token());

rPublic.get('/oauth/authorize', (ctx) => {
    if(!ctx.session.userId) {
        debug('User not authenticated, redirecting to /login');
        ctx.session.query = {
            state:         ctx.request.query.state,
            scope:         ctx.request.query.scope,
            client_id:     ctx.request.query.client_id,
            redirect_uri:  ctx.request.query.redirect_uri,
            response_type: ctx.request.query.response_type
        };

        ctx.redirect('/login');
        return;
    }

    const client = db.clients.find((client) => {
        return client.id === ctx.session.query.client_id;
    });

    if(!client) { ctx.throw(401, 'No such client'); }

    ctx.response.body = `<html><body><h1>Grant access to "${client.name}"?</h1>`
        + `<p>The application requests access to ${ctx.session.query.scope}</p>`
        + '<form action="/oauth/authorize" method="post">'
        + '<input type="submit" value="Grant access"></form></body></html>';
});

// OAuth authorization endpoint (authcode grant flow)
rPublic.post('/oauth/authorize', (ctx, next) => {
    if(!ctx.session.userId) {
        debug('User not authenticated, redirecting to /login');
        ctx.redirect('/login');
        return;
    }

    ctx.request.body         = ctx.session.query;
    ctx.request.body.user_id = ctx.session.userId;
    ctx.session.query        = null;

    return next();
}, oauth.authorize({
    authenticateHandler: {
        handle: (req, res) => {
            return db.users.find((user) => {
                return user.id === req.body.user_id;
            });
        }
    }
}));

rAccount.get('/', (ctx) => {
    ctx.response.body = { message: 'Displaying user account information.' };
});

rAccount.post('/', oauth.scope('edit'), (ctx) => {
    ctx.response.body = { message: 'Account information updated!' };
});

rPrivate.use(oauth.authenticate());
rPrivate.use('/account', oauth.scope('account'), rAccount.routes());

// Application initialization

app.keys = ['superupersessionsecret']; // For koa-session
app
    .use(convert(session(app)))
    .use(bodyParser())
    .use((ctx, next) => {
        debug(`${ctx.method} ${ctx.url}`);

        return next().catch((err) => {
            debug('Caught error: ', err);

            ctx.status = err.status || 500;
            ctx.body = {
                name: err.name,
                message: err.message
            };
        });
    })
    .use(rPublic.routes())
    .use(rPrivate.routes())
    .listen(8080, () => {
        debug('Example application listening on localhost:8080');
    });
