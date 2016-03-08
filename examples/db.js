'use strict';

// Mock data, this would normally be database bindings, ORM wrappers, etc.

module.exports = {
    clients: [{
        id: 'someClient',
        secret: 'superSecret', 
        name: 'Sample client application',
        accessTokenLifetime: 3600,    // If omitted, server default will be used
        refreshTokenLifetime: 604800, // ^
        redirectUris: ['https://www.getpostman.com/oauth2/callback'],
        grants: ['client_credentials', 'refresh_token', 'authorization_code', 'password'],
        validScopes: ['account', 'edit'],
    }],
    users: [{
        id: 1,
        name: 'AzureDiamond',
        username: 'foo@example.com',
        password: 'hunter2',
    }],
    tokens: [],
    authCodes: []
};
