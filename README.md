# passport-instagram-token

![Build Status](https://img.shields.io/travis/ghaiklor/passport-instagram-token.svg)
![Coverage](https://img.shields.io/coveralls/ghaiklor/passport-instagram-token.svg)

![Downloads](https://img.shields.io/npm/dm/passport-instagram-token.svg)
![Downloads](https://img.shields.io/npm/dt/passport-instagram-token.svg)
![npm version](https://img.shields.io/npm/v/passport-instagram-token.svg)
![License](https://img.shields.io/npm/l/passport-instagram-token.svg)

[![semantic-release](https://img.shields.io/badge/%20%20%F0%9F%93%A6%F0%9F%9A%80-semantic--release-e10079.svg)](https://github.com/semantic-release/semantic-release)
[![Commitizen friendly](https://img.shields.io/badge/commitizen-friendly-brightgreen.svg)](http://commitizen.github.io/cz-cli/)
![dependencies](https://img.shields.io/david/ghaiklor/passport-instagram-token.svg)
![dev dependencies](https://img.shields.io/david/dev/ghaiklor/passport-instagram-token.svg)

[Passport](http://passportjs.org/) strategy for authenticating with Instagram access tokens using the OAuth 2.0 API.

This module lets you authenticate using Instagram in your Node.js applications.
By plugging into Passport, Instagram authentication can be easily and unobtrusively integrated into any application or framework that supports [Connect](http://www.senchalabs.org/connect/)-style middleware, including [Express](http://expressjs.com/).

## Installation

```shell
npm install passport-instagram-token
```

## Usage

### Configure Strategy

The Instagram authentication strategy authenticates users using a Instagram account and OAuth 2.0 tokens.
The strategy requires a `verify` callback, which accepts these credentials and calls `next` providing a user, as well as `options` specifying a app ID and app secret.

```javascript
var InstagramTokenStrategy = require('passport-instagram-token');

passport.use(new InstagramTokenStrategy({
    clientID: INSTAGRAM_CLIENT_ID,
    clientSecret: INSTAGRAM_CLIENT_SECRET,
    passReqToCallback: true
}, function(req, accessToken, refreshToken, profile, next) {
    User.findOrCreate({'instagram.id': profile.id}, function(error, user) {
        return next(error, user);
    });
}));
```

### Authenticate Requests

Use `passport.authenticate()`, specifying the `instagram-token` strategy, to authenticate requests.

For example, as route middleware in an [Express](http://expressjs.com/) application:

```javascript
app.get('/auth/instagram', passport.authenticate('instagram-token'));
```

Or if you are using Sails framework:

```javascript
// AuthController.js
module.exports = {
    instagram: function(req, res) {
        passport.authenticate('instagram-token', function(error, user, info) {
            if (error) return res.serverError(error);
            if (info) return res.unauthorized(info);
            return res.ok(user);
        })(req, res);
    }
};
```

The request to this route should include a GET or POST data with the keys `access_token` and optionally, `refresh_token` set to the credentials you receive from Instagram.

```
GET /auth/instagram?access_token=<TOKEN>
```

## Issues

If you receive a `401 Unauthorized` error, it is most likely because you have wrong access token or not yet specified any application permissions.
Once you refresh access token with new permissions, try to send this access token again.

## License

The MIT License (MIT)

Copyright (c) 2015 Eugene Obrezkov

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
