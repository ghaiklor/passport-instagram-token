var util = require('util');
var OAuth2Strategy = require('passport-oauth').OAuth2Strategy;
var InternalOAuthError = require('passport-oauth').InternalOAuthError;

util.inherits(InstagramTokenStrategy, OAuth2Strategy);

/**
 * `Strategy` constructor.
 * The Instagram authentication strategy authenticates requests by delegating to Instagram using OAuth2 access tokens.
 * Applications must supply a `verify` callback which accepts a accessToken, refreshToken, profile and callback.
 * Callback supplying a `user`, which should be set to `false` if the credentials are not valid.
 * If an exception occurs, `error` should be set.
 *
 * Options:
 * - clientID          Identifies client to Instagram App
 * - clientSecret      Secret used to establish ownership of the consumer key
 * - passReqToCallback If need, pass req to verify callback
 *
 * Example:
 *     passport.use(new InstagramTokenStrategy({
 *           clientID: '123-456-789',
 *           clientSecret: 'shhh-its-a-secret',
 *           passReqToCallback: true
 *       }, function(req, accessToken, refreshToken, profile, next) {
 *              User.findOrCreate(..., function (error, user) {
 *                  next(error, user);
 *              });
 *          }
 *       ));
 *
 * @param {Object} _options
 * @param {Function} _verify
 * @constructor
 */
function InstagramTokenStrategy(_options, _verify) {
  var options = _options || {};
  options.authorizationURL = options.authorizationURL || 'https://api.instagram.com/oauth/authorize/';
  options.tokenURL = options.tokenURL || 'https://api.instagram.com/oauth/access_token';
  options.profileURL = options.profileURL || 'https://api.instagram.com/v1/users/self';

  OAuth2Strategy.call(this, options, _verify);

  this.name = 'instagram-token';
  this._profileURL = options.profileURL;
  this._passReqToCallback = options.passReqToCallback;
}

/**
 * Authenticate method
 * @param {Object} req
 * @param {Object} options
 * @returns {*}
 */
InstagramTokenStrategy.prototype.authenticate = function (req, options) {
  var self = this;
  var accessToken = (req.body && req.body.access_token) || (req.query && req.query.access_token) || (req.headers && req.headers.access_token);
  var refreshToken = (req.body && req.body.refresh_token) || (req.query && req.query.refresh_token) || (req.headers && req.headers.refresh_token);

  if (!accessToken) {
    return self.fail({message: 'You should provide access_token'});
  }

  self._loadUserProfile(accessToken, function (error, profile) {
    if (error) return self.error(error);

    function verified(error, user, info) {
      if (error) return self.error(error);
      if (!user) return self.fail(info);

      return self.success(user, info);
    }

    if (self._passReqToCallback) {
      self._verify(req, accessToken, refreshToken, profile, verified);
    } else {
      self._verify(accessToken, refreshToken, profile, verified);
    }
  });
};

/**
 * Parse user profile
 * @param {String} accessToken Instagram OAuth2 access token
 * @param {Function} done
 */
InstagramTokenStrategy.prototype.userProfile = function (accessToken, done) {
  this._oauth2.get(this._profileURL, accessToken, function (error, body, res) {
    if (error) {
      try {
        var errorJSON = JSON.parse(error.data);
        return done(new InternalOAuthError(errorJSON.meta.error_message, errorJSON.meta.code));
      } catch (_) {
        return done(new InternalOAuthError('Failed to fetch user profile', error));
      }
    }

    try {
      var json = JSON.parse(body);
      json['id'] = json.data.id;

      var profile = {
        provider: 'instagram',
        id: json.id,
        username: json.data.username,
        displayName: json.data.full_name || '',
        name: {
          familyName: json.data.last_name || '',
          givenName: json.data.first_name || ''
        },
        emails: [],
        photos: [{value: json.data.profile_picture}],
        _raw: body,
        _json: json
      };

      return done(null, profile);
    } catch (e) {
      return done(e);
    }
  });
};

module.exports = InstagramTokenStrategy;
