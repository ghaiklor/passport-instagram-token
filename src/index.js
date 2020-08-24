import { OAuth2Strategy, InternalOAuthError } from 'passport-oauth';
import jwksRsa from 'jwks-rsa';
import jwt from 'jsonwebtoken';

const jwksClient = jwksRsa({
  strictSsl: true,
  rateLimit: true,
  cache: true,
  cacheMaxEntries: 100,
  cacheMaxAge: 1000 * 60 * 60 * 24,
  jwksUri: 'https://appleid.apple.com/auth/keys'
});

const getAppleJWKSKey = (header, callback) => {
  jwksClient.getSigningKey(header.kid, (err, key) => {
      callback(err, key && (key.publicKey || key.rsaPublicKey));
  });
};

/**
 * `Strategy` constructor.
 * The Apple authentication strategy authenticates requests by verify identity token.
 * Applications must supply a `verify` callback which accepts a accessToken, refreshToken, profile and callback.
 * Callback supplying a `user`, which should be set to `false` if the credentials are not valid.
 * If an exception occurs, `error` should be set.
 *
 * Options:
 * - clientID          Identifier of Apple Service ID
 * - passReqToCallback If need, pass req to verify callback
 *
 * @param {Object} _options
 * @param {Function} _verify
 * @example
 * passport.use(new AppleTokenStrategy({
 *   clientID: '123456789',
 * }), function(undefined, undefined, profile, next) {
 *   User.findOrCreate({appleId: profile.id}, function(error, user) {
 *     next(error, user);
 *   })
 * })
 */
export default class AppleTokenStrategy extends OAuth2Strategy {
  constructor(_options, _verify) {
    let options = _options || {};
    let verify = _verify;

    if (!options.clientID) {
      throw new TypeError('AppleTokenStrategy requires a clientID option');
    }

    options.authorizationURL = options.authorizationURL || 'https://appleid.apple.com/auth/authorize';
    options.tokenURL = options.tokenURL || 'https://appleid.apple.com/auth/token';

    super(options, verify);

    this.name = 'apple-token';
    this._clientID = options.clientID;
    this._identityTokenField = options.identityTokenField || 'id_token';
    this._passReqToCallback = options.passReqToCallback;
  }

  /**
   * Authenticate method
   * @param {Object} req
   * @param {Object} options
   * @returns {*}
   */
  authenticate(req, options) {
    const identityToken = (req.body && req.body[this._identityTokenField]) || (req.query && req.query[this._identityTokenField]);
    let user = (req.body && req.body.user) || (req.query && req.query.user);

    if (!identityToken) return this.fail({message: `You should provide ${this._identityTokenField}`});

    if (typeof user === 'string') {
      try {
        user = JSON.parse(user);
      } catch(err) {}
    }

    this._loadUserProfile({identityToken, user}, (error, profile) => {
      if (error) return this.error(error);

      const verified = (error, user, info) => {
        if (error) return this.error(error);
        if (!user) return this.fail(info);

        return this.success(user, info);
      };

      if (this._passReqToCallback) {
        this._verify(req, undefined, undefined, profile, verified);
      } else {
        this._verify(undefined, undefined, profile, verified);
      }
    });
  }

  /**
   * Parse user profile
   * @param {String} data Apple data info
   * @param {Function} done
   */
  userProfile(data, done) {
    const {identityToken, user} = data;

    const verifyOpts = {
      audience: this._clientID,
      issuer: 'https://appleid.apple.com',
      algorithms: ['RS256']
    };

    jwt.verify(identityToken, getAppleJWKSKey, verifyOpts, (err, jwtClaims) => {
      if (err) {
        return done(new InternalOAuthError('Failed to validate identity token', err));
      }

      const profile = {
        provider: 'apple',
        id: jwtClaims.sub,
        emails: [{value: jwtClaims.email}],
        emailVerified: jwtClaims.email_verified === 'true',
        isPrivateEmail: jwtClaims.is_private_email === 'true',
        _raw: JSON.stringify(jwtClaims),
        _json: jwtClaims,
      }

      if (user && (user.lastName || user.firstName)) {
        const name = {};

        if (user.lastName) {
          name.familyName = user.lastName;
        }

        if (user.firstName) {
          name.givenName = user.firstName;
        }

        profile.name = name;
      }

      return done(null, profile);
    });
  }
}
