var chai = require('chai');
var assert = chai.assert;
var InstagramTokenStrategy = require('../');
var fakeProfile = JSON.stringify(require('./fixtures/profile.json'));

describe('InstagramTokenStrategy:init', function () {
  it('Should properly export Strategy constructor', function () {
    assert.equal(typeof InstagramTokenStrategy, 'function');
    assert.equal(typeof InstagramTokenStrategy.Strategy, 'function');
    assert.equal(InstagramTokenStrategy, InstagramTokenStrategy.Strategy);
  });

  it('Should properly initialize', function () {
    var strategy = new InstagramTokenStrategy({
      clientID: '123',
      clientSecret: '123'
    }, function () {
    });

    assert.equal(strategy.name, 'instagram-token');
  });
});

describe('InstagramTokenStrategy:authenticate', function () {
  describe('Authenticate without passReqToCallback', function () {
    var strategy;

    before(function () {
      strategy = new InstagramTokenStrategy({
        clientID: '123',
        clientSecret: '123'
      }, function (accessToken, refreshToken, profile, next) {
        assert.equal(accessToken, 'access_token');
        assert.equal(refreshToken, 'refresh_token');
        assert.typeOf(profile, 'object');
        assert.typeOf(next, 'function');
        return next(null, profile, {info: 'foo'});
      });

      strategy._oauth2.get = function (url, accessToken, next) {
        next(null, fakeProfile, null);
      };
    });

    it('Should properly parse access_token', function (done) {
      chai.passport.use(strategy)
        .success(function (user, info) {
          assert.typeOf(user, 'object');
          assert.typeOf(info, 'object');
          assert.deepEqual(info, {info: 'foo'});
          done();
        })
        .req(function (req) {
          req.headers = {
            access_token: 'access_token',
            refresh_token: 'refresh_token'
          }
        })
        .authenticate({});
    });

    it('Should properly call fail if access_token is not provided', function (done) {
      chai.passport.use(strategy)
        .fail(function (error) {
          assert.typeOf(error, 'object');
          assert.typeOf(error.message, 'string');
          assert.equal(error.message, 'You should provide access_token');
          done();
        })
        .authenticate();
    });
  });

  describe('Authenticate with passReqToCallback', function () {
    var strategy;

    before(function () {
      strategy = new InstagramTokenStrategy({
        clientID: '123',
        clientSecret: '123',
        passReqToCallback: true
      }, function (req, accessToken, refreshToken, profile, next) {
        assert.typeOf(req, 'object');
        assert.equal(accessToken, 'access_token');
        assert.equal(refreshToken, 'refresh_token');
        assert.typeOf(profile, 'object');
        assert.typeOf(next, 'function');
        return next(null, profile, {info: 'foo'});
      });

      strategy._oauth2.get = function (url, accessToken, next) {
        next(null, fakeProfile, null);
      }
    });

    it('Should properly call _verify with req', function (done) {
      chai.passport.use(strategy)
        .success(function (user, info) {
          assert.typeOf(user, 'object');
          assert.typeOf(info, 'object');
          assert.deepEqual(info, {info: 'foo'});
          done();
        })
        .req(function (req) {
          req.body = {
            access_token: 'access_token',
            refresh_token: 'refresh_token'
          }
        })
        .authenticate({});
    });
  });
});

describe('InstagramTokenStrategy:userProfile', function () {
  it('Should properly fetch profile', function (done) {
    var strategy = new InstagramTokenStrategy({
      clientID: '123',
      clientSecret: '123'
    }, function () {
    });

    strategy._oauth2.get = function (url, accessToken, next) {
      next(null, fakeProfile, null);
    };

    strategy.userProfile('accessToken', function (error, profile) {
      if (error) return done(error);

      assert.equal(profile.provider, 'instagram');
      assert.equal(profile.id, '1234567');
      assert.equal(profile.displayName, 'Eugene Obrezkov');
      assert.equal(profile.name.familyName, 'Obrezkov');
      assert.equal(profile.name.givenName, 'Eugene');
      assert.deepEqual(profile.emails, []);
      assert.equal(profile.photos[0].value, 'http://distillery.s3.amazonaws.com/profiles/profile_1574083_75sq_1295469061.jpg');
      assert.equal(typeof profile._raw, 'string');
      assert.equal(typeof profile._json, 'object');

      done();
    });
  });

  it('Should properly handle exception on fetching profile', function (done) {
    var strategy = new InstagramTokenStrategy({
      clientID: '123',
      clientSecret: '123'
    }, function () {
    });

    strategy._oauth2.get = function (url, accessToken, done) {
      done(null, 'not a JSON', null);
    };

    strategy.userProfile('accessToken', function (error, profile) {
      assert(error instanceof SyntaxError);
      assert.equal(typeof profile, 'undefined');
      done();
    });
  });
});
