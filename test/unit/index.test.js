import chai, { assert } from 'chai';
import sinon from 'sinon';
import AppleTokenStrategy from '../../src/index';
import fakeProfile from '../fixtures/profile';

const STRATEGY_CONFIG = {
  clientID: '123',
};

const BLANK_FUNCTION = () => {
};

describe('InstagramTokenStrategy:init', () => {
  it('Should properly export Strategy constructor', () => {
    assert.isFunction(AppleTokenStrategy);
  });

  it('Should properly initialize', () => {
    let strategy = new AppleTokenStrategy(STRATEGY_CONFIG, BLANK_FUNCTION);

    assert.equal(strategy.name, 'apple-token');
  });

  it('Should properly throw error on empty options', () => {
    assert.throws(() => new AppleTokenStrategy(), Error);
  });
});

describe('InstagramTokenStrategy:authenticate', () => {
  describe('Authenticate without passReqToCallback', () => {
    let strategy;

    before(() => {
      strategy = new AppleTokenStrategy(STRATEGY_CONFIG, (accessToken, refreshToken, profile, next) => {
        assert.equal(accessToken, undefined);
        assert.equal(refreshToken, undefined);
        assert.typeOf(profile, 'object');
        assert.typeOf(next, 'function');
        return next(null, profile, {info: 'foo'});
      });

      sinon.stub(strategy, 'userProfile').yields(null, fakeProfile);
    });

    it('Should properly parse token from body', done => {
      chai.passport.use(strategy)
        .success((user, info) => {
          assert.typeOf(user, 'object');
          assert.typeOf(info, 'object');
          assert.deepEqual(info, {info: 'foo'});
          done();
        })
        .req(req => {
          req.body = {
            id_token: 'id_token',
          }
        })
        .authenticate();
    });

    it('Should properly parse token from query', done => {
      chai.passport.use(strategy)
        .success((user, info) => {
          assert.typeOf(user, 'object');
          assert.typeOf(info, 'object');
          assert.deepEqual(info, {info: 'foo'});
          done();
        })
        .req(req => {
          req.query = {
            id_token: 'id_token',
          }
        })
        .authenticate();
    });

    it('Should properly call fail if id_token is not provided', done => {
      chai.passport.use(strategy)
        .fail(error => {
          assert.typeOf(error, 'object');
          assert.typeOf(error.message, 'string');
          assert.equal(error.message, 'You should provide id_token');
          done();
        })
        .authenticate();
    });
  });

  describe('Authenticate with passReqToCallback', () => {
    let strategy;

    before(() => {
      strategy = new AppleTokenStrategy(Object.assign(STRATEGY_CONFIG, {passReqToCallback: true}), (req, accessToken, refreshToken, profile, next) => {
        assert.typeOf(req, 'object');
        assert.equal(accessToken, undefined);
        assert.equal(refreshToken, undefined);
        assert.typeOf(profile, 'object');
        assert.typeOf(next, 'function');
        return next(null, profile, {info: 'foo'});
      });

      sinon.stub(strategy, 'userProfile').yields(null, fakeProfile);
    });

    it('Should properly call _verify with req', done => {
      chai.passport.use(strategy)
        .success((user, info) => {
          assert.typeOf(user, 'object');
          assert.typeOf(info, 'object');
          assert.deepEqual(info, {info: 'foo'});
          done();
        })
        .req(req => {
          req.body = {
            id_token: 'id_token',
          }
        })
        .authenticate({});
    });
  });
});

describe.skip('InstagramTokenStrategy:userProfile', () => {
  it('Should properly fetch profile', done => {
    let strategy = new AppleTokenStrategy(STRATEGY_CONFIG, BLANK_FUNCTION);

    sinon.stub(strategy, '_loadUserProfile').yields(null, fakeProfile);

    strategy.userProfile('idToken', (error, profile) => {
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

  it('Should properly handle exception on fetching profile', done => {
    let strategy = new AppleTokenStrategy(STRATEGY_CONFIG, BLANK_FUNCTION);

    sinon.stub(strategy._oauth2, 'get', (url, accessToken, done) => done(null, 'not a JSON', null));

    strategy.userProfile('accessToken', (error, profile) => {
      assert(error instanceof SyntaxError);
      assert.equal(typeof profile, 'undefined');
      done();
    });
  });

  it('Should properly handle wrong JSON on fetching profile', done => {
    let strategy = new AppleTokenStrategy(STRATEGY_CONFIG, BLANK_FUNCTION);

    sinon.stub(strategy._oauth2, 'get', (url, accessToken, done) => done(new Error('ERROR'), 'not a JSON', null));

    strategy.userProfile('accessToken', (error, profile) => {
      assert.instanceOf(error, Error);
      assert.equal(typeof profile, 'undefined');
      done();
    });
  });

  it('Should properly handle wrong JSON on fetching profile', done => {
    let strategy = new AppleTokenStrategy(STRATEGY_CONFIG, BLANK_FUNCTION);

    sinon.stub(strategy._oauth2, 'get', (url, accessToken, done) => done({
      data: JSON.stringify({
        error: {
          message: 'MESSAGE',
          code: 'CODE'
        }
      })
    }, 'not a JSON', null));

    strategy.userProfile('accessToken', (error, profile) => {
      assert.equal(error.message, 'Failed to fetch user profile');
      assert.equal(typeof profile, 'undefined');
      done();
    });
  });

  it('Should properly make request with enableProof', done => {
    let strategy = new AppleTokenStrategy({
      clientID: '123',
      clientSecret: '123',
      enableProof: true
    }, BLANK_FUNCTION);

    sinon.stub(strategy._oauth2, 'get', (url, accessToken, done) => done(null, fakeProfile, null));

    strategy.userProfile('accessToken', (error, profile) => {
      assert.equal(strategy._oauth2.get.getCall(0).args[0], 'https://api.instagram.com/v1/users/self?sig=7393bd6533bae39c66e720280eeb57298cfd3b7649ff63eaa76d02da70ad8d45');
      strategy._oauth2.get.restore();
      done();
    });
  });

  it('Should properly make request with enableProof disabled', done => {
    let strategy = new AppleTokenStrategy({
      clientID: '123',
      clientSecret: '123',
      enableProof: false
    }, BLANK_FUNCTION);

    sinon.stub(strategy._oauth2, 'get', (url, accessToken, done) => done(null, fakeProfile, null));

    strategy.userProfile('accessToken', (error, profile) => {
      assert.equal(strategy._oauth2.get.getCall(0).args[0], 'https://api.instagram.com/v1/users/self');
      strategy._oauth2.get.restore();
      done();
    });
  });
});
