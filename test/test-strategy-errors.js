var PasswordGrantStrategy = require('..'),
    chai = require('chai'),
	passport = require('chai-passport-strategy');

var InternalOAuthError = require('passport-oauth2').InternalOAuthError,
    TokenError = require('passport-oauth2').TokenError;

var expect = chai.expect;

chai.use(passport);

describe('PasswordGrantStrategy', function() {
  describe('that encounters an error obtaining an access token', function() {
    var strategy = new PasswordGrantStrategy({
      tokenURL: 'https://www.example.com/oauth2/token',
      clientID: 'foo'
    },
    function(accessToken, refreshToken, params, profile, done) {
      if (accessToken == '2YotnFZFEjr1zCsicMWpAA' && refreshToken == 'tGzv3JOkF0XG5Qx2TlKWIA') {
        return done(null, { id: '1234' }, { message: 'Hello' });
      }
      return done(null, false);
    });

    // inject a "mock" oauth2 instance
    strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
      return callback(new Error('something went wrong'));
    };

    var err;

    before(function(done) {
      chai.passport.use(strategy)
        .error(function(e) {
          err = e;
          done();
        })
        .authenticate({ username: 'foo', password: 'bar' });
    });

    it('should error', function() {
      expect(err).to.be.an.instanceof(InternalOAuthError)
      expect(err.message).to.equal('Failed to obtain access token');
      expect(err.oauthError.message).to.equal('something went wrong');
    });
  });

  describe('that encounters a node-oauth object literal error with OAuth-compatible body obtaining an access token', function() {
    var strategy = new PasswordGrantStrategy({
      tokenURL: 'https://www.example.com/oauth2/token',
      clientID: 'foo'
    },
    function(accessToken, refreshToken, params, profile, done) {
      if (accessToken == '2YotnFZFEjr1zCsicMWpAA' && refreshToken == 'tGzv3JOkF0XG5Qx2TlKWIA') {
        return done(null, { id: '1234' }, { message: 'Hello' });
      }
      return done(null, false);
    });

    // inject a "mock" oauth2 instance
    strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
      return callback({ statusCode: 400, data: '{"error":"invalid_grant","error_description":"The provided username or password was incorrect."} '});
    };

    var err;

    before(function(done) {
      chai.passport.use(strategy)
        .error(function(e) {
          err = e;
          done();
        })
        .authenticate({ username: 'foo', password: 'bar' });
    });

    it('should error', function() {
      expect(err).to.be.an.instanceof(TokenError)
      expect(err.message).to.equal('The provided username or password was incorrect.');
      expect(err.code).to.equal('invalid_grant');
      expect(err.oauthError).to.be.undefined;
    });
  });

  describe('that encounters a node-oauth object literal error with nearly-OAuth-compatible body obtaining an access token', function() {
    var strategy = new PasswordGrantStrategy({
      tokenURL: 'https://www.example.com/oauth2/token',
      clientID: 'foo'
    },
    function(accessToken, refreshToken, params, profile, done) {
      if (accessToken == '2YotnFZFEjr1zCsicMWpAA' && refreshToken == 'tGzv3JOkF0XG5Qx2TlKWIA') {
        return done(null, { id: '1234' }, { message: 'Hello' });
      }
      return done(null, false);
    });

    // inject a "mock" oauth2 instance
    strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
      return callback({ statusCode: 400, data: '{"error_code":"invalid_grant"}'});
    }

    var err;

    before(function(done) {
      chai.passport.use(strategy)
        .error(function(e) {
          err = e;
          done();
        })
        .authenticate({ username: 'foo', password: 'bar' });
    });

    it('should error', function() {
      expect(err).to.be.an.instanceof(InternalOAuthError);
      expect(err.message).to.equal('Failed to obtain access token');
      expect(err.oauthError.statusCode).to.equal(400);
      expect(err.oauthError.data).to.equal('{"error_code":"invalid_grant"}');
    });
  });

  describe('that encounters a node-oauth object literal error with non-OAuth-compatible body obtaining an access token', function() {
    var strategy = new PasswordGrantStrategy({
      tokenURL: 'https://www.example.com/oauth2/token',
      clientID: 'foo'
    },
    function(accessToken, refreshToken, params, profile, done) {
      if (accessToken == '2YotnFZFEjr1zCsicMWpAA' && refreshToken == 'tGzv3JOkF0XG5Qx2TlKWIA') {
        return done(null, { id: '1234' }, { message: 'Hello' });
      }
      return done(null, false);
    });

    // inject a "mock" oauth2 instance
    strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
      return callback({ statusCode: 500, data: 'Something went wrong'});
    };

    var err;

    before(function(done) {
      chai.passport.use(strategy)
        .error(function(e) {
          err = e;
          done();
        })
        .authenticate({ username: 'foo', password: 'bar' });
    });

    it('should error', function() {
      expect(err).to.be.an.instanceof(InternalOAuthError);
      expect(err.message).to.equal('Failed to obtain access token');
      expect(err.oauthError.statusCode).to.equal(500);
      expect(err.oauthError.data).to.equal('Something went wrong');
    });
  });

  describe('that encounters an error during verification', function() {
    var strategy = new PasswordGrantStrategy({
      tokenURL: 'https://www.example.com/oauth2/token',
      clientID: 'foo'
    },
    function(accessToken, refreshToken, params, profile, done) {
      return done(new Error('something went wrong'));
    });

    // inject a "mock" oauth2 instance
    strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
      if (options.username == 'foo' && options.password == 'bar' && options.grant_type == 'password') {
        return callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example' });
      } else {
        return callback(null, 'wrong-access-token', 'wrong-refresh-token');
      }
    };

    var err;

    before(function(done) {
      chai.passport.use(strategy)
        .error(function(e) {
          err = e;
          done();
        })
        .authenticate({ username: 'foo', password: 'bar' });
    });

    it('should error', function() {
      expect(err).to.be.an.instanceof(Error);
      expect(err.message).to.equal('something went wrong');
    });
  });

  describe('that encounters a thrown error during verification', function() {
    var strategy = new PasswordGrantStrategy({
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'foo'
      },
      function(accessToken, refreshToken, params, profile, done) {
        throw new Error('something was thrown');
      });

    // inject a "mock" oauth2 instance
    strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
      if (options.username == 'foo' && options.password == 'bar' && options.grant_type == 'password') {
        return callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example' });
      } else {
        return callback(null, 'wrong-access-token', 'wrong-refresh-token');
      }
    };

    var err;

    before(function(done) {
      chai.passport.use(strategy)
        .error(function(e) {
          err = e;
          done();
        })
        .authenticate({ username: 'foo', password: 'bar' });
    });

    it('should error', function() {
      expect(err).to.be.an.instanceof(Error);
      expect(err.message).to.equal('something was thrown');
    });
  });
});
