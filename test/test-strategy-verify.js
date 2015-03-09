var PasswordGrantStrategy = require('..'),
    chai = require('chai'),
	passport = require('chai-passport-strategy');

var expect = chai.expect;

chai.use(passport);

describe('PasswordGrantStrategy', function() {
  describe('passing request to verify callback', function() {
    var strategy = new PasswordGrantStrategy({
      tokenURL: 'https://www.example.com/oauth2/token',
      clientID: 'foo',
      passReqToCallback: true
    },
    function(req, accessToken, refreshToken, profile, done) {
      if (Object.keys(profile).length !== 0) { return done(null, false); }

      if (accessToken == '2YotnFZFEjr1zCsicMWpAA' && refreshToken == 'tGzv3JOkF0XG5Qx2TlKWIA') {
        return done(null, { id: '1234' }, { message: 'Hello', foo: req.headers['x-foo'] });
      }
      return done(null, false);
    });

    // inject a "mock" oauth2 instance
    strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
      if (options.username == 'foo' && options.password == 'bar' && options.grant_type == 'password') {
        callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example' });
      } else {
        callback(null, 'wrong-access-token', 'wrong-refresh-token');
      }
    }

    var user, info;

    before(function(done) {
      chai.passport.use(strategy)
        .success(function(u, i) {
          user = u;
          info = i;
          done();
        })
        .req(function(req) { req.headers['x-foo'] = 'hello'; })
        .authenticate({ username: 'foo', password: 'bar' });
    });

    it('should supply user', function() {
      expect(user).to.be.an.object;
      expect(user.id).to.equal('1234');
    });

    it('should supply info', function() {
      expect(info).to.be.an.object;
      expect(info.message).to.equal('Hello');
    });

    it('should supply request header in info', function() {
      expect(info.foo).to.equal('hello');
    });
  });

  describe('passing request to verify callback that accepts params', function() {
    var strategy = new PasswordGrantStrategy({
      tokenURL: 'https://www.example.com/oauth2/token',
      clientID: 'foo',
      passReqToCallback: true
    },
    function(req, accessToken, refreshToken, params, profile, done) {
      if (params.example_parameter !== 'example_value') { return done(null, false); }
      if (Object.keys(profile).length !== 0) { return done(null, false); }

      if (accessToken == '2YotnFZFEjr1zCsicMWpAA' && refreshToken == 'tGzv3JOkF0XG5Qx2TlKWIA') {
        return done(null, { id: '1234' }, { message: 'Hello', foo: req.headers['x-foo'] });
      }
      return done(null, false);
    });

    // inject a "mock" oauth2 instance
    strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
      if (options.username == 'foo' && options.password == 'bar' && options.grant_type == 'password') {
        callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example', expires_in: 3600, example_parameter: 'example_value' });
      } else {
        callback(null, 'wrong-access-token', 'wrong-refresh-token');
      }
    }

    var user, info;

    before(function(done) {
      chai.passport.use(strategy)
        .success(function(u, i) {
          user = u;
          info = i;
          done();
        })
        .req(function(req) { req.headers['x-foo'] = 'hello'; })
        .authenticate({ username: 'foo', password: 'bar' });
    });

    it('should supply user', function() {
      expect(user).to.be.an.object;
      expect(user.id).to.equal('1234');
    });

    it('should supply info', function() {
      expect(info).to.be.an.object;
      expect(info.message).to.equal('Hello');
    });

    it('should supply request header in info', function() {
      expect(info.foo).to.equal('hello');
    });
  });

  describe('failing verification with additional information', function() {
    var strategy = new PasswordGrantStrategy({
      tokenURL: 'https://www.example.com/oauth2/token',
      clientID: 'foo'
    },
    function(accessToken, refreshToken, profile, done) {
      return done(null, false, { message: 'Invite required' });
    });

    // inject a "mock" oauth2 instance
    strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
      if (options.username == 'foo' && options.password == 'bar' && options.grant_type == 'password') {
        callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example', expires_in: 3600, example_parameter: 'example_value' });
      } else {
        callback(null, 'wrong-access-token', 'wrong-refresh-token');
      }
    }

    var info;

    before(function(done) {
      chai.passport.use(strategy)
        .fail(function(i) {
          info = i;
          done();
        })
        .authenticate({ username: 'foo', password: 'bar' });
    });

    it('should supply info', function() {
      expect(info).to.be.an.object;
      expect(info.message).to.equal('Invite required');
    });
  });
});
