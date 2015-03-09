var PasswordGrantStrategy = require('..'),
    util = require('util'),
    chai = require('chai'),
	passport = require('chai-passport-strategy');

var expect = chai.expect;

chai.use(passport);

function MockPasswordGrantStrategy(options, verify) {
  PasswordGrantStrategy.call(this, options, verify);
}

util.inherits(MockPasswordGrantStrategy, PasswordGrantStrategy);

MockPasswordGrantStrategy.prototype.userProfile = function(accessToken, done) {
  if (accessToken == '2YotnFZFEjr1zCsicMWpAA') {
    return done(null, { real_name: 'Foo Baz', email: 'foo@example.com' });
  }
  return done(new Error('failed to load user profile'));
}

describe('PasswordGrantStrategy', function() {
  describe('subclass that overrides userProfile function', function() {
    describe('with default options', function() {
      var strategy = new MockPasswordGrantStrategy({
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'foo'
      },
      function(accessToken, refreshToken, profile, done) {
        if (accessToken == '2YotnFZFEjr1zCsicMWpAA' && refreshToken == 'tGzv3JOkF0XG5Qx2TlKWIA') {
          return done(null, { id: '1234', profile: profile }, { message: 'Hello' });
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

      describe('handling an authorized return request', function() {
        var user, info;

        before(function(done) {
          chai.passport.use(strategy)
            .success(function(u, i) {
              user = u;
              info = i;
              done();
            })
            .authenticate({ username: 'foo', password: 'bar' });
        });

        it('should supply user', function() {
          expect(user).to.be.an.object;
          expect(user.id).to.equal('1234');
        });

        it('should load profile', function() {
          expect(user.profile).to.not.be.undefined;
          expect(user.profile.real_name).to.equal('Foo Baz');
        });

        it('should supply info', function() {
          expect(info).to.be.an.object;
          expect(info.message).to.equal('Hello');
        });
      });

      describe('failing to load user profile', function() {
        var err;

        before(function(done) {
          chai.passport.use(strategy)
            .error(function(e) {
              err = e;
              done();
            })
            .authenticate({ username: 'foo', password: 'hat' });
        });

        it('should error', function() {
          expect(err).to.be.an.instanceof(Error)
          expect(err.message).to.equal('failed to load user profile');
        });
      });
    });

    describe('with skip profile option set to true', function() {
      var strategy = new MockPasswordGrantStrategy({
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'foo',
          skipUserProfile: true
        },
        function(accessToken, refreshToken, profile, done) {
          if (accessToken == '2YotnFZFEjr1zCsicMWpAA' && refreshToken == 'tGzv3JOkF0XG5Qx2TlKWIA') {
            return done(null, { id: '1234', profile: profile }, { message: 'Hello' });
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
          .authenticate({ username: 'foo', password: 'bar' });
      });

      it('should supply user', function() {
        expect(user).to.be.an.object;
        expect(user.id).to.equal('1234');
      });

      it('should not load profile', function() {
        expect(user.profile).to.be.undefined;
      });

      it('should supply info', function() {
        expect(info).to.be.an.object;
        expect(info.message).to.equal('Hello');
      });
    });
  });
});
