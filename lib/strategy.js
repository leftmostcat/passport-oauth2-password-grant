var passport = require('passport-strategy'),
    OAuth2Strategy = require('passport-oauth2'),
    util = require('util'),
    OAuth2 = require('oauth').OAuth2,
    AuthorizationError = require('passport-oauth2').AuthorizationError,
    TokenError = require('passport-oauth2').TokenError;

function PasswordGrantStrategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = undefined;
  }
  options = options || {};

  if (!verify) { throw new TypeError('PasswordGrantStrategy requires a verify callback'); }
  if (!options.tokenURL) { throw new TypeError('PasswordGrantStrategy requires a tokenURL option'); }
  if (!options.clientID) { throw new TypeError('PasswordGrantStrategy requires a clientID option'); }

  /* The OAuth2Strategy constructor is insufficiently generic to allow us to
   * call it directly. */
  passport.Strategy.call(this);
  this.name = 'password-grant';
  this._verify = verify;

  this._oauth2 = new OAuth2(options.clientID, options.clientSecret, '', '', options.tokenURL, options.customHeaders);

  this._passReqToCallback = options.passReqToCallback;
  this._skipUserProfile = (options.skipUserProfile === undefined) ? false : options.skipUserProfile;
}

util.inherits(PasswordGrantStrategy, OAuth2Strategy);

/* Adapted from passport-oauth2. Given its fixed grant type, we reimplement
 * portions of its access token logic. */
PasswordGrantStrategy.prototype.authenticate = function(req, options) {
  options = options || {};
  var self = this;

  if (!options.username) { throw new TypeError('PasswordGrantStrategy requires a username param'); }
  if (!options.password) { throw new TypeError('PasswordGrantStrategy requires a password param'); }

  var params = {};
  params.grant_type = 'password';
  params.username = options.username;
  params.password = options.password;

  this._oauth2.getOAuthAccessToken(null, params,
    function(err, accessToken, refreshToken, params) {
      if (err) { return self.error(self._createOAuthError('Failed to obtain access token', err)); }

      self._loadUserProfile(accessToken, function(err, profile) {
        if (err) { return self.error(err); }

        function verified(err, user, info) {
          if (err) { return self.error(err); }
          if (!user) { return self.fail(info); }
          self.success(user, info);
        }

        try {
          var arity = self._verify.length;

          if (self._passReqToCallback) {
            if (arity == 6) {
              self._verify(req, accessToken, refreshToken, params, profile, verified);
            } else { // arity == 5
              self._verify(req, accessToken, refreshToken, profile, verified);
            }
          } else {
            if (arity == 5) {
              self._verify(accessToken, refreshToken, params, profile, verified);
            } else { // arity == 4
              self._verify(accessToken, refreshToken, profile, verified);
            }
          }
        } catch (ex) {
          return self.error(ex);
        }
      });
    });
};

PasswordGrantStrategy.prototype.parseErrorResponse = function(body, status) {
  var json = JSON.parse(body);

  if (json.error) {
    switch (json.error) {
      case 'invalid_grant':
        return new AuthorizationError(json.error_description, json.error, json.error_uri);
        break;
      default:
        return new TokenError(json.error_description, json.error, json.error_uri);
    }
  }

  return null;
}

module.exports = PasswordGrantStrategy;
