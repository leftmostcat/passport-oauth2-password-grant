# passport-oauth2-password-grant

[![Build](https://travis-ci.org/leftmostcat/passport-oauth2-password-grant.svg?branch=master)](https://travis-ci.org/leftmostcat/passport-oauth2-password-grant)
[![Quality](https://codeclimate.com/github/leftmostcat/passport-oauth2-password-grant/badges/gpa.svg)](https://codeclimate.com/github/leftmostcat/passport-oauth2-password-grant)

This module allows authentication through OAuth2 on servers which permit the
'password' grant type. It makes use of the [Passport](http://passportjs.org/)
authentication framework to allow easy use by any
[Express](http://expressjs.com/)-based application. Like the module on which it
is based, [passport-oauth2](https://github.com/jaredhanson/passport-oauth2), its
functionality is designed to be generic enough for use with any OAuth2-compliant
implementation which accepts password grants and can be subclassed for
provider-specific functionality, including user profile.

## Installation

	$ npm install passport-oauth2-password-grant

## Usage

#### Generic Configuration

Like passport-oauth2, the token grant endpoint and OAuth2 client ID are
passed as options to the strategy constructor. It also requires a `verify()`
callback, which is called when authentication has succeeded and must call the
`done()` callback when it has finished. `verify()` accepts one of the following
prototypes:

	function(accessToken, refreshToken, profile, done);
	function(accessToken, refreshToken, requestParams, profile, done);

The following demonstrates how to construct and use a PasswordGrantStrategy
object:

	var PasswordGrantStrategy = require('passport-oauth2-password-grant');

	passport.use(new PasswordGrantStrategy({
		tokenURL: 'https://www.example.com/oauth2/token',
		clientID: EXAMPLE_CLIENT_ID
	},
	function(accessToken, refreshToken, profile, done) {
		done(null, profile);
	});

Additionally, the `passReqToCallback` and `skipUserProfile` options may be used,
which function identically to the same options for passport-oauth2.

#### Authentication

This is accomplished through the use of `passport.authenticate()` with the
`password-grant` strategy. The username and password to be used for
authentication are to be passed to `passport.authenticate()` as the `username`
and `password` options, respectively. This may be done as in the following
example:

	function authenticate() {
		return function(req, res, next) {
			var username = req.body.username;
			var password = req.body.password;

			passport.authenticate('password-grant', {
				username: username,
				password: password
			})(req, res, next);
		};
	}

	app.get('/auth/handler', authenticate(), function(req, res) {
		res.redirect('/');
	});

#### User Profile Retrieval

In order to retrieve profile information for the authenticating user, a subclass
of PasswordGrantStrategy must be provided which overrides the
`PasswordGrantStrategy.userProfile()` function with prototype
`userProfile(accessToken, done)`. `done()` should be called as
`done(err, profile)`, and `profile` is then passed to the `verify()` callback
provided during configuration.

## Related Modules

* [passport-oauth2](https://github.com/jaredhanson/passport-oauth2)
  – OAuth 2.0 authentication strategy, upon which this module is based
* [passport-http-bearer](https://github.com/jaredhanson/passport-http-bearer)
  – Bearer token authentication strategy for APIs

## Testing

	$ npm install
	$ npm test

## Credits

- [Sean Burke](https://github.com/leftmostcat/) — Module author
- [Jared Hanson](https://github.com/jaredhanson/) – Author of passport-oauth2,
  from which this module was adapted and upon which this module relies

## License

[The MIT License](http://opensource.org/licenses/MIT)
