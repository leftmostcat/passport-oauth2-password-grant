var PasswordGrantStrategy = require('..'),
    expect = require('chai').expect;

describe('PasswordGrantStrategy', function() {
  var strategy = new PasswordGrantStrategy({
    tokenURL: 'https://www.example.com/oauth2/token',
    clientID: 'foo'
  }, function() {});

  it('should be named password-grant', function() {
    expect(strategy.name).to.equal('password-grant');
  });

  it('should throw if constructed without a verify callback', function() {
    expect(function() {
      new PasswordGrantStrategy({
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'foo'
      });
    }).to.throw(TypeError, 'PasswordGrantStrategy requires a verify callback');
  });

  it('should throw if constructed without a tokenURL option', function() {
    expect(function() {
      new PasswordGrantStrategy({
        clientID: 'foo'
      }, function() {});
    }).to.throw(TypeError, 'PasswordGrantStrategy requires a tokenURL option');
  });

  it('should throw if constructed without a clientID option', function() {
    expect(function() {
      new PasswordGrantStrategy({
        tokenURL: 'https://www.example.com/oauth2/token'
      }, function() {});
    }).to.throw(TypeError, 'PasswordGrantStrategy requires a clientID option');
  });

  it('should throw if constructed with only a verify callback', function() {
    expect(function() {
      new PasswordGrantStrategy(function() {});
    }).to.throw(TypeError, 'PasswordGrantStrategy requires a tokenURL option');
  });
});
