var strategy = require('..'),
    expect = require('chai').expect;

describe('passport-oauth2-password-grant', function() {
  it('should export Strategy constructor directly from package', function() {
    expect(strategy).to.be.a('function');
    expect(strategy).to.equal(strategy.Strategy);
  });
});
