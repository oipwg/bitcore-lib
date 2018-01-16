"use strict";

var should = require("chai").should();
var flocore = require("../");

describe('#versionGuard', function() {
  it('global._flocore should be defined', function() {
    should.equal(global._flocore, flocore.version);
  });

  it('throw an error if version is already defined', function() {
    (function() {
      flocore.versionGuard('version');
    }).should.throw('More than one instance of flocore');
  });
});
