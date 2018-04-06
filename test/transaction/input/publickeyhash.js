'use strict';
/* jshint unused: false */

var should = require('chai').should();
var expect = require('chai').expect;
var _ = require('lodash');

var flocore = require('../../..');
var Transaction = flocore.Transaction;
var PrivateKey = flocore.PrivateKey;
var Address = flocore.Address;
var Script = flocore.Script;
var Networks = flocore.Networks;
var Signature = flocore.crypto.Signature;

describe('PublicKeyHashInput', function() {

  var privateKey = new PrivateKey('cSY2jbTDyPhmEx94TD72NwuHQ4J4pxzMEjj8G1Nc7c1eptCnevza');
  var publicKey = privateKey.publicKey;
  var address = new Address(publicKey, Networks.livenet);

  var output = {
    address: 'oPoBiZJxdHtNYVNhNTspRE8a4id6ytMKzY',
    txId: '0fa147b287dacf753fd5f0e9aaf342464555b78960352ec043b9f7289e82e60f',
    outputIndex: 0,
    script: new Script(address),
    satoshis: 1000000
  };
  it('can count missing signatures', function() {
    var transaction = new Transaction()
      .from(output)
      .to(address, 1000000);
    var input = transaction.inputs[0];

    input.isFullySigned().should.equal(false);
    transaction.sign(privateKey);
    input.isFullySigned().should.equal(true);
  });
  it('it\'s size can be estimated', function() {
    var transaction = new Transaction()
      .from(output)
      .to(address, 1000000);
    var input = transaction.inputs[0];
    input._estimateSize().should.equal(107);
  });
  it('it\'s signature can be removed', function() {
    var transaction = new Transaction()
      .from(output)
      .to(address, 1000000);
    var input = transaction.inputs[0];

    transaction.sign(privateKey);
    input.clearSignatures();
    input.isFullySigned().should.equal(false);
  });
  it('returns an empty array if private key mismatches', function() {
    var transaction = new Transaction()
      .from(output)
      .to(address, 1000000);
    var input = transaction.inputs[0];
    var signatures = input.getSignatures(transaction, new PrivateKey(), 0);
    signatures.length.should.equal(0);
  });
});
