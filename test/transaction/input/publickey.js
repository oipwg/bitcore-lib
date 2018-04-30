'use strict';

var should = require('chai').should();
var flocore = require('../../..');
var Transaction = flocore.Transaction;
var PrivateKey = flocore.PrivateKey;

describe('PublicKeyInput', function() {

  var utxo = {
    txid: '0fa147b287dacf753fd5f0e9aaf342464555b78960352ec043b9f7289e82e60f',
    vout: 0,
    address: 'oPoBiZJxdHtNYVNhNTspRE8a4id6ytMKzY',
    scriptPubKey: '76a9144bfe7033b03d04a9143203cfb8350cad125ebfa488ac',
    amount: 0.001,
    confirmations: 104,
    spendable: true
  };
  var privateKey = PrivateKey.fromWIF('cSY2jbTDyPhmEx94TD72NwuHQ4J4pxzMEjj8G1Nc7c1eptCnevza');
  var address = privateKey.toAddress();
  utxo.address.should.equal(address.toString());

  var destKey = new PrivateKey();

  it('will correctly sign a publickey out transaction', function() {
    var tx = new Transaction();
    tx.from(utxo);
    tx.to(destKey.toAddress(), 10000);
    tx.sign(privateKey);
    tx.inputs[0].script.toBuffer().length.should.be.above(0);
  });

  it('count can count missing signatures', function() {
    var tx = new Transaction();
    tx.from(utxo);
    tx.to(destKey.toAddress(), 10000);
    var input = tx.inputs[0];
    input.isFullySigned().should.equal(false);
    tx.sign(privateKey);
    input.isFullySigned().should.equal(true);
  });

  it('it\'s size can be estimated', function() {
    var tx = new Transaction();
    tx.from(utxo);
    tx.to(destKey.toAddress(), 10000);
    var input = tx.inputs[0];
    input._estimateSize().should.equal(107);
  });

  it('it\'s signature can be removed', function() {
    var tx = new Transaction();
    tx.from(utxo);
    tx.to(destKey.toAddress(), 10000);
    var input = tx.inputs[0];
    tx.sign(privateKey);
    input.isFullySigned().should.equal(true);
    input.clearSignatures();
    input.isFullySigned().should.equal(false);
  });

  it('returns an empty array if private key mismatches', function() {
    var tx = new Transaction();
    tx.from(utxo);
    tx.to(destKey.toAddress(), 10000);
    var input = tx.inputs[0];
    var signatures = input.getSignatures(tx, new PrivateKey(), 0);
    signatures.length.should.equal(0);
  });

});
