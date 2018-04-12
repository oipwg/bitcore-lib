'use strict';

/* jshint maxstatements: 30 */

var chai = require('chai');
var should = chai.should();
var expect = chai.expect;

var flocore = require('..');
var PublicKey = flocore.PublicKey;
var Address = flocore.Address;
var Script = flocore.Script;
var Networks = flocore.Networks;

var validbase58 = require('./data/florincoind/base58_keys_valid.json');
var invalidbase58 = require('./data/florincoind/base58_keys_invalid.json');

describe('Address', function() {

  var addressbuffer = new Buffer('23c3e217d7fda84485390a9b3a3160c2cd3bd234aa', 'hex');
  var pubkeyhash = new Buffer('c3e217d7fda84485390a9b3a3160c2cd3bd234aa', 'hex');
  var buf = Buffer.concat([new Buffer([0]), pubkeyhash]);
  var str = 'FPgr5SBjii5VTRjqxgWYPN4byyY7eS9RQG';

  it('can\'t build without data', function() {
    (function() {
      return new Address();
    }).should.throw('First argument is required, please include address data.');
  });

  it('should throw an error because of bad network param', function() {
    (function() {
      return new Address(PKHLivenet[0], 'main', 'pubkeyhash');
    }).should.throw('Second argument must be "livenet" or "testnet".');
  });

  it('should throw an error because of bad type param', function() {
    (function() {
      return new Address(PKHLivenet[0], 'livenet', 'pubkey');
    }).should.throw('Third argument must be "pubkeyhash" or "scripthash"');
  });

  describe('florincoind compliance', function() {
    validbase58.map(function(d) {
      if (!d[2].isPrivkey) {
        it('should describe address ' + d[0] + ' as valid', function() {
          var type;
          if (d[2].addrType === 'script') {
            type = 'scripthash';
          } else if (d[2].addrType === 'pubkey') {
            type = 'pubkeyhash';
          }
          var network = 'livenet';
          if (d[2].isTestnet) {
            network = 'testnet';
          }
          return new Address(d[0], network, type);
        });
      }
    });
    invalidbase58.map(function(d) {
      it('should describe input ' + d[0].slice(0, 10) + '... as invalid', function() {
        expect(function() {
          return new Address(d[0]);
        }).to.throw(Error);
      });
    });
  });

  // livenet valid
  var PKHLivenet = [
    'FR4HPLm1a9Zp9ZUPX5oGievMjKti7CjVLP',
    'FAX1jEfEc7NtyCrY6doYQVLojAWWaXxfQg',
    'FN589LzUWJw2hoLFoVsvCZr9EwZYTsbsE2',
    'FM8dUWY9iwXxuqCZJHbsB46GQyk1X5ZqH1',
    '    FJTsfUvWAPbC9xe27Zkxt9aqnyYezYTEc4   \t\n'
  ];

  // livenet p2sh
  var P2SHLivenet = [
    '4c7H1T2yvizgzCnrv72qa5q9JoE2N9Lu3o',
    '4GyP6UAaeEodghbyAQX6eSEJJDYUvYcHHt',
    '4PnqKST4U1iwCx6T4qLpAUSnKMZF3cUvou',
    '4LjiDJWT6Hia5sYY4PszhLjF5tiHLNyihb',
    '\t \n4XzbQmEoTPfMHWHHq2HotFDRnDjSPtMd8F \r'
  ];

  // testnet p2sh
  var P2SHTestnet = [
    '2NhbHS6z4HcXSFDYY1NRv2MrobdexPYyCh9',
    '2NhbHf7mqqmdH8yUUX5TNZ6VVfcbGw6Wzz5',
    '2NiT5S3BU7v4PioPwfckUP83Fypf2FFWNzL',
    '2NgyNYwfpiEdLzDgAFM21ZNr4FmhWEAsyBc'
  ];

  //livenet bad checksums
  var badChecksums = [
    '15vkcKf7gB23wLAnZLmbVuMiiVDc3nq4a2',
    '1A6ut1tWnUq1SEQLMr4ttDh24wcbj4w2TT',
    '1BpbpfLdY7oBS9gK7aDXgvMgr1DpvNH3B2',
    '1Jz2yCRd5ST1p2gUqFB5wsSQfdmEJaffg7'
  ];

  //livenet non-base58
  var nonBase58 = [
    '15vkcKf7g#23wLAnZLmb$uMiiVDc3nq4a2',
    '1A601ttWnUq1SEQLMr4ttDh24wcbj4w2TT',
    '1BpbpfLdY7oBS9gK7aIXgvMgr1DpvNH3B2',
    '1Jz2yCRdOST1p2gUqFB5wsSQfdmEJaffg7'
  ];

  //testnet valid
  var PKHTestnet = [
    'oN2BxyDaWPASPtp9k8Fas5Y4mTexoU6Frr',
    'oKKLdSsRdyWuTXdebpKqNZ9B9ZS3zVUPRg',
    'oHLfnovCLV8gyDMUvh49Wiq1brHCUnKxbD',
    'oZbuYNHL7BUz671FyFu1yp6h61HGqyf8EM'
  ];

  describe('validation', function() {

    it('getValidationError detects network mismatchs', function() {
      var error = Address.getValidationError('37BahqRsFrAd3qLiNNwLNV3AWMRD7itxTo', 'testnet');
      should.exist(error);
    });

    it('isValid returns true on a valid address', function() {
      var valid = Address.isValid('FLCqAZWitvE5G2qVRS6u2nB3RtZzZBGrsT', 'livenet');
      valid.should.equal(true);
    });

    it('isValid returns false on network mismatch', function() {
      var valid = Address.isValid('FLCqAZWitvE5G2qVRS6u2nB3RtZzZBGrsT', 'testnet');
      valid.should.equal(false);
    });

    it('validates correctly the P2PKH test vector', function() {
      for (var i = 0; i < PKHLivenet.length; i++) {
        var error = Address.getValidationError(PKHLivenet[i]);
        should.not.exist(error);
      }
    });

    it('validates correctly the P2SH test vector', function() {
      for (var i = 0; i < P2SHLivenet.length; i++) {
        var error = Address.getValidationError(P2SHLivenet[i]);
        should.not.exist(error);
      }
    });

    it('validates correctly the P2SH testnet test vector', function() {
      for (var i = 0; i < P2SHTestnet.length; i++) {
        var error = Address.getValidationError(P2SHTestnet[i], 'testnet');
        should.not.exist(error);
      }
    });

    it('rejects correctly the P2PKH livenet test vector with "testnet" parameter', function() {
      for (var i = 0; i < PKHLivenet.length; i++) {
        var error = Address.getValidationError(PKHLivenet[i], 'testnet');
        should.exist(error);
      }
    });

    it('validates correctly the P2PKH livenet test vector with "livenet" parameter', function() {
      for (var i = 0; i < PKHLivenet.length; i++) {
        var error = Address.getValidationError(PKHLivenet[i], 'livenet');
        should.not.exist(error);
      }
    });

    it('should not validate if checksum is invalid', function() {
      for (var i = 0; i < badChecksums.length; i++) {
        var error = Address.getValidationError(badChecksums[i], 'livenet', 'pubkeyhash');
        should.exist(error);
        error.message.should.equal('Checksum mismatch');
      }
    });

    it('should not validate on a network mismatch', function() {
      var error, i;
      for (i = 0; i < PKHLivenet.length; i++) {
        error = Address.getValidationError(PKHLivenet[i], 'testnet', 'pubkeyhash');
        should.exist(error);
        error.message.should.equal('Address has mismatched network type.');
      }
      for (i = 0; i < PKHTestnet.length; i++) {
        error = Address.getValidationError(PKHTestnet[i], 'livenet', 'pubkeyhash');
        should.exist(error);
        error.message.should.equal('Address has mismatched network type.');
      }
    });

    it('should not validate on a type mismatch', function() {
      for (var i = 0; i < PKHLivenet.length; i++) {
        var error = Address.getValidationError(PKHLivenet[i], 'livenet', 'scripthash');
        should.exist(error);
        error.message.should.equal('Address has mismatched type.');
      }
    });

    it('should not validate on non-base58 characters', function() {
      for (var i = 0; i < nonBase58.length; i++) {
        var error = Address.getValidationError(nonBase58[i], 'livenet', 'pubkeyhash');
        should.exist(error);
        error.message.should.equal('Non-base58 character');
      }
    });

    it('testnet addresses are validated correctly', function() {
      for (var i = 0; i < PKHTestnet.length; i++) {
        var error = Address.getValidationError(PKHTestnet[i], 'testnet');
        should.not.exist(error);
      }
    });

    it('addresses with whitespace are validated correctly', function() {
      var ws = '  \r \t    \n FHtwd1scrPk19F1aAu8rbRFtqjqH6jzuSr \t \n            \r';
      var error = Address.getValidationError(ws);
      should.not.exist(error);
      Address.fromString(ws).toString().should.equal('FHtwd1scrPk19F1aAu8rbRFtqjqH6jzuSr');
    });
  });

  describe('instantiation', function() {
    it('can be instantiated from another address', function() {
      var address = Address.fromBuffer(addressbuffer);
      var address2 = new Address({
        hashBuffer: address.hashBuffer,
        network: address.network,
        type: address.type
      });
      address.toString().should.equal(address2.toString());
    });
  });

  describe('encodings', function() {

    it('should make an address from a buffer', function() {
      Address.fromBuffer(addressbuffer).toString().should.equal(str);
      new Address(addressbuffer).toString().should.equal(str);
      new Address(addressbuffer).toString().should.equal(str);
    });

    it('should make an address from a string', function() {
      Address.fromString(str).toString().should.equal(str);
      new Address(str).toString().should.equal(str);
    });

    it('should make an address using a non-string network', function() {
      Address.fromString(str, Networks.livenet).toString().should.equal(str);
    });

    it('should throw with bad network param', function() {
      (function(){
        Address.fromString(str, 'somenet');
      }).should.throw('Unknown network');
    });

    it('should error because of unrecognized data format', function() {
      (function() {
        return new Address(new Error());
      }).should.throw(flocore.errors.InvalidArgument);
    });

    it('should error because of incorrect format for pubkey hash', function() {
      (function() {
        return new Address.fromPublicKeyHash('notahash');
      }).should.throw('Address supplied is not a buffer.');
    });

    it('should error because of incorrect format for script hash', function() {
      (function() {
        return new Address.fromScriptHash('notascript');
      }).should.throw('Address supplied is not a buffer.');
    });

    it('should error because of incorrect type for transform buffer', function() {
      (function() {
        return Address._transformBuffer('notabuffer');
      }).should.throw('Address supplied is not a buffer.');
    });

    it('should error because of incorrect length buffer for transform buffer', function() {
      (function() {
        return Address._transformBuffer(new Buffer(20));
      }).should.throw('Address buffers must be exactly 21 bytes.');
    });

    it('should error because of incorrect type for pubkey transform', function() {
      (function() {
        return Address._transformPublicKey(new Buffer(20));
      }).should.throw('Address must be an instance of PublicKey.');
    });

    it('should error because of incorrect type for script transform', function() {
      (function() {
        return Address._transformScript(new Buffer(20));
      }).should.throw('Invalid Argument: script must be a Script instance');
    });

    it('should error because of incorrect type for string transform', function() {
      (function() {
        return Address._transformString(new Buffer(20));
      }).should.throw('data parameter supplied is not a string.');
    });

    it('should make an address from a pubkey hash buffer', function() {
      var hash = pubkeyhash; //use the same hash
      var a = Address.fromPublicKeyHash(hash, 'livenet');
      a.network.should.equal(Networks.livenet);
      a.toString().should.equal(str);
      var b = Address.fromPublicKeyHash(hash, 'testnet');
      b.network.should.equal(Networks.testnet);
      b.type.should.equal('pubkeyhash');
      new Address(hash, 'livenet').toString().should.equal(str);
    });

    it('should make an address using the default network', function() {
      var hash = pubkeyhash; //use the same hash
      var network = Networks.defaultNetwork;
      Networks.defaultNetwork = Networks.livenet;
      var a = Address.fromPublicKeyHash(hash);
      a.network.should.equal(Networks.livenet);
      // change the default
      Networks.defaultNetwork = Networks.testnet;
      var b = Address.fromPublicKeyHash(hash);
      b.network.should.equal(Networks.testnet);
      // restore the default
      Networks.defaultNetwork = network;
    });

    it('should throw an error for invalid length hashBuffer', function() {
      (function() {
        return Address.fromPublicKeyHash(buf);
      }).should.throw('Address hashbuffers must be exactly 20 bytes.');
    });

    it('should make this address from a compressed pubkey', function() {
      var pubkey = new PublicKey('0342552965cc8f4110141becda42bb6c152e5c707936b2271bf5bda749039e1504');
      var address = Address.fromPublicKey(pubkey, 'livenet');
      address.toString().should.equal('F6LgZe9BrMtufKJqGLufXNMsXBXhiXt2r2');
    });

    it('should use the default network for pubkey', function() {
      var pubkey = new PublicKey('023d29f6da8e5a1b86461d8a781e81f1eacdcd3a86fa59f3d9356d3e14b07edcc3');
      var address = Address.fromPublicKey(pubkey);
      address.network.should.equal(Networks.defaultNetwork);
    });

    it('should make this address from an uncompressed pubkey', function() {
      var pubkey = new PublicKey('03e0cdc0ec449c6c80f1725f1519bfbadc0cd65e8004cd6994772fa6798788c889');
      var a = Address.fromPublicKey(pubkey, 'livenet');
      a.toString().should.equal('FBfqtdvp8HCCu2KyGxNn9Z1kTBXtS5SpUz');
      var b = new Address(pubkey, 'livenet', 'pubkeyhash');
      b.toString().should.equal('FBfqtdvp8HCCu2KyGxNn9Z1kTBXtS5SpUz');
    });

    it('should classify from a custom network', function() {
      var custom = {
        name: 'customnetwork',
        pubkeyhash: 0x1c,
        privatekey: 0x1e,
        scripthash: 0x28,
        xpubkey: 0x02e8de8f,
        xprivkey: 0x02e8da54,
        networkMagic: 0x0c110907,
        port: 7333
      };
      var addressString = 'CX4WePxBwq1Y6u7VyMJfmmitE7GiTgC9aE';
      Networks.add(custom);
      var network = Networks.get('customnetwork');
      var address = Address.fromString(addressString);
      address.type.should.equal(Address.PayToPublicKeyHash);
      address.network.should.equal(network);
      Networks.remove(network);
    });

    describe('from a script', function() {
      it('should fail to build address from a non p2sh,p2pkh script', function() {
        var s = new Script('OP_CHECKMULTISIG');
        (function() {
          return new Address(s);
        }).should.throw('needs to be p2pkh in, p2pkh out, p2sh in, or p2sh out');
      });
      it('should make this address from a p2pkh output script', function() {
        var s = new Script('OP_DUP OP_HASH160 20 0x126d746b55571fd3dbe2f992df073bb47a24668f OP_EQUALVERIFY OP_CHECKSIG');
        var buf = s.toBuffer();
        var a = Address.fromScript(s, 'livenet');
        a.toString().should.equal('F7WYkJcpQvJrpQb1Jc7gD3S2De8xVuFBQU');
        var b = new Address(s, 'livenet');
        b.toString().should.equal('F7WYkJcpQvJrpQb1Jc7gD3S2De8xVuFBQU');
      });

      it('should make this address from a p2sh input script', function() {
        var s = Script.fromString('OP_HASH160 20 0xb967066b152ff93264741d32f8a7ee53ea2b40a1 OP_EQUAL');
        var a = Address.fromScript(s, 'livenet');
        a.toString().should.equal('4Wc9JfZLZqz9gz1hmUTaPQ9jELXp7Xv8Km');
        var b = new Address(s, 'livenet');
        b.toString().should.equal('4Wc9JfZLZqz9gz1hmUTaPQ9jELXp7Xv8Km');
      });

      it('returns the same address if the script is a pay to public key hash out', function() {
        var address = 'F7WYkJcpQvJrpQb1Jc7gD3S2De8xVuFBQU';
        var script = Script.buildPublicKeyHashOut(new Address(address));
        Address(script, Networks.livenet).toString().should.equal(address);
      });
      it('returns the same address if the script is a pay to script hash out', function() {
        var address = '4Wc9JfZLZqz9gz1hmUTaPQ9jELXp7Xv8Km';
        var script = Script.buildScriptHashOut(new Address(address));
        Address(script, Networks.livenet).toString().should.equal(address);
      });
    });

    it('should derive from this known address string livenet', function() {
      var address = new Address(str);
      var buffer = address.toBuffer();
      var slice = buffer.slice(1);
      var sliceString = slice.toString('hex');
      sliceString.should.equal(pubkeyhash.toString('hex'));
    });

    it('should derive from this known address string testnet', function() {
      var a = new Address(PKHTestnet[0], 'testnet');
      var b = new Address(a.toString());
      b.toString().should.equal(PKHTestnet[0]);
      b.network.should.equal(Networks.testnet);
    });

    it('should derive from this known address string livenet scripthash', function() {
      var a = new Address(P2SHLivenet[0], 'livenet', 'scripthash');
      var b = new Address(a.toString());
      b.toString().should.equal(P2SHLivenet[0]);
    });

    it('should derive from this known address string testnet scripthash', function() {
      var address = new Address(P2SHTestnet[0], 'testnet', 'scripthash');
      address = new Address(address.toString());
      address.toString().should.equal(P2SHTestnet[0]);
    });

  });

  describe('#toBuffer', function() {

    it('3c3fa3d4adcaf8f52d5b1843975e122548269937 corresponds to hash 16VZnHwRhwrExfeHFHGjwrgEMq8VcYPs9r', function() {
      var address = new Address(str);
      address.toBuffer().slice(1).toString('hex').should.equal(pubkeyhash.toString('hex'));
    });

  });

  describe('#object', function() {

    it('roundtrip to-from-to', function() {
      var obj = new Address(str).toObject();
      var address = Address.fromObject(obj);
      address.toString().should.equal(str);
    });

    it('will fail with invalid state', function() {
      expect(function() {
        return Address.fromObject('¹');
      }).to.throw(flocore.errors.InvalidState);
    });
  });

  describe('#toString', function() {

    it('livenet pubkeyhash address', function() {
      var address = new Address(str);
      address.toString().should.equal(str);
    });

    it('scripthash address', function() {
      var address = new Address(P2SHLivenet[0]);
      address.toString().should.equal(P2SHLivenet[0]);
    });

    it('testnet scripthash address', function() {
      var address = new Address(P2SHTestnet[0]);
      address.toString().should.equal(P2SHTestnet[0]);
    });

    it('testnet pubkeyhash address', function() {
      var address = new Address(PKHTestnet[0]);
      address.toString().should.equal(PKHTestnet[0]);
    });

  });

  describe('#inspect', function() {
    it('should output formatted output correctly', function() {
      var address = new Address(str);
      var output = '<Address: FPgr5SBjii5VTRjqxgWYPN4byyY7eS9RQG, type: pubkeyhash, network: livenet>';
      address.inspect().should.equal(output);
    });
  });

  describe('questions about the address', function() {
    it('should detect a P2SH address', function() {
      new Address(P2SHLivenet[0]).isPayToScriptHash().should.equal(true);
      new Address(P2SHLivenet[0]).isPayToPublicKeyHash().should.equal(false);
      new Address(P2SHTestnet[0]).isPayToScriptHash().should.equal(true);
      new Address(P2SHTestnet[0]).isPayToPublicKeyHash().should.equal(false);
    });
    it('should detect a Pay To PubkeyHash address', function() {
      new Address(PKHLivenet[0]).isPayToPublicKeyHash().should.equal(true);
      new Address(PKHLivenet[0]).isPayToScriptHash().should.equal(false);
      new Address(PKHTestnet[0]).isPayToPublicKeyHash().should.equal(true);
      new Address(PKHTestnet[0]).isPayToScriptHash().should.equal(false);
    });
  });

  it('throws an error if it couldn\'t instantiate', function() {
    expect(function() {
      return new Address(1);
    }).to.throw(TypeError);
  });
  it('can roundtrip from/to a object', function() {
    var address = new Address(P2SHLivenet[0]);
    expect(new Address(address.toObject()).toString()).to.equal(P2SHLivenet[0]);
  });

  it('will use the default network for an object', function() {
    var obj = {
      hash: 'FPgr5SBjii5VTRjqxgWYPN4byyY7eS9RQG',
      type: 'scripthash'
    };
    var address = new Address(obj);
    address.network.should.equal(Networks.defaultNetwork);
  });

  describe('creating a P2SH address from public keys', function() {

    var public1 = '026f803dd1afb606e4e543c7d06c7f483a3cacdb6f596ff301737be3bb08f842d6';
    var public2 = '029aba974a7cab1f6d5da182626eda7010b4b24a5d1feed1b0db5a95ea4372bd62';
    var public3 = '03f621917b73f6ecca9b7919f2d024e2fc71de56d1fd39539bc43e79b8dcbbf8d0';
    var publics = [public1, public2, public3];

    it('can create an address from a set of public keys', function() {
      var address = Address.createMultisig(publics, 2, Networks.livenet);
      address.toString().should.equal('4Q1e4gD65QvRYdWQKvAQ8dGzXF6BF6Vu9v');
      address = new Address(publics, 2, Networks.livenet);
      address.toString().should.equal('4Q1e4gD65QvRYdWQKvAQ8dGzXF6BF6Vu9v');
    });

    it('works on testnet also', function() {
      var address = Address.createMultisig(publics, 2, Networks.testnet);
      address.toString().should.equal('2NrEF9JqpygxtvyzrydSxGSzU763QEaH9Je');
    });

    it('can create an address from a set of public keys with a nested witness program', function() {
      var address = Address.createMultisig(publics, 2, Networks.livenet, true);
      address.toString().should.equal('3PpK1bBqUmPK3Q6QPSUK7BQSZ1DMWL6aes');
    });

    it('can also be created by Address.createMultisig', function() {
      var address = Address.createMultisig(publics, 2);
      var address2 = Address.createMultisig(publics, 2);
      address.toString().should.equal(address2.toString());
    });

    it('fails if invalid array is provided', function() {
      expect(function() {
        return Address.createMultisig([], 3, 'testnet');
      }).to.throw('Number of required signatures must be less than or equal to the number of public keys');
    });
  });

});
