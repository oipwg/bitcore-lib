'use strict';

// Relax some linter options:
//   * quote marks so "m/0'/1/2'/" doesn't need to be scaped
//   * too many tests, maxstatements -> 100
//   * store test vectors at the end, latedef: false
//   * should call is never defined
/* jshint quotmark: false */
/* jshint latedef: false */
/* jshint maxstatements: 100 */
/* jshint unused: false */

var _ = require('lodash');
var should = require('chai').should();
var expect = require('chai').expect;
var sinon = require('sinon');
var flocore = require('..');
var Networks = flocore.Networks;
var HDPrivateKey = flocore.HDPrivateKey;
var HDPublicKey = flocore.HDPublicKey;

describe('HDKeys building with static methods', function() {
  var classes = [HDPublicKey, HDPrivateKey];
  var clazz, index;

  _.each(classes, function(clazz) {
    var expectStaticMethodFail = function(staticMethod, argument, message) {
      expect(clazz[staticMethod].bind(null, argument)).to.throw(message);
    };
    it(clazz.name + ' fromJSON checks that a valid JSON is provided', function() {
      var errorMessage = 'Invalid Argument: No valid argument was provided';
      var method = 'fromObject';
      expectStaticMethodFail(method, undefined, errorMessage);
      expectStaticMethodFail(method, null, errorMessage);
      expectStaticMethodFail(method, 'invalid JSON', errorMessage);
      expectStaticMethodFail(method, '{\'singlequotes\': true}', errorMessage);
    });
    it(clazz.name + ' fromString checks that a string is provided', function() {
      var errorMessage = 'No valid string was provided';
      var method = 'fromString';
      expectStaticMethodFail(method, undefined, errorMessage);
      expectStaticMethodFail(method, null, errorMessage);
      expectStaticMethodFail(method, {}, errorMessage);
    });
    it(clazz.name + ' fromObject checks that an object is provided', function() {
      var errorMessage = 'No valid argument was provided';
      var method = 'fromObject';
      expectStaticMethodFail(method, undefined, errorMessage);
      expectStaticMethodFail(method, null, errorMessage);
      expectStaticMethodFail(method, '', errorMessage);
    });
  });
});

describe('BIP32 compliance', function() {

  it('should initialize test vector 1 from the extended public key', function() {
    new HDPublicKey(vector1_m_public).xpubkey.should.equal(vector1_m_public);
  });

  it('should initialize test vector 1 from the extended private key', function() {
    new HDPrivateKey(vector1_m_private).xprivkey.should.equal(vector1_m_private);
  });

  it('can initialize a public key from an extended private key', function() {
    new HDPublicKey(vector1_m_private).xpubkey.should.equal(vector1_m_public);
  });

  it('toString should be equal to the `xpubkey` member', function() {
    var privateKey = new HDPrivateKey(vector1_m_private);
    privateKey.toString().should.equal(privateKey.xprivkey);
  });

  it('toString should be equal to the `xpubkey` member', function() {
    var publicKey = new HDPublicKey(vector1_m_public);
    publicKey.toString().should.equal(publicKey.xpubkey);
  });

  it('should get the extended public key from the extended private key for test vector 1', function() {
    HDPrivateKey(vector1_m_private).xpubkey.should.equal(vector1_m_public);
  });

  it("should get m/0' ext. private key from test vector 1", function() {
    var privateKey = new HDPrivateKey(vector1_m_private).derive("m/0'");
    privateKey.xprivkey.should.equal(vector1_m0h_private);
  });

  it("should get m/0' ext. public key from test vector 1", function() {
    HDPrivateKey(vector1_m_private).derive("m/0'")
      .xpubkey.should.equal(vector1_m0h_public);
  });

  it("should get m/0'/1 ext. private key from test vector 1", function() {
    HDPrivateKey(vector1_m_private).derive("m/0'/1")
      .xprivkey.should.equal(vector1_m0h1_private);
  });

  it("should get m/0'/1 ext. public key from test vector 1", function() {
    HDPrivateKey(vector1_m_private).derive("m/0'/1")
      .xpubkey.should.equal(vector1_m0h1_public);
  });

  it("should get m/0'/1 ext. public key from m/0' public key from test vector 1", function() {
    var derivedPublic = HDPrivateKey(vector1_m_private).derive("m/0'").hdPublicKey.derive("m/1");
    derivedPublic.xpubkey.should.equal(vector1_m0h1_public);
  });

  it("should get m/0'/1/2' ext. private key from test vector 1", function() {
    var privateKey = new HDPrivateKey(vector1_m_private);
    var derived = privateKey.derive("m/0'/1/2'");
    derived.xprivkey.should.equal(vector1_m0h12h_private);
  });

  it("should get m/0'/1/2' ext. public key from test vector 1", function() {
    HDPrivateKey(vector1_m_private).derive("m/0'/1/2'")
      .xpubkey.should.equal(vector1_m0h12h_public);
  });

  it("should get m/0'/1/2'/2 ext. private key from test vector 1", function() {
    HDPrivateKey(vector1_m_private).derive("m/0'/1/2'/2")
      .xprivkey.should.equal(vector1_m0h12h2_private);
  });

  it("should get m/0'/1/2'/2 ext. public key from m/0'/1/2' public key from test vector 1", function() {
    var derived = HDPrivateKey(vector1_m_private).derive("m/0'/1/2'").hdPublicKey;
    derived.derive("m/2").xpubkey.should.equal(vector1_m0h12h2_public);
  });

  it("should get m/0'/1/2h/2 ext. public key from test vector 1", function() {
    HDPrivateKey(vector1_m_private).derive("m/0'/1/2'/2")
      .xpubkey.should.equal(vector1_m0h12h2_public);
  });

  it("should get m/0'/1/2h/2/1000000000 ext. private key from test vector 1", function() {
    HDPrivateKey(vector1_m_private).derive("m/0'/1/2'/2/1000000000")
      .xprivkey.should.equal(vector1_m0h12h21000000000_private);
  });

  it("should get m/0'/1/2h/2/1000000000 ext. public key from test vector 1", function() {
    HDPrivateKey(vector1_m_private).derive("m/0'/1/2'/2/1000000000")
      .xpubkey.should.equal(vector1_m0h12h21000000000_public);
  });

  it("should get m/0'/1/2'/2/1000000000 ext. public key from m/0'/1/2'/2 public key from test vector 1", function() {
    var derived = HDPrivateKey(vector1_m_private).derive("m/0'/1/2'/2").hdPublicKey;
    derived.derive("m/1000000000").xpubkey.should.equal(vector1_m0h12h21000000000_public);
  });

  it('should initialize test vector 2 from the extended public key', function() {
    HDPublicKey(vector2_m_public).xpubkey.should.equal(vector2_m_public);
  });

  it('should initialize test vector 2 from the extended private key', function() {
    HDPrivateKey(vector2_m_private).xprivkey.should.equal(vector2_m_private);
  });

  it('should get the extended public key from the extended private key for test vector 2', function() {
    HDPrivateKey(vector2_m_private).xpubkey.should.equal(vector2_m_public);
  });

  it("should get m/0 ext. private key from test vector 2", function() {
    HDPrivateKey(vector2_m_private).derive(0).xprivkey.should.equal(vector2_m0_private);
  });

  it("should get m/0 ext. public key from test vector 2", function() {
    HDPrivateKey(vector2_m_private).derive(0).xpubkey.should.equal(vector2_m0_public);
  });

  it("should get m/0 ext. public key from m public key from test vector 2", function() {
    HDPrivateKey(vector2_m_private).hdPublicKey.derive(0).xpubkey.should.equal(vector2_m0_public);
  });

  it("should get m/0/2147483647h ext. private key from test vector 2", function() {
    HDPrivateKey(vector2_m_private).derive("m/0/2147483647'")
      .xprivkey.should.equal(vector2_m02147483647h_private);
  });

  it("should get m/0/2147483647h ext. public key from test vector 2", function() {
    HDPrivateKey(vector2_m_private).derive("m/0/2147483647'")
      .xpubkey.should.equal(vector2_m02147483647h_public);
  });

  it("should get m/0/2147483647h/1 ext. private key from test vector 2", function() {
    HDPrivateKey(vector2_m_private).derive("m/0/2147483647'/1")
      .xprivkey.should.equal(vector2_m02147483647h1_private);
  });

  it("should get m/0/2147483647h/1 ext. public key from test vector 2", function() {
    HDPrivateKey(vector2_m_private).derive("m/0/2147483647'/1")
      .xpubkey.should.equal(vector2_m02147483647h1_public);
  });

  it("should get m/0/2147483647h/1 ext. public key from m/0/2147483647h public key from test vector 2", function() {
    var derived = HDPrivateKey(vector2_m_private).derive("m/0/2147483647'").hdPublicKey;
    derived.derive(1).xpubkey.should.equal(vector2_m02147483647h1_public);
  });

  it("should get m/0/2147483647h/1/2147483646h ext. private key from test vector 2", function() {
    HDPrivateKey(vector2_m_private).derive("m/0/2147483647'/1/2147483646'")
      .xprivkey.should.equal(vector2_m02147483647h12147483646h_private);
  });

  it("should get m/0/2147483647h/1/2147483646h ext. public key from test vector 2", function() {
    HDPrivateKey(vector2_m_private).derive("m/0/2147483647'/1/2147483646'")
      .xpubkey.should.equal(vector2_m02147483647h12147483646h_public);
  });

  it("should get m/0/2147483647h/1/2147483646h/2 ext. private key from test vector 2", function() {
    HDPrivateKey(vector2_m_private).derive("m/0/2147483647'/1/2147483646'/2")
      .xprivkey.should.equal(vector2_m02147483647h12147483646h2_private);
  });

  it("should get m/0/2147483647h/1/2147483646h/2 ext. public key from test vector 2", function() {
    HDPrivateKey(vector2_m_private).derive("m/0/2147483647'/1/2147483646'/2")
      .xpubkey.should.equal(vector2_m02147483647h12147483646h2_public);
  });

  it("should get m/0/2147483647h/1/2147483646h/2 ext. public key from m/0/2147483647h/2147483646h public key from test vector 2", function() {
    var derivedPublic = HDPrivateKey(vector2_m_private)
      .derive("m/0/2147483647'/1/2147483646'").hdPublicKey;
    derivedPublic.derive("m/2")
      .xpubkey.should.equal(vector2_m02147483647h12147483646h2_public);
  });

  it('should use full 32 bytes for private key data that is hashed (as per bip32)', function() {
    // https://github.com/florincoin/bips/blob/master/bip-0032.mediawiki
    var privateKeyBuffer = new Buffer('00000055378cf5fafb56c711c674143f9b0ee82ab0ba2924f19b64f5ae7cdbfd', 'hex');
    var chainCodeBuffer = new Buffer('9c8a5c863e5941f3d99453e6ba66b328bb17cf0b8dec89ed4fc5ace397a1c089', 'hex');
    var key = HDPrivateKey.fromObject({
      network: 'testnet',
      depth: 0,
      parentFingerPrint: 0,
      childIndex: 0,
      privateKey: privateKeyBuffer,
      chainCode: chainCodeBuffer
    });
    var derived = key.deriveChild("m/44'/0'/0'/0/0'");
    derived.privateKey.toString().should.equal('3348069561d2a0fb925e74bf198762acc47dce7db27372257d2d959a9e6f8aeb');
  });

  it('should NOT use full 32 bytes for private key data that is hashed with nonCompliant flag', function() {
    // This is to test that the previously implemented non-compliant to BIP32
    var privateKeyBuffer = new Buffer('00000055378cf5fafb56c711c674143f9b0ee82ab0ba2924f19b64f5ae7cdbfd', 'hex');
    var chainCodeBuffer = new Buffer('9c8a5c863e5941f3d99453e6ba66b328bb17cf0b8dec89ed4fc5ace397a1c089', 'hex');
    var key = HDPrivateKey.fromObject({
      network: 'testnet',
      depth: 0,
      parentFingerPrint: 0,
      childIndex: 0,
      privateKey: privateKeyBuffer,
      chainCode: chainCodeBuffer
    });
    var derived = key.deriveNonCompliantChild("m/44'/0'/0'/0/0'");
    derived.privateKey.toString().should.equal('4811a079bab267bfdca855b3bddff20231ff7044e648514fa099158472df2836');
  });

  it('should NOT use full 32 bytes for private key data that is hashed with the nonCompliant derive method', function() {
    // This is to test that the previously implemented non-compliant to BIP32
    var privateKeyBuffer = new Buffer('00000055378cf5fafb56c711c674143f9b0ee82ab0ba2924f19b64f5ae7cdbfd', 'hex');
    var chainCodeBuffer = new Buffer('9c8a5c863e5941f3d99453e6ba66b328bb17cf0b8dec89ed4fc5ace397a1c089', 'hex');
    var key = HDPrivateKey.fromObject({
      network: 'testnet',
      depth: 0,
      parentFingerPrint: 0,
      childIndex: 0,
      privateKey: privateKeyBuffer,
      chainCode: chainCodeBuffer
    });
    var derived = key.derive("m/44'/0'/0'/0/0'");
    derived.privateKey.toString().should.equal('4811a079bab267bfdca855b3bddff20231ff7044e648514fa099158472df2836');
  });

  describe('edge cases', function() {
    var sandbox = sinon.sandbox.create();
    afterEach(function() {
      sandbox.restore();
    });
    it('will handle edge case that derived private key is invalid', function() {
      var invalid = new Buffer('0000000000000000000000000000000000000000000000000000000000000000', 'hex');
      var privateKeyBuffer = new Buffer('5f72914c48581fc7ddeb944a9616389200a9560177d24f458258e5b04527bcd1', 'hex');
      var chainCodeBuffer = new Buffer('39816057bba9d952fe87fe998b7fd4d690a1bb58c2ff69141469e4d1dffb4b91', 'hex');
      var unstubbed = flocore.crypto.BN.prototype.toBuffer;
      var count = 0;
      var stub = sandbox.stub(flocore.crypto.BN.prototype, 'toBuffer', function(args) {
        // On the fourth call to the function give back an invalid private key
        // otherwise use the normal behavior.
        count++;
        if (count === 4) {
          return invalid;
        }
        var ret = unstubbed.apply(this, arguments);
        return ret;
      });
      sandbox.spy(flocore.PrivateKey, 'isValid');
      var key = HDPrivateKey.fromObject({
        network: 'testnet',
        depth: 0,
        parentFingerPrint: 0,
        childIndex: 0,
        privateKey: privateKeyBuffer,
        chainCode: chainCodeBuffer
      });
      var derived = key.derive("m/44'");
      derived.privateKey.toString().should.equal('b15bce3608d607ee3a49069197732c656bca942ee59f3e29b4d56914c1de6825');
      flocore.PrivateKey.isValid.callCount.should.equal(2);
    });
    it('will handle edge case that a derive public key is invalid', function() {
      var publicKeyBuffer = new Buffer('029e58b241790284ef56502667b15157b3fc58c567f044ddc35653860f9455d099', 'hex');
      var chainCodeBuffer = new Buffer('39816057bba9d952fe87fe998b7fd4d690a1bb58c2ff69141469e4d1dffb4b91', 'hex');
      var key = new HDPublicKey({
        network: 'testnet',
        depth: 0,
        parentFingerPrint: 0,
        childIndex: 0,
        chainCode: chainCodeBuffer,
        publicKey: publicKeyBuffer
      });
      var unstubbed = flocore.PublicKey.fromPoint;
      flocore.PublicKey.fromPoint = function() {
        flocore.PublicKey.fromPoint = unstubbed;
        throw new Error('Point cannot be equal to Infinity');
      };
      sandbox.spy(key, '_deriveWithNumber');
      var derived = key.derive("m/44");
      key._deriveWithNumber.callCount.should.equal(2);
      key.publicKey.toString().should.equal('029e58b241790284ef56502667b15157b3fc58c567f044ddc35653860f9455d099');
    });
  });

  describe('seed', function() {

    it('should initialize a new BIP32 correctly from test vector 1 seed', function() {
      var seededKey = HDPrivateKey.fromSeed(vector1_master, Networks.livenet);
      seededKey.xprivkey.should.equal(vector1_m_private);
      seededKey.xpubkey.should.equal(vector1_m_public);
    });

    it('should initialize a new BIP32 correctly from test vector 2 seed', function() {
      var seededKey = HDPrivateKey.fromSeed(vector2_master, Networks.livenet);
      seededKey.xprivkey.should.equal(vector2_m_private);
      seededKey.xpubkey.should.equal(vector2_m_public);
    });
  });
});

//test vectors: https://github.com/floblockchain/flo/blob/flo-master/src/test/bip32_tests.cpp#L46
var vector1_master = '000102030405060708090a0b0c0d0e0f';
var vector1_m_public = 'Fpub15bEDvvx1UUJ5idB31kXnq1boZreVC1g4Ujmym73jtvhcUVEK9SvXeNQ2RmL2AW122PytQNzGGrFrrecSjjkUneQd9sVX3cqNDmZaxyS1uX';
var vector1_m_private = 'Fprv4rbspRQ4B6uzsEYhvzDXRh4sFY2A5jHphFpBBNhSBZPijgA5mc8fyr3vBA82WH5w6VW3PTMqcyVx4LTU9Vu6rkeKqT9GMX7Ec7ApYdFxs4e';
var vector1_m0h_public = 'Fpub17reDeER6jbHEKktEmdAfs7i8PQzsGVgk6AfwrVAi67yyknQjNz1enioohL2mUQY2EgYkdvQzuvLqFckPmU8Yg78pnfkSMX3t9u7taBzcAK';
var vector1_m0h_private = 'Fprv4tsHp8hXGN2z1qgR8k6AJjAyaMaWTomqNsF59U5Z9kb16xTGBqfm6zQKxRUMuzTtoYPjkkgi1LLpn6VBo6BHepiquKpQbUp8K7ofyq9vodP';
var vector1_m0h1_public = 'Fpub1A2mRRnJVSUM4moKy2X3Gc1NBmQ6sJDygQqWY8FyeivCDJHYTBQKcMd3DmncBR7syxJbY4NX7WQpRZMZs6e2EKw57zWbuzXKWtRuBVeADEd';
var vector1_m0h1_private = 'Fprv4w3R1vFQf4v3rHirrzz2uU4ddjZcTqW8KBuujjrN6PPDLVxPue654ZJZNUfRWvEwFd9RZaH963JEv31QvRyGRzDHR6n8fEayyv83Wij9dyj';
var vector1_m0h12h_public = 'Fpub1Ce3TxcACKKkvwbRDcvQdc3WQvGd8qoy1x5BnTZ8pbHdd9UfFwEkWoAxmnySdHZCLUQL9SM8VSynstVraCBZHn5uhtUjzwb1EaM3Gmtr4ZK';
var vector1_m0h12h_private = 'Fprv4yeh4T5GMwmTiTWx7bPQGU6mrtS8jP67ej9az59XGFkekM9WiPvVxzrUvWt3V9kRm6ApA3E4WT899EkAWStTZ5ewmiLgpApvbBsG9HQsNDn';
var vector1_m0h12h2_public = 'Fpub1EsSJPj7Nnzk1R58ut8VX7CpVjZMmS8ATRxV3R5c92rEzF72Khw7iNdtT7xq35hvonXWHSq5YBsuSJqrfVcm1NZAcg2vq8UqFGFtRS93Feo';
var vector1_m0h12h2_private = 'Fprv51t5ttCDYRSSnvzforbV9yG5whisMyQK6D2tF2fzahKG7SmsnAcsAaKQbqHVwp9rptJWmxTdRGaJcRechsRokUEzAxRnNFedkALReoCWMvd';
var vector1_m0h12h21000000000_public = 'Fpub1GbCn5LMVvNwXkrb2RhDppCpHy8favwCFgM3HhTkM7EjhNWQr8BmyUnx5wsmtLneHUp3nnkt5PaW2jEsmM7brdiHVDT1dc4U4DsofWnZFzi';
var vector1_m0h12h21000000000_private = 'Fprv53brNZoTfYpeKGn7vQADTgG5jwJBBUDLtTRSVK48nmhkpaBGJasXRgUUEh4hrjGwSHhmZKSaGK7RcbezEwSXsRtXWTC1VAQM2VtnPzNwcEC';
var vector2_master = 'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542';
var vector2_m_public = 'Fpub15bEDvvx1UUJ5L8W9AppF2jN3m15ApGVk4XWGhqsiH3ZuTWRVJDrxYXzNXrJjQrxvadmo539fMMWaeNqZveucheMV64xMY7VgbSfrrxY1rp';
var vector2_m_private = 'Fprv4rbspRQ4B6uzrr4339HostndVjAamMYeNqbuUKSG9wWb2fBGwkucQkDWXDu5gne2LYFU8jpHu5Y99sBaBvHoU7y6HsDWVs1yBMo3uaPVLDN';
var vector2_m0_public = 'Fpub18ryVecuVVJNbbioGxChJq8tQikKsnknJEGsSWsKnguXbRxQ4ZZw7P7EwzpCXVsQ8u7wfJ2u4SCUjooXT5MKxJJdm8odFtFsp5ZLJ9iPye3';
var vector2_m0_private = 'Fprv4usd6961f7k5P7eLAvfgwhC9rguqUL2vw1MGe8TiEMNYiddFX2FgZanm6jAtKrUrkCVJ2kE2LExGWNpPkCnrQM8VJ3dZtMBiJmhcGuGzwd5';
var vector2_m02147483647h_public = 'Fpub1A22kFeRsPUUmTvyhQCLnApSoTyERGvUPPMQMun6SRfv3jBrgSzFKStqZP4KHEUVvR3VK8tWMed5QUfsDyqSgSmGJDRgccWtgTpw8s7ntYn';
var vector2_m02147483647h_private = 'Fprv4w2gLk7Y31vBYyrWbNfLR2siFS8k1pCd2ARoZXNUt68wAvri8ufzmeaMi5es47DLeRpBomRfPFTNwcZAUaPyyea3imrueruy6Z393MVb1ru';
var vector2_m02147483647h1_public = 'Fpub1Cq1AGdN32mfs5c7m4Luk7kg8zqjXTqjhprGCySRkK2MiZ41yxWxDMHDQBFT57AnWbW39myjzmvuVGvt8tGPwnEAtVdXq9x6cEVtPMzJofX';
var vector2_m02147483647h1_private = 'Fprv4yqekm6UCfDNebXef2ouNyoway1F817tLbvfQb2pByVNqkisSRChfYxjYsrV5pR2xPAtZ4W3no8bGKLKXTvMz8PLrYPiVxtMaMTsWvTygH4';
var vector2_m02147483647h12147483646h_public = 'Fpub1E135EZieRjPA2qiVYAT7dSs3jK6aSUEjXa9jh8qb5HcAuNx5dSxjseK2qNxGUhEU39fxH3T3PFm8v6GpmNuf8vdAPx2PT3WUTaTvLFF4h1';
var vector2_m02147483647h12147483646h_private = 'Fprv511gfj2pp4B5wYmFPWdSkVW8VhUcAykPNJeYwJjE2jkdJ73oY68iC5KqBaasiEoKVxTartH3BAiB5SRh3Qprfy4WgUw2eAuyuwUPanePVaK';
var vector2_m02147483647h12147483646h2_public = 'Fpub1FN52fnEAc3cuJ2cDcJ96NpqSnrCpmPKPhC39UVLDs9CF6iXFGNivSbK7ETEQ43vz6MuECYrw6GkdM9mes4oyPnCoZn7KpLF9kmeauXfZTw';
var vector2_m02147483647h12147483646h2_private = 'Fprv52NidAFLLEVKgox97am8jEt6tm1iRJfU2UGSM65ifXcDNJPNhj4UNeGqFzFssFtPYGKK9durdGYs7zKCmjC5iwoEVLSXhb3hcJowfLFVLYp';
