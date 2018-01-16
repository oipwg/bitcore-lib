'use strict';

var flocore = module.exports;

// module information
flocore.version = 'v' + require('./package.json').version;
flocore.versionGuard = function(version) {
  if (version !== undefined) {
    var message = 'More than one instance of flocore-lib found. ' +
      'Please make sure to require flocore-lib and check that submodules do' +
      ' not also include their own flocore-lib dependency.';
    throw new Error(message);
  }
};
flocore.versionGuard(global._flocore);
global._flocore = flocore.version;

// crypto
flocore.crypto = {};
flocore.crypto.BN = require('./lib/crypto/bn');
flocore.crypto.ECDSA = require('./lib/crypto/ecdsa');
flocore.crypto.Hash = require('./lib/crypto/hash');
flocore.crypto.Random = require('./lib/crypto/random');
flocore.crypto.Point = require('./lib/crypto/point');
flocore.crypto.Signature = require('./lib/crypto/signature');

// encoding
flocore.encoding = {};
flocore.encoding.Base58 = require('./lib/encoding/base58');
flocore.encoding.Base58Check = require('./lib/encoding/base58check');
flocore.encoding.BufferReader = require('./lib/encoding/bufferreader');
flocore.encoding.BufferWriter = require('./lib/encoding/bufferwriter');
flocore.encoding.Varint = require('./lib/encoding/varint');

// utilities
flocore.util = {};
flocore.util.buffer = require('./lib/util/buffer');
flocore.util.js = require('./lib/util/js');
flocore.util.preconditions = require('./lib/util/preconditions');

// errors thrown by the library
flocore.errors = require('./lib/errors');

// main florincoin library
flocore.Address = require('./lib/address');
flocore.Block = require('./lib/block');
flocore.MerkleBlock = require('./lib/block/merkleblock');
flocore.BlockHeader = require('./lib/block/blockheader');
flocore.HDPrivateKey = require('./lib/hdprivatekey.js');
flocore.HDPublicKey = require('./lib/hdpublickey.js');
flocore.Networks = require('./lib/networks');
flocore.Opcode = require('./lib/opcode');
flocore.PrivateKey = require('./lib/privatekey');
flocore.PublicKey = require('./lib/publickey');
flocore.Script = require('./lib/script');
flocore.Transaction = require('./lib/transaction');
flocore.URI = require('./lib/uri');
flocore.Unit = require('./lib/unit');

// dependencies, subject to change
flocore.deps = {};
flocore.deps.bnjs = require('bn.js');
flocore.deps.bs58 = require('bs58');
flocore.deps.Buffer = Buffer;
flocore.deps.elliptic = require('elliptic');
flocore.deps._ = require('lodash');

// Internal usage, exposed for testing/advanced tweaking
flocore.Transaction.sighash = require('./lib/transaction/sighash');
