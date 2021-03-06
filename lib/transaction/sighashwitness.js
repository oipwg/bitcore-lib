'use strict';

/* jshint maxparams:5 */

var Signature = require('../crypto/signature');
var Script = require('../script');
var Output = require('./output');
var BufferReader = require('../encoding/bufferreader');
var BufferWriter = require('../encoding/bufferwriter');
var BN = require('../crypto/bn');
var Hash = require('../crypto/hash');
var ECDSA = require('../crypto/ecdsa');
var $ = require('../util/preconditions');
var _ = require('lodash');

/**
 * Returns a buffer of length 32 bytes with the hash that needs to be signed
 * for witness programs as defined by:
 * https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
 *
 * @name Signing.sighash
 * @param {Transaction} transaction the transaction to sign
 * @param {number} sighashType the type of the hash
 * @param {number} inputNumber the input index for the signature
 * @param {Buffer} scriptCode
 * @param {Buffer} satoshisBuffer
 */
var sighash = function sighash(transaction, sighashType, inputNumber, scriptCode, satoshisBuffer) {
  /* jshint maxstatements: 50 */

  var hashPrevouts;
  var hashSequence;
  var hashOutputs;

  if (!(sighashType & Signature.SIGHASH_ANYONECANPAY)) {
    var buffers = [];
    for (var n = 0; n < transaction.inputs.length; n++) {
      var input = transaction.inputs[n];
      var prevTxIdBuffer = new BufferReader(input.prevTxId).readReverse();
      buffers.push(prevTxIdBuffer);
      var outputIndexBuffer = new Buffer(new Array(4));
      outputIndexBuffer.writeUInt32LE(input.outputIndex, 0);
      buffers.push(outputIndexBuffer);
    }
    hashPrevouts = Hash.sha256sha256(Buffer.concat(buffers));
  }

  if (!(sighashType & Signature.SIGHASH_ANYONECANPAY) &&
      (sighashType & 0x1f) !== Signature.SIGHASH_SINGLE && (sighashType & 0x1f) !== Signature.SIGHASH_NONE) {

    var sequenceBuffers = [];
    for (var m = 0; m < transaction.inputs.length; m++) {
      var sequenceBuffer = new Buffer(new Array(4));
      sequenceBuffer.writeUInt32LE(transaction.inputs[m].sequenceNumber, 0);
      sequenceBuffers.push(sequenceBuffer);
    }
    hashSequence = Hash.sha256sha256(Buffer.concat(sequenceBuffers));
  }

  var outputWriter = new BufferWriter();
  if ((sighashType & 0x1f) !== Signature.SIGHASH_SINGLE && (sighashType & 0x1f) !== Signature.SIGHASH_NONE) {
    for (var p = 0; p < transaction.outputs.length; p++) {
      transaction.outputs[p].toBufferWriter(outputWriter);
    }
    hashOutputs = Hash.sha256sha256(outputWriter.toBuffer());
  } else if ((sighashType & 0x1f) === Signature.SIGHASH_SINGLE && inputNumber < transaction.outputs.length) {
    transaction.outputs[inputNumber].toBufferWriter(outputWriter);
    hashOutputs = Hash.sha256sha256(outputWriter.toBuffer());
  }

  // Version
  var writer = new BufferWriter();
  writer.writeUInt32LE(transaction.version);

  // Input prevouts/nSequence (none/all, depending on flags)
  writer.write(hashPrevouts);
  writer.write(hashSequence);

  // The input being signed (replacing the scriptSig with scriptCode + amount)
  // The prevout may already be contained in hashPrevout, and the nSequence
  // may already be contain in hashSequence.
  var outpointId = new BufferReader(transaction.inputs[inputNumber].prevTxId).readReverse();
  writer.write(outpointId);
  writer.writeUInt32LE(transaction.inputs[inputNumber].outputIndex);

  writer.write(scriptCode);

  writer.write(satoshisBuffer);

  writer.writeUInt32LE(transaction.inputs[inputNumber].sequenceNumber);

  // Outputs (none/one/all, depending on flags)
  writer.write(hashOutputs);

  // Locktime
  writer.writeUInt32LE(transaction.nLockTime);

  writer.writeVarintNum(transaction.strFloData.length)
  writer.write(Buffer.from(transaction.strFloData));

  // Sighash type
  writer.writeInt32LE(sighashType);

  return Hash.sha256sha256(writer.toBuffer());

};

/**
 * Create a signature
 *
 * @name Signing.sign
 * @param {Transaction} transaction
 * @param {PrivateKey} privateKey
 * @param {number} sighash
 * @param {number} inputIndex
 * @param {Script} subscript
 * @return {Signature}
 */
function sign(transaction, privateKey, sighashType, inputIndex, scriptCode, satoshisBuffer) {
  var hashbuf = sighash(transaction, sighashType, inputIndex, scriptCode, satoshisBuffer);
  var sig = ECDSA.sign(hashbuf, privateKey).set({
    nhashtype: sighashType
  });
  return sig;
}

/**
 * Verify a signature
 *
 * @name Signing.verify
 * @param {Transaction} transaction
 * @param {Signature} signature
 * @param {PublicKey} publicKey
 * @param {number} inputIndex
 * @param {Script} subscript
 * @return {boolean}
 */
function verify(transaction, signature, publicKey, inputIndex, scriptCode, satoshisBuffer) {
  $.checkArgument(!_.isUndefined(transaction));
  $.checkArgument(!_.isUndefined(signature) && !_.isUndefined(signature.nhashtype));
  var hashbuf = sighash(transaction, signature.nhashtype, inputIndex, scriptCode, satoshisBuffer);
  return ECDSA.verify(hashbuf, signature, publicKey);
}

/**
 * @namespace Signing
 */
module.exports = {
  sighash: sighash,
  sign: sign,
  verify: verify
};
