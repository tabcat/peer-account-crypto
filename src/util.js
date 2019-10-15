
'use strict'
const webcrypto = require('./node-webcrypto-ossl')
const BN = require('asn1.js').bignum

// Convert a BN.js instance to a base64 encoded string without padding
// Adapted from https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#appendix-C
exports.toBase64 = function toBase64 (bn, len) {
  // if len is defined then the bytes are leading-0 padded to the length
  let s = bn.toArrayLike(Buffer, 'be', len).toString('base64') // eslint-disable-line

  return s
    .replace(/(=*)$/, '') // Remove any trailing '='s
    .replace(/\+/g, '-') // 62nd char of encoding
    .replace(/\//g, '_') // 63rd char of encoding
}

// Convert a base64 encoded string to a BN.js instance
exports.toBn = function toBn (str) {
  return new BN(Buffer.from(str, 'base64'))
}

exports.randomBytes = (bytes) => webcrypto.get()
  .getRandomValues(new Uint8Array(bytes))

exports.str2ab = function str2ab (str) {
  var buf = new ArrayBuffer(str.length * 2) // 2 bytes for each char
  var bufView = new Uint16Array(buf)
  for (var i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i)
  }
  return buf
}
exports.ab2str = function ab2str (buf) {
  return String.fromCharCode.apply(null, new Uint16Array(buf))
}
