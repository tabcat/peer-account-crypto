
'use strict'
const webcrypto = require('./node-webcrypto-ossl')
const { randomBytes } = require('./util')

class AesKey {
  constructor (cryptoKey) {
    this._cryptoKey = cryptoKey
  }

  static async genKey (length = 128) {
    const cryptoKey = await webcrypto.get().subtle.generateKey(
      {
        name: 'AES-GCM',
        length: length // can be  128, 192, or 256
      },
      true,
      ['encrypt', 'decrypt']
    )
    return new AesKey(cryptoKey)
  }

  static async deriveKey
  (bytes, salt, length = 128) {
    if (bytes === undefined || salt === undefined) {
      throw new Error('bytes and salt must be defined')
    }
    const pbkdf2 = await webcrypto.get().subtle.importKey(
      'raw',
      bytes,
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    )
    const cryptoKey = await webcrypto.get().subtle.deriveKey(
      {
        name: 'PBKDF2',
        hash: { name: 'SHA-256' },
        salt,
        iterations: 10000
      },
      pbkdf2,
      { name: 'AES-GCM', length },
      true, // exportable
      ['encrypt', 'decrypt']
    )
    return new AesKey(cryptoKey)
  }

  static async exportKey (key) {
    if (key === undefined) {
      throw new Error('key must be defined')
    }
    key = key._cryptoKey || key
    const ab = await webcrypto.get().subtle.exportKey('raw', key)
    return new Uint8Array(ab)
  }

  static async importKey (rawKey) {
    if (rawKey === undefined) {
      throw new Error('rawKey must be defined')
    }
    rawKey = rawKey.buffer || rawKey
    const cryptoKey = await webcrypto.get().subtle.importKey(
      'raw',
      rawKey,
      { name: 'AES-GCM' },
      true, // exportable
      ['encrypt', 'decrypt']
    )
    return new AesKey(cryptoKey)
  }

  async encrypt (bytes, iv) {
    if (bytes === undefined) {
      throw new Error('bytes must be defined')
    }
    // 12bytes is recommended for GCM for computational efficiencies
    iv = iv || await randomBytes(12)
    const algo = { ...this._cryptoKey.algorithm, iv }
    const cipherbytes = new Uint8Array(
      await webcrypto.get().subtle.encrypt(algo, this._cryptoKey, bytes)
    )
    return { cipherbytes, iv }
  }

  async decrypt (bytes, iv) {
    if (bytes === undefined || iv === undefined) {
      throw new Error('bytes and iv must be defined')
    }
    const algo = { ...this._cryptoKey.algorithm, iv }
    const ab = await webcrypto.get().subtle.decrypt(
      algo,
      this._cryptoKey,
      bytes
    )
    return new Uint8Array(ab)
  }
}

module.exports = AesKey
