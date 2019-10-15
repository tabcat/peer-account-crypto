
'use strict'
const assert = require('assert')
const crypto = require('../src')

const aes = crypto.aes

const { str2ab, ab2str } = crypto.util

describe('crypto.aes', function () {
  let aesKey, rawKey
  const string = 'string'
  const obj = { prop: 'prop' }
  const bytes = str2ab('bytes')
  const salt = str2ab('salt')

  const useAesKey = async () => {
    if (!aesKey) throw new Error('aesKey must be defined when called')
    const encStr = await aesKey.encrypt(str2ab(string))
    const encObj = await aesKey.encrypt(str2ab(JSON.stringify(obj)))
    const decStr = await aesKey.decrypt(encStr.cipherbytes, encStr.iv)
    const decObj = await aesKey.decrypt(encObj.cipherbytes, encObj.iv)
    assert.strictEqual(ab2str(decStr.buffer), string)
    assert.deepStrictEqual(JSON.parse(ab2str(decObj.buffer)), obj)
    const ivEncObj = await aesKey.encrypt(
      str2ab(JSON.stringify(obj)),
      new Uint8Array(12)
    )
    const ivDecObj = await aesKey.decrypt(ivEncObj.cipherbytes, ivEncObj.iv)
    assert.deepStrictEqual(JSON.parse(ab2str(ivDecObj.buffer)), obj)
  }

  describe('.generateKey', function () {
    it('generates an instance of AesKey with default length 128', async () => {
      const length = 128
      aesKey = await aes.generateKey()
      assert.strictEqual(aesKey._cryptoKey.algorithm.length, length)
      await useAesKey()
    })

    it('generates an instance of AesKey with optional length 256', async () => {
      const length = 256
      aesKey = await aes.generateKey(length)
      assert.strictEqual(aesKey._cryptoKey.algorithm.length, length)
      await useAesKey()
    })
  })

  describe('.deriveKey', function () {
    it('derives an instance of AesKey with default length 128', async () => {
      const length = 128
      aesKey = await aes.deriveKey(bytes, salt)
      assert.strictEqual(aesKey._cryptoKey.algorithm.length, length)
      await useAesKey()
    })

    it('derives an instance of AesKey with optional length 256', async () => {
      const length = 256
      aesKey = await aes.deriveKey(bytes, salt, length)
      assert.strictEqual(aesKey._cryptoKey.algorithm.length, length)
      await useAesKey()
    })
  })

  describe('.exportKey', function () {
    before(async () => {
      aesKey = await aes.deriveKey(bytes, salt)
      rawKey = new Uint8Array(
        [221, 189, 199, 144, 98, 65, 223, 203, 196, 23, 8, 73, 8, 112, 161, 205]
      )
    })

    it('exports an aesKey in raw format', async () => {
      const exported = await aes.exportKey(aesKey)
      assert.deepStrictEqual(exported, rawKey)
    })
  })

  describe('.importKey', function () {
    before(async () => {
      aesKey = await aes.deriveKey(bytes, salt)
      rawKey = new Uint8Array(
        [221, 189, 199, 144, 98, 65, 223, 203, 196, 23, 8, 73, 8, 112, 161, 205]
      )
    })

    it('imports an aesKey from raw format', async () => {
      const imported = await aes.importKey(rawKey)
      assert.deepStrictEqual(imported, aesKey)
    })
  })

  describe('aesKey instance', function () {
    before(async () => {
      aesKey = await aes.deriveKey(bytes, salt)
    })

    it('encrypts and decrypts', async () => {
      await useAesKey()
    })
  })
})
