
'use strict'
const assert = require('assert')
const crypto = require('../src')

const ecdh = crypto.ecdh

describe('crypto.ecdh', function () {
  const useEcdh = async (ecdh1, ecdh2) => {
    if (
      (ecdh1.jwk.pub.crv !== ecdh2.jwk.pub.crv) ||
      (ecdh1.jwk.priv.crv !== ecdh2.jwk.priv.crv)
    ) { throw new Error('ecdh pairs curve mismatch') }
    const shared1 = await ecdh1.genSharedKey(ecdh2.key)
    const shared2 = await ecdh2.genSharedKey(ecdh1.key)
    assert.deepStrictEqual(shared1, shared2)
  }

  describe('.import', function () {
    it('import ecdh key pair with curve P-256', async () => {
      const jwk1 = JSON.parse(
        `{"pub":{"crv":"P-256","ext":true,"key_ops":[],"kty":"EC","x":"8szEL4417fLQPY-bXDtpZqM5-AeSfJ34VCLw-s3kqcs","y":"9OLr8qSX8wgtil1eyYW7ja0n06vEoXa-dLrKBVqGPjg"},"priv":{"crv":"P-256","d":"ehJdZEAAYa_hJIAQz05XwxUlfCdQPM2zx78zUzAtHNo","ext":true,"key_ops":["deriveBits"],"kty":"EC","x":"8szEL4417fLQPY-bXDtpZqM5-AeSfJ34VCLw-s3kqcs","y":"9OLr8qSX8wgtil1eyYW7ja0n06vEoXa-dLrKBVqGPjg"}}` // eslint-disable-line
      )
      const jwk2 = JSON.parse(
        `{"pub":{"crv":"P-256","ext":true,"key_ops":[],"kty":"EC","x":"BLb6LwR2nAybTeOhxGs51mCj70iHBGARIjOLZMXy2eo","y":"pOu-ytY-h0o0Hl44Ex6i2M1PgMb63K_ZAqgCbgVRDms"},"priv":{"crv":"P-256","d":"rGhTwNGn9E9v7M8BtZF6eYngsNILhznxsNhTIg29wVI","ext":true,"key_ops":["deriveBits"],"kty":"EC","x":"BLb6LwR2nAybTeOhxGs51mCj70iHBGARIjOLZMXy2eo","y":"pOu-ytY-h0o0Hl44Ex6i2M1PgMb63K_ZAqgCbgVRDms"}}` // eslint-disable-line
      )
      const ecdh1 = await ecdh.import(jwk1)
      const ecdh2 = await ecdh.import(jwk2)
      await useEcdh(ecdh1, ecdh2)
    })

    it('import ecdh key pair with curve P-521', async () => {
      const jwk1 = JSON.parse(
        `{"pub":{"crv":"P-521","ext":true,"key_ops":[],"kty":"EC","x":"AZdm6lkHvxilOnjRK3trVJhsPYR7rR8upD_BpG4YOz1lCmFU28HnVMxqooFH2XOsTp8b6ftL4r4zSPNdzZifNVsm","y":"AMwjJAdCXU3wt40viqTHq7a6Tta3bOrtS0e5Vp75_erdvkY_Ovzxa42IOyMzUCFHKaVl3yp51g7KsX_xllVCZZiu"},"priv":{"crv":"P-521","d":"AD7AL_bpBR9GqgcvILQPwoMqTZiI3WxDFnxsPfN7K6MsCAqQlJoBM-HFmU-WszK3laH1iNRhhZq4lYJSRlX64lcP","ext":true,"key_ops":["deriveBits"],"kty":"EC","x":"AZdm6lkHvxilOnjRK3trVJhsPYR7rR8upD_BpG4YOz1lCmFU28HnVMxqooFH2XOsTp8b6ftL4r4zSPNdzZifNVsm","y":"AMwjJAdCXU3wt40viqTHq7a6Tta3bOrtS0e5Vp75_erdvkY_Ovzxa42IOyMzUCFHKaVl3yp51g7KsX_xllVCZZiu"}}` // eslint-disable-line
      )
      const jwk2 = JSON.parse(
        `{"pub":{"crv":"P-521","ext":true,"key_ops":[],"kty":"EC","x":"Adx5bXEQarHhc6rUOtG3sfwoaY-RPBnHUTst9KQWGWhOZsexlgpbll_8VtzAl6uIu0tjJ_d3BZR2OkZwFpGZ7fhz","y":"ALbhYH2sT-EgGaQXsO5xwUNZK64YdKtX4EZyz8XkuuoAJ_4S8eCZgN8a3dq7Ir2oLobLIJwehygpM-Eoa1pwAwMR"},"priv":{"crv":"P-521","d":"AIWQm91tZ6s_mPjrlLV68dsbAvBN7Pw9ahTwtyRvM0S6RfjOCOE6_iRClVcQ9ztfdfaLXcLjnaZjxa0brFuiOb_e","ext":true,"key_ops":["deriveBits"],"kty":"EC","x":"Adx5bXEQarHhc6rUOtG3sfwoaY-RPBnHUTst9KQWGWhOZsexlgpbll_8VtzAl6uIu0tjJ_d3BZR2OkZwFpGZ7fhz","y":"ALbhYH2sT-EgGaQXsO5xwUNZK64YdKtX4EZyz8XkuuoAJ_4S8eCZgN8a3dq7Ir2oLobLIJwehygpM-Eoa1pwAwMR"}}` // eslint-disable-line
      )
      const ecdh1 = await ecdh.import(jwk1)
      const ecdh2 = await ecdh.import(jwk2)
      await useEcdh(ecdh1, ecdh2)
    })
  })

  describe('.generate', function () {
    it('generates a new ecdh key pair with default curve P-256', async () => {
      const curve = 'P-256'
      const ecdh1 = await ecdh.generate()
      const ecdh2 = await ecdh.generate()
      assert.strictEqual(ecdh1.jwk.priv.crv, curve)
      await useEcdh(ecdh1, ecdh2)
    })

    it('generates a new ecdh key pair with optional curve P-521', async () => {
      const curve = 'P-521'
      const ecdh1 = await ecdh.generate(curve)
      const ecdh2 = await ecdh.generate(curve)
      assert.strictEqual(ecdh1.jwk.priv.crv, curve)
      await useEcdh(ecdh1, ecdh2)
    })
  })
})
