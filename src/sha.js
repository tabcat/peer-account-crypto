
'use strict'
const webcrypto = require('./node-webcrypto-ossl.js')

module.exports = async function (data, length = '256') {
  return new Uint8Array(
    await webcrypto.get().subtle.digest(
      {
        name: `SHA-${length}`
      },
      new Uint8Array(data)
    )
  )
}
