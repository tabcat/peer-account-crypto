
'use strict'
const webcrypto = require('./node-webcrypto-ossl.js')

module.exports = async function (length = '256', data) {
  return new Uint8Array(
    await webcrypto.get().subtle.digest(
      {
        name: `SHA-${length}`
      },
      new Uint8Array(data)
    )
  )
}
