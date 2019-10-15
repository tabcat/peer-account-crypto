
'use strict'
const webcrypto = require('./node-webcrypto-ossl.js')
const BN = require('asn1.js').bignum
const { toBase64, toBn } = require('./util')
const validateCurveType = require('./validate-curve-type')

const bits = {
  'P-256': 256,
  'P-521': 521
}

exports.import = async (jwk) => {
  if (
    (!jwk || !jwk.pub || !jwk.pub.crv) ||
    (!jwk || !jwk.priv || !jwk.priv.crv)
  ) {
    throw new Error('invalid ecdh pair jwk')
  }
  if (jwk.pub.crv !== jwk.priv.crv) throw new Error('jwk curve mismatch')
  const curve = jwk.pub.crv
  validateCurveType(Object.keys(bits), curve)
  let privateKey = await webcrypto.get().subtle.importKey(
    'jwk',
    jwk.priv,
    {
      name: 'ECDH',
      namedCurve: curve
    },
    false,
    ['deriveBits']
  )

  // forcePrivate is used for testing only
  const genSharedKey = async (theirPub, forcePrivate) => {
    if (forcePrivate) {
      privateKey = await webcrypto.get().subtle.importKey(
        'jwk',
        unmarshalPrivateKey(curve, forcePrivate),
        {
          name: 'ECDH',
          namedCurve: curve
        },
        false,
        ['deriveBits']
      )
    }

    const keys = [
      await webcrypto.get().subtle.importKey(
        'jwk',
        unmarshalPublicKey(curve, theirPub),
        {
          name: 'ECDH',
          namedCurve: curve
        },
        false,
        []
      ),
      privateKey
    ]

    return Buffer.from(await webcrypto.get().subtle.deriveBits(
      {
        name: 'ECDH',
        namedCurve: curve,
        public: keys[0]
      },
      keys[1],
      bits[curve]
    ))
  }

  return {
    key: marshalPublicKey(jwk.pub),
    genSharedKey,
    jwk
  }
}

exports.generate = async function (curve = 'P-256') {
  validateCurveType(Object.keys(bits), curve)
  const pair = await webcrypto.get().subtle.generateKey(
    {
      name: 'ECDH',
      namedCurve: curve
    },
    true,
    ['deriveBits']
  )
  const pub = await webcrypto.get().subtle.exportKey('jwk', pair.publicKey)
  const priv = await webcrypto.get().subtle.exportKey('jwk', pair.privateKey)
  return exports.import({ pub, priv })
}

const curveLengths = {
  'P-256': 32,
  'P-521': 66
}

// Marshal converts a jwk encodec ECDH public key into the
// form specified in section 4.3.6 of ANSI X9.62. (This is the format
// go-ipfs uses)
function marshalPublicKey (jwk) {
  const byteLen = curveLengths[jwk.crv]

  return Buffer.concat([
    Buffer.from([4]), // uncompressed point
    toBn(jwk.x).toArrayLike(Buffer, 'be', byteLen),
    toBn(jwk.y).toArrayLike(Buffer, 'be', byteLen)
  ], 1 + byteLen * 2)
}

// Unmarshal converts a point, serialized by Marshal, into an jwk encoded key
function unmarshalPublicKey (curve, key) {
  const byteLen = curveLengths[curve]

  if (!key.slice(0, 1).equals(Buffer.from([4]))) {
    throw new Error('Cannot unmarshal public key - invalid key format')
  }
  const x = new BN(key.slice(1, byteLen + 1))
  const y = new BN(key.slice(1 + byteLen))

  return {
    kty: 'EC',
    crv: curve,
    x: toBase64(x, byteLen),
    y: toBase64(y, byteLen),
    ext: true
  }
}

function unmarshalPrivateKey (curve, key) {
  const result = unmarshalPublicKey(curve, key.public)
  result.d = toBase64(new BN(key.private))
  return result
}
