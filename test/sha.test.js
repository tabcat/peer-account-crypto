
'use strict'
const assert = require('assert')
const crypto = require('../src')

const sha = crypto.sha

describe('crypto.sha', function () {
  const emptyData = new Uint8Array(16)

  it('digests data to length 256', async () => {
    const length = '256'
    const precomputed = new Uint8Array(
      [55, 71, 8, 255, 247, 113, 157, 213, 151, 158, 200, 117, 213, 108, 210, 40, 111, 109, 60, 247, 236, 49, 122, 59, 37, 99, 42, 171, 40, 236, 55, 187]
    )
    const digest = await sha(emptyData, length)
    assert.deepStrictEqual(digest, precomputed)
  })

  it('digests data to length 512', async () => {
    const length = '512'
    const precomputed = new Uint8Array(
      [11, 108, 186, 200, 56, 223, 231, 244, 126, 161, 189, 13, 240, 14, 194, 130, 253, 244, 85, 16, 201, 33, 97, 7, 44, 207, 184, 64, 53, 57, 12, 77, 167, 67, 217, 195, 185, 84, 234, 161, 176, 248, 111, 201, 134, 27, 35, 204, 108, 134, 103, 171, 35, 44, 17, 198, 134, 67, 46, 187, 92, 140, 63, 39]
    )
    const digest = await sha(emptyData, length)
    assert.deepStrictEqual(digest, precomputed)
  })
})
