
'use strict'

module.exports = function (curveTypes, type) {
  if (!curveTypes.includes(type)) {
    const names = curveTypes.join(' / ')
    throw new Error(`Unknown curve: ${type}. Must be ${names}`)
  }
}
