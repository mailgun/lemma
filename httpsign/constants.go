package httpsign

const MaxSkewSec = 20                     // 20 sec
const CacheTimeout = 30                   // 30 sec
const CacheCapacity = 5000 * CacheTimeout // 5,000 msg/sec * 30 sec = 150,000 elements

const XMailgunSignature = "X-Mailgun-Signature"
const XMailgunSignatureVersion = "X-Mailgun-Signature-Version"
const XMailgunNonce = "X-Mailgun-Nonce"
const XMailgunTimestamp = "X-Mailgun-Timestamp"
