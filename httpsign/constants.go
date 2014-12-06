package httpsign

const MaxSkewSec = 5                      // 5 sec
const CacheTimeout = 100                  // 100 sec
const CacheCapacity = 5000 * CacheTimeout // 5,000 msg/sec * 100 sec = 500,000 elements

const XMailgunSignature = "X-Mailgun-Signature"
const XMailgunSignatureVersion = "X-Mailgun-Signature-Version"
const XMailgunNonce = "X-Mailgun-Nonce"
const XMailgunTimestamp = "X-Mailgun-Timestamp"
