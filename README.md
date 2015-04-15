![TravisCI](https://travis-ci.org/TomMD/cipher-aes128.svg)

## AES and various modes

This package, available on hackage, implements AES and various modes of
operation.  Despite the name, it provides AES-192 and 256 as well.

While it original started as a fork of the cipher-aes package to test a
[performance improvement](https://github.com/vincenthz/hs-cipher-aes/issues/8),
this package continues to be maintained due to my preference for the API ([for
example](https://github.com/vincenthz/hs-cipher-aes/issues/27), [also
this](https://github.com/vincenthz/hs-cipher-aes/issues/23)) and the idea that
faster C code will eventually be adopted.


## Use

Most users will want the `crypto-api` interface to generate keys and
encrypt/decrypt data:

```
{-# LANGUAGE OverloadedStrings #-}
import Data.ByteString
import Crypto.Cipher.AES128 (AESKey128)
import Crypto.Classes (buildKeyIO, ctr, unCtr, zeroIV)

main =
 do k <- buildKeyIO :: IO AESKey128
    let myMessage            = "Some message or another"
        (ciphertext,_nextIV) = ctr k zeroIV myMessage
        (myMessage',_nextIV) = unCtr k zeroIV ciphertext
    print (unpack myMessage)
    print (unpack ciphertext)
    print $ myMessage == myMessage'
```

Unless you need GCM in which case, as of writing, you'll
need to use `makeGCMCtx`, `encryptGCM` and `decryptGCM`.
