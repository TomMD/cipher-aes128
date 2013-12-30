{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PackageImports #-}
import Test.AES
import Crypto.Cipher.AES128
import "test-framework" Test.Framework

main = do
    ts <- makeAESTests (undefined :: AESKey128)
    defaultMain ts
