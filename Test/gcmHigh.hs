{-# LANGUAGE OverloadedStrings #-}
module Main where

import Control.Monad
import Crypto.Cipher.AES128
import Data.ByteString.Internal as I
import Data.ByteString.Char8 as C
import Data.ByteString as B
import Data.Word
import Foreign.Ptr
import Foreign.Storable
import Foreign.Marshal.Utils
import Foreign.Marshal.Alloc

main = do
    let pt = "hello there!"
        Just k = buildKey (B.replicate 16 0) :: Maybe AESKey128
        gcmc = aesKeyToGCM k
        iv = B.replicate 12 48
        auth = "Authenticate me!"
        authbad = "Authenticate you!"
        (ct,tag) = encryptGCM gcmc iv pt auth
        (pt2,tag2) = decryptGCM gcmc iv ct auth
        (pt3,tag3) = decryptGCM gcmc iv ct authbad
    print (pt,pt2,pt3)
    print ("Test: good plaintext decrypt", pt == pt2)
    print ("Test Bad plaintext decrypt correctly", pt == pt3)
    print ("Test: Good auth", tag == tag2)
    print ("Test Bad auth", tag /= tag3)
