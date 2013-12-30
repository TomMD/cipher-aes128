{-# OPTIONS_GHC -fno-warn-orphans #-}
module Crypto.Cipher.AES128
  ( AESKey128, AESKey192, AESKey256
  , BlockCipher(..), buildKeyIO, zeroIV
  ) where

import Crypto.Cipher.AES128.Internal
import Crypto.Classes
import Control.Monad (when)
import Data.Serialize
import Data.Tagged
import Foreign.Ptr
import Foreign.ForeignPtr
import System.IO.Unsafe
import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as B
import qualified Data.ByteString.Unsafe as B

instance Serialize AESKey128 where
    put k = do
        let RKey128 l h = (rawKey128 k)
        putWord64be h
        putWord64be l

    get = do
        b <- getByteString 16
        case buildKey b of
            Nothing -> fail "Invalid key on 'get'"
            Just k  -> return k

instance Serialize AESKey192 where
    put k = do
        let RKey192 a b c = (rawKey192 k)
        putWord64be c
        putWord64be b
        putWord64be a

    get = do
        b <- getByteString 24
        case buildKey b of
            Nothing -> fail "Invalid key on 'get'"
            Just k  -> return k

instance Serialize AESKey256 where
    put k = do
        let RKey256 a b c d = (rawKey256 k)
        putWord64be d
        putWord64be c
        putWord64be b
        putWord64be a

    get = do
        b <- getByteString 32
        case buildKey b of
            Nothing -> fail "Invalid key on 'get'"
            Just k  -> return k

instance BlockCipher AESKey128 where
    blockSize = Tagged 128
    keyLength = Tagged 128
    buildKey bs
      | B.length bs >= 16 = unsafePerformIO $
          B.unsafeUseAsCString bs (\p -> generateKey128 (castPtr p))
      | otherwise = Nothing
    encryptBlock k b = unsafePerformIO $ do
        B.unsafeUseAsCStringLen b $ \(inP,len) -> do
         B.create (B.length b) $ \outP -> do
            encryptECB k (castPtr outP) (castPtr inP) (len`div`blkSize)
    decryptBlock k b = unsafePerformIO $ do
        B.unsafeUseAsCStringLen b $ \(inP,len) -> do
         B.create (B.length b) $ \outP -> do
            decryptECB k (castPtr outP) (castPtr inP) (len`div`blkSize)
    ecb   = encryptBlock
    unEcb = decryptBlock
    ctr k (IV bs) pt = unsafePerformIO $ do
        B.unsafeUseAsCStringLen pt $ \(inP, len) -> do
         B.unsafeUseAsCStringLen bs $ \(ivP, ivLen) -> do
            when (ivLen /= (blockSizeBytes .::. k))
                (error "Cipher-AES128: IV wrong length!  They type system would have/should have caught this if you didn't use the IV constructor...")
            newIVFP <- B.mallocByteString ivLen
            ct <- B.create len $ \outP -> withForeignPtr newIVFP $ \newIVP -> do
                encryptCTR k (castPtr ivP) (castPtr newIVP) (castPtr outP) (castPtr inP) len
            let newIV = B.fromForeignPtr newIVFP 0 ivLen
            return (ct,IV newIV)
    {-# INLINE ctr #-}
    unCtr = ctr

blkSize :: Int
blkSize = 16

instance BlockCipher AESKey192 where
    blockSize = Tagged 128
    keyLength = Tagged 192
    buildKey bs
      | B.length bs >= 16 = unsafePerformIO $
          B.unsafeUseAsCString bs (\p -> generateKey192 (castPtr p))
      | otherwise = Nothing
    encryptBlock k b = unsafePerformIO $ do
        B.unsafeUseAsCStringLen b $ \(inP,len) -> do
         B.create (B.length b) $ \outP -> do
            encryptECB k (castPtr outP) (castPtr inP) (len`div`blkSize)
    decryptBlock k b = unsafePerformIO $ do
        B.unsafeUseAsCStringLen b $ \(inP,len) -> do
         B.create (B.length b) $ \outP -> do
            decryptECB k (castPtr outP) (castPtr inP) (len`div`blkSize)
    ecb   = encryptBlock
    unEcb = decryptBlock
    ctr k (IV bs) pt = unsafePerformIO $ do
        B.unsafeUseAsCStringLen pt $ \(inP, len) -> do
         B.unsafeUseAsCStringLen bs $ \(ivP, ivLen) -> do
            when (ivLen /= (blockSizeBytes .::. k))
                (error "Cipher-AES128: IV wrong length!  They type system would have/should have caught this if you didn't use the IV constructor...")
            newIVFP <- B.mallocByteString ivLen
            ct <- B.create len $ \outP -> withForeignPtr newIVFP $ \newIVP -> do
                encryptCTR k (castPtr ivP) (castPtr newIVP) (castPtr outP) (castPtr inP) len
            let newIV = B.fromForeignPtr newIVFP 0 ivLen
            return (ct,IV newIV)
    {-# INLINE ctr #-}
    unCtr = ctr

instance BlockCipher AESKey256 where
    blockSize = Tagged 128
    keyLength = Tagged 256
    buildKey bs
      | B.length bs >= 16 = unsafePerformIO $
          B.unsafeUseAsCString bs (\p -> generateKey256 (castPtr p))
      | otherwise = Nothing
    encryptBlock k b = unsafePerformIO $ do
        B.unsafeUseAsCStringLen b $ \(inP,len) -> do
         B.create (B.length b) $ \outP -> do
            encryptECB k (castPtr outP) (castPtr inP) (len`div`blkSize)
    decryptBlock k b = unsafePerformIO $ do
        B.unsafeUseAsCStringLen b $ \(inP,len) -> do
         B.create (B.length b) $ \outP -> do
            decryptECB k (castPtr outP) (castPtr inP) (len`div`blkSize)
    ecb   = encryptBlock
    unEcb = decryptBlock
    ctr k (IV bs) pt = unsafePerformIO $ do
        B.unsafeUseAsCStringLen pt $ \(inP, len) -> do
         B.unsafeUseAsCStringLen bs $ \(ivP, ivLen) -> do
            when (ivLen /= (blockSizeBytes .::. k))
                (error "Cipher-AES128: IV wrong length!  They type system would have/should have caught this if you didn't use the IV constructor...")
            newIVFP <- B.mallocByteString ivLen
            ct <- B.create len $ \outP -> withForeignPtr newIVFP $ \newIVP -> do
                encryptCTR k (castPtr ivP) (castPtr newIVP) (castPtr outP) (castPtr inP) len
            let newIV = B.fromForeignPtr newIVFP 0 ivLen
            return (ct,IV newIV)
    {-# INLINE ctr #-}
    unCtr = ctr
