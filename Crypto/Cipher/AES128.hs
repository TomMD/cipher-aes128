{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE RecordWildCards #-}
module Crypto.Cipher.AES128
  ( -- * Key types with crypto-api instances
    AESKey128, AESKey192, AESKey256
  , BlockCipher(..), buildKeyIO, zeroIV
    -- * GCM Operations
  , makeGCMCtx, aesKeyToGCM, GCMCtx, AES_GCM
  , Crypto.Cipher.AES128.encryptGCM
  , Crypto.Cipher.AES128.decryptGCM
  ) where

import Crypto.Cipher.AES128.Internal as I
import Crypto.Classes
import Data.Function (on)
import Control.Monad (when)
import Data.Serialize
import Data.Tagged
import Data.Word (Word8)
import Foreign.Ptr
import Foreign.ForeignPtr
import Foreign.Marshal.Alloc as F
import System.IO.Unsafe
import Data.ByteString (ByteString)
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

-- GCM Routines
maxTagLen :: Int
maxTagLen = 16

data AuthTag = AuthTag { unAuthTag :: ByteString }

-- | A tuple of key and precomputed data for use by GCM
data GCMCtx k = GCMCtx { gcmkey :: k
                       , gcmpc  :: GCMpc
                       }

instance Eq AuthTag where
    (==)  = constTimeEq `on` unAuthTag

-- A super-class indicating which keys can be used with GCMCtx.
class (BlockCipher k, GetExpanded k) => AES_GCM k where
instance AES_GCM AESKey128
instance AES_GCM AESKey192
instance AES_GCM AESKey256

-- | Given key material produce a context useful for GCM operations
makeGCMCtx :: AES_GCM k => ByteString -> Maybe (GCMCtx k)
makeGCMCtx = fmap aesKeyToGCM . buildKey

-- | Given an AESKey produce a GCM Context.
aesKeyToGCM :: AES_GCM k => k -> GCMCtx k
aesKeyToGCM k = GCMCtx k (I.precomputeGCMdata k)

-- |Encrypts multiple-of-block-sized input, returning a bytestring and tag.
encryptGCM :: AES_GCM k
           => GCMCtx k
           -> ByteString -- ^ IV
           -> ByteString -- ^ Plaintext
           -> ByteString -- ^ AAD
           -> (ByteString, AuthTag)
encryptGCM key iv pt aad = unsafePerformIO $ do
 B.unsafeUseAsCString pt  $ \ptPtr  -> do
  B.unsafeUseAsCString iv  $ \ivPtr  -> do
   B.unsafeUseAsCString aad $ \aadPtr -> do
    ctPtr  <- F.mallocBytes (B.length pt)
    tagPtr <- F.mallocBytes maxTagLen
    encryptGCMPtr key
                  (castPtr ivPtr) (B.length iv)
                  (castPtr ptPtr) (B.length pt)
                  (castPtr aadPtr) (B.length aad)
                  (castPtr tagPtr)
                  (castPtr ctPtr)
    ctBS  <- B.unsafePackMallocCStringLen (castPtr ctPtr, B.length pt)
    tagBS <- B.unsafePackMallocCStringLen (castPtr tagPtr, maxTagLen)
    return (ctBS, AuthTag tagBS)

-- Encrypts multiple-of-block-sized input, filling a pointer with the
-- result of [ctr, ct, tag].
encryptGCMPtr :: AES_GCM k
           => GCMCtx k
           -> Ptr Word8 -- ^ IV
           -> Int       -- ^ IV Length
           -> Ptr Word8 -- ^ Plaintext buffer
           -> Int       -- ^ Plaintext length
           -> Ptr Word8 -- ^ AAD buffer
           -> Int       -- ^ AAD Length
           -> Ptr Word8 -- ^ Tag buffer (always allocated to max length)
           -> Ptr Word8 -- ^ ciphertext buffer (at least encBytes large)
           -> IO ()
encryptGCMPtr (GCMCtx {..}) ivPtr ivLen
                             ptPtr ptLen
                             aadPtr aadLen
                             tagPtr
                             ctPtr =
 do I.encryptGCM gcmkey gcmpc
                   (castPtr ivPtr)  (fromIntegral ivLen)
                   (castPtr aadPtr) (fromIntegral aadLen)
                   (castPtr ptPtr)  (fromIntegral ptLen)
                   (castPtr tagPtr)
                   (castPtr ctPtr)

-- | Decrypts multiple-of-block-sized input, returing a bytestring of the
-- [ctr, ct, tag].
decryptGCM :: AES_GCM k
           => GCMCtx k
           -> ByteString -- ^ IV
           -> ByteString -- ^ Ciphertext
           -> ByteString -- ^ AAD
           -> (ByteString, AuthTag)
           -- ^ Plaintext and incremented context (or an error)
decryptGCM gcmdata iv ct aad = unsafePerformIO $ do
 let ivLen     = B.length iv
     tagLen    = maxTagLen
     ctLen     = B.length ct
 B.unsafeUseAsCString iv  $ \ivPtr  -> do
  B.unsafeUseAsCString ct  $ \ctPtr  -> do
   B.unsafeUseAsCString aad $ \aadPtr -> do
    tagPtr     <- F.mallocBytes tagLen
    ptPtr      <- F.mallocBytes ctLen
    decryptGCM_ptr gcmdata
                   (castPtr ivPtr)   ivLen
                   (castPtr ctPtr)   ctLen
                   (castPtr aadPtr) (B.length aad)
                   (castPtr ptPtr)
                   (castPtr tagPtr)
    tagBS      <- B.unsafePackMallocCStringLen (castPtr tagPtr,tagLen)
    ptBS       <- B.unsafePackMallocCStringLen (castPtr ptPtr, ctLen)
    return (ptBS, AuthTag tagBS)

decryptGCM_ptr :: AES_GCM k
               => GCMCtx k
               -> Ptr Word8 -> Int -- IV
               -> Ptr Word8 -> Int -- CT
               -> Ptr Word8 -> Int -- AAD
               -> Ptr Word8        -- Tag
               -> Ptr Word8        -- Plaintext
               -> IO ()
decryptGCM_ptr (GCMCtx {..})
               ivPtr ivLen
               ctPtr ctLen
               aadPtr aadLen
               tagPtr
               ptPtr =
    I.decryptGCM gcmkey gcmpc
                   ivPtr  (fromIntegral ivLen)
                   aadPtr (fromIntegral aadLen)
                   ctPtr  (fromIntegral ctLen)
                   ptPtr
                   tagPtr
