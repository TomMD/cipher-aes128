{-# LANGUAGE ForeignFunctionInterface, EmptyDataDecls #-}
module Crypto.Cipher.AES128.Internal
        ( AESKey(..), RawKey(..)
        , generateKey
        , encryptECB
        , decryptECB
        , encryptGCM
        , decryptGCM
        , encryptCTR
        , decryptCTR
        ) where

import Foreign.Ptr
import Foreign.ForeignPtr
import Foreign.Storable
import Data.Word
import Data.Bits (shiftL, (.|.))

-- AES Bindings
data AESKeyStruct
type AESKeyPtr = Ptr AESKeyStruct
data RawKey = RKey { lowK,highK :: {-# UNPACK #-} !Word64 }
data AESKey = AESKey { rawKey      :: !RawKey
                     , expandedKey :: ForeignPtr AESKeyStruct }

foreign import ccall unsafe "aes/aes.h generate_key128"
        c_generate_key128 :: AESKeyPtr -> Ptr Word8 -> IO ()

foreign import ccall unsafe "aes/aes.h allocate_key128"
        c_allocate_key128 :: IO AESKeyPtr

foreign import ccall unsafe "aes/aes.h &free_key128"
        c_free_key128 :: FunPtr (AESKeyPtr -> IO ())

foreign import ccall unsafe "aes/aes.h encrypt_ecb"
        c_encrypt_ecb :: AESKeyPtr -> Ptr Word8 -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "aes/aes.h decrypt_ecb"
        c_decrypt_ecb :: AESKeyPtr -> Ptr Word8 -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "aes/aes.h aes_gcm_full_encrypt"
    c_encrypt_gcm :: AESKeyPtr
                  -> Ptr Word8 -> Word32 -- ^ IV and length
                  -> Ptr Word8 -> Word32 -- ^ AAD and length
                  -> Ptr Word8 -> Word32 -- ^ PT and length
                  -> Ptr Word8 -> Ptr Word8 -- ^ Result CT and TAG
                  -> IO ()

foreign import ccall unsafe "aes/aes.h aes_gcm_full_decrypt"
    c_decrypt_gcm :: AESKeyPtr
                  -> Ptr Word8 -> Word32 -- ^ IV and length
                  -> Ptr Word8 -> Word32 -- ^ AAD and length
                  -> Ptr Word8 -> Word32 -- ^ CT and length
                  -> Ptr Word8 -> Ptr Word8 -- ^ Result PT and TAG
                  -> IO ()

foreign import ccall unsafe "aes/aes.h encrypt_ctr"
    c_encrypt_ctr :: AESKeyPtr
                  -> Ptr Word8 -- ^ 128 bit IV
                  -> Ptr Word8 -- ^ 128 bit new IV
                  -> Ptr Word8 -- ^ Result
                  -> Ptr Word8 -- ^ Input
                  -> Word32    -- ^ Input length in bytes
                  -> IO ()

c_decrypt_ctr :: AESKeyPtr
              -> Ptr Word8 -- ^ 128 bit IV
              -> Ptr Word8 -- ^ 128 bit new IV
              -> Ptr Word8 -- ^ Result
              -> Ptr Word8 -- ^ Input
              -> Word32    -- ^ Input length in bytes
              -> IO ()
c_decrypt_ctr = c_encrypt_ctr

blkSzC :: Word32
blkSzC = 16

-- Given a 16 byte buffer, allocate and return an AESKey
generateKey :: Ptr Word64 -- ^ Buffer of 16 bytes of key material
            -> IO AESKey
generateKey keyPtr  = do
    raw <- do
            a <- peekLE (castPtr keyPtr)
            let keyPtr2 = (castPtr keyPtr) `plusPtr` sizeOf a
            b <- peekLE keyPtr2
            return (RKey b a)
    k <- c_allocate_key128
    c_generate_key128 k (castPtr keyPtr)
    fmap (AESKey raw) (newForeignPtr c_free_key128 k)
 where
     peekLE :: Ptr Word8 -> IO Word64
     peekLE p = do
        a1 <- peekElemOff p 0
        a2 <- peekElemOff p 1
        a3 <- peekElemOff p 2
        a4 <- peekElemOff p 3
        a5 <- peekElemOff p 4
        a6 <- peekElemOff p 5
        a7 <- peekElemOff p 6
        a8 <- peekElemOff p 7
        let f n s = fromIntegral n `shiftL` s
        let a = (f a1 56) .|. (f a2 48) .|. (f a3 40) .|.
                (f a4 32) .|. (f a5 24) .|. (f a6 16) .|.
                (f a7 8)  .|. fromIntegral a8
        return a
{-# INLINE generateKey #-}

-- An encrypt function that can handle up to blks < maxBound `div` 16 :: Word32
-- simultaneous blocks.
encryptECB :: AESKey    -- ^ The key
           -> Ptr Word8 -- ^ The result buffer
           -> Ptr Word8 -- ^ The source buffer
           -> Int       -- ^ The input size in blocks
           -> IO ()
encryptECB (AESKey _ k) dst src blks = withForeignPtr k $ \p -> c_encrypt_ecb p dst src (fromIntegral blks)
{-# INLINE encryptECB #-}

decryptECB :: AESKey    -- ^ The key
           -> Ptr Word8 -- ^ The result buffer
           -> Ptr Word8 -- ^ The source buffer
           -> Int       -- ^ The input size in blocks
           -> IO ()
decryptECB (AESKey _ k) dst src blks
  | blks > fromIntegral (maxBound `div` blkSzC :: Word32) = error "Can not decrypt so many blocks at once"
  | otherwise = withForeignPtr k $ \p -> c_decrypt_ecb p dst src (fromIntegral blks)
{-# INLINE decryptECB #-}

encryptGCM :: AESKey
           -> Ptr Word8 -> Int -- IV
           -> Ptr Word8 -> Int -- AAD
           -> Ptr Word8 -> Int -- PT
           -> Ptr Word8        -- CT  (output)
           -> Ptr Word8        -- Tag (output)
           -> IO ()
encryptGCM (AESKey _ k) iv ivLen aad aadLen pt ptLen ct tag = withForeignPtr k $ \p -> do
        c_encrypt_gcm p iv (fromIntegral ivLen) aad (fromIntegral aadLen) pt (fromIntegral ptLen) ct tag
{-# INLINE encryptGCM #-}

decryptGCM :: AESKey
           -> Ptr Word8 -> Int -- IV
           -> Ptr Word8 -> Int -- AAD
           -> Ptr Word8 -> Int -- CT
           -> Ptr Word8        -- PT  (output)
           -> Ptr Word8        -- Tag (output)
           -> IO ()
decryptGCM (AESKey _ k) iv ivLen aad aadLen ct ctLen pt tag = withForeignPtr k $ \p -> do
        c_decrypt_gcm p iv (fromIntegral ivLen) aad (fromIntegral aadLen) ct (fromIntegral ctLen) pt tag
{-# INLINE decryptGCM #-}

encryptCTR :: AESKey
           -> Ptr Word8 -- ^ IV
           -> Ptr Word8 -- ^ NEW IV
           -> Ptr Word8 -- ^ CT
           -> Ptr Word8 -- ^ PT
           -> Int       -- ^ Length in bytes
           -> IO ()
encryptCTR (AESKey _ k) iv niv ct pt len = withForeignPtr k $ \p -> do
    c_encrypt_ctr p iv niv ct pt (fromIntegral len)
{-# INLINE encryptCTR #-}

decryptCTR :: AESKey
           -> Ptr Word8 -- ^ IV
           -> Ptr Word8 -- ^ NEW IV
           -> Ptr Word8 -- ^ CT
           -> Ptr Word8 -- ^ PT
           -> Int       -- ^ Length in bytes
           -> IO ()

decryptCTR (AESKey _ k) iv niv ct pt len = withForeignPtr k $ \p -> do
    c_decrypt_ctr p iv niv ct pt (fromIntegral len)
{-# INLINE decryptCTR #-}
