{-# LANGUAGE ForeignFunctionInterface, EmptyDataDecls, ViewPatterns #-}
module Crypto.Cipher.AES128.Internal
        ( AESKey128(..), AESKey192(..), AESKey256(..), RawKey128(..), RawKey192(..), RawKey256(..), GCM(..), GCMpc
        , generateKey128, generateKey192, generateKey256
        , generateGCM, precomputeGCMdata
        , encryptECB
        , decryptECB
        , encryptCTR
        , decryptCTR
        , encryptGCM, decryptGCM
        -- * Piece-meal functions
        , cipherOnlyGCM
        , decipherOnlyGCM
        , finishGCM, aadGCM
        -- * Internal, will not be exported in a near-future release.
        , GetExpanded
        ) where

import Foreign.Ptr
import Foreign.ForeignPtr
import Foreign.Storable
import Foreign.Marshal.Alloc
import Data.Word
import Data.Bits (shiftL, (.|.))
import System.IO.Unsafe

-- AES Bindings
data AESKeyStruct
type AESKeyPtr = Ptr AESKeyStruct

data RawKey128 = RKey128 { lowK128,highK128 :: {-# UNPACK #-} !Word64 }
data AESKey128 = AESKey128 { rawKey128      :: !RawKey128
                           , expandedKey128 :: ForeignPtr AESKeyStruct }

data RawKey192 = RKey192 { lowK192,midK192,highK192 :: {-# UNPACK #-} !Word64 }
data AESKey192 = AESKey192 { rawKey192      :: !RawKey192
                           , expandedKey192 :: ForeignPtr AESKeyStruct }

data RawKey256 = RKey256 { aK256,bK256,cK256,dK256 :: {-# UNPACK #-} !Word64 }
data AESKey256 = AESKey256 { rawKey256      :: !RawKey256
                           , expandedKey256 :: ForeignPtr AESKeyStruct }

class GetExpanded a where
    expandedKey :: a -> ForeignPtr AESKeyStruct

instance GetExpanded AESKey256 where
    expandedKey = expandedKey256
instance GetExpanded AESKey192 where
    expandedKey = expandedKey192
instance GetExpanded AESKey128 where
    expandedKey = expandedKey128

type AESGcmPtr = Ptr GCMStruct
data GCMStruct

-- Store the key, the precomputed GCM data, and the current IV by way of
-- a foreign pointer
data GCM k = GCM { _gcmFP   :: GCMpc
                 , _keyFP   :: k
                 , _ctxFP2  :: ForeignPtr CTXStruct
                 }

newtype GCMpc = GCMpc { unGCMpc :: ForeignPtr GCMStruct }

type AESCtxPtr = Ptr CTXStruct
data CTXStruct
-- data CTX = CTX { _ctxFP :: ForeignPtr CTXStruct }

foreign import ccall unsafe "aes.h tmd_aes_initkey"
        c_aes_initkey :: AESKeyPtr -> Ptr Word8 -> Word8 -> IO ()

foreign import ccall unsafe "aes.h tmd_allocatekey"
        c_allocate_key :: IO AESKeyPtr

foreign import ccall unsafe "aes.h &tmd_freekey"
        c_free_key :: FunPtr (AESKeyPtr -> IO ())

-- foreign import ccall unsafe "aes.h tmd_freekey"
--         c_key_free :: AESKeyPtr -> IO ()

foreign import ccall unsafe "aes.h tmd_allocatectx"
        c_allocate_ctx :: IO AESCtxPtr

foreign import ccall unsafe "aes.h &tmd_freectx"
        c_free_ctx :: FunPtr (AESCtxPtr -> IO ())

-- foreign import ccall unsafe "aes.h tmd_freectx"
--         c_ctx_free :: AESCtxPtr -> IO ()

foreign import ccall unsafe "aes.h tmd_allocategcm"
        c_allocate_gcm :: IO AESGcmPtr

foreign import ccall unsafe "aes.h &tmd_freegcm"
        c_free_gcm :: FunPtr (AESGcmPtr -> IO ())

-- foreign import ccall unsafe "aes.h tmd_freegcm"
--         c_gcm_free :: AESGcmPtr -> IO ()

foreign import ccall unsafe "aes.h tmd_aes_gcm_init"
    c_gcm_init :: AESGcmPtr
               -> AESKeyPtr
               -> IO ()

foreign import ccall unsafe "aes.h tmd_aes_ctx_init"
    c_ctx_init :: AESGcmPtr
               -> AESCtxPtr
               -> AESKeyPtr
               -> Ptr Word8 -> Word32 -- ^ IV and length
               -> IO ()


foreign import ccall unsafe "aes.h tmd_aes_encrypt_ecb"
        c_encrypt_ecb :: Ptr Word8 -> AESKeyPtr -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "aes.h tmd_aes_decrypt_ecb"
        c_decrypt_ecb :: Ptr Word8 -> AESKeyPtr -> Ptr Word8 -> Word32 -> IO ()


foreign import ccall unsafe "aes.h tmd_aes_gcm_finish"
    c_gcm_finish  :: Ptr Word8           -- Tag
                  -> AESGcmPtr
                  -> AESKeyPtr           -- Key
                  -> AESCtxPtr           -- Context
                  -> IO ()

foreign import ccall unsafe "aes.h tmd_aes_gcm_aad"
    c_gcm_aad     :: AESGcmPtr
                  -> AESCtxPtr
                  -> Ptr Word8 -> Word32 -- AAD, len
                  -> IO ()

foreign import ccall unsafe "aes.h tmd_aes_gcm_decrypt"
    c_gcm_decrypt :: Ptr Word8           -- Output
                  -> AESGcmPtr
                  -> AESCtxPtr
                  -> AESKeyPtr
                  -> Ptr Word8 -> Word32 -- CT and length
                  -> IO ()

foreign import ccall unsafe "aes.h tmd_aes_gcm_encrypt"
    c_gcm_encrypt :: Ptr Word8           -- Output
                  -> AESGcmPtr
                  -> AESCtxPtr
                  -> AESKeyPtr
                  -> Ptr Word8 -> Word32 -- PT and length
                  -> IO ()

foreign import ccall unsafe "aes.h tmd_aes_gcm_full_encrypt"
    c_gcm_full_encrypt :: AESKeyPtr -> AESGcmPtr
                       -> Ptr Word8 -> Word32           -- IV, IVLen
                       -> Ptr Word8 -> Word32           -- AAD, AADLen
                       -> Ptr Word8 -> Word32           -- PT, PTLen
                       -> Ptr Word8                     -- CT
                       -> Ptr Word8                     -- Tag
                       -> IO ()

foreign import ccall unsafe "aes.h tmd_aes_gcm_full_decrypt"
    c_gcm_full_decrypt :: AESKeyPtr -> AESGcmPtr
                       -> Ptr Word8 -> Word32           -- IV, IVLen
                       -> Ptr Word8 -> Word32           -- AAD, AADLen
                       -> Ptr Word8 -> Word32           -- PT, PTLen
                       -> Ptr Word8                     -- CT
                       -> Ptr Word8                     -- Tag
                       -> IO ()

foreign import ccall unsafe "aes.h tmd_aes_encrypt_ctr"
    c_encrypt_ctr :: Ptr Word8 -- ^ Output
                  -> AESKeyPtr
                  -> Ptr Word8 -- ^ 128 bit IV
                  -> Ptr Word8 -- ^ 128 bit new IV
                  -> Ptr Word8 -- ^ Input
                  -> Word32    -- ^ Input length in bytes
                  -> IO ()

c_decrypt_ctr :: Ptr Word8 -- ^ Result
              -> AESKeyPtr
              -> Ptr Word8 -- ^ 128 bit IV
              -> Ptr Word8 -- ^ 128 bit new IV
              -> Ptr Word8 -- ^ Input
              -> Word32    -- ^ Input length in bytes
              -> IO ()
c_decrypt_ctr = c_encrypt_ctr

blkSzC :: Word32
blkSzC = 16

-- Given a 16 byte buffer, allocate and return an AESKey
generateKey128 :: Ptr Word64
            -- ^ Buffer of 16 bytes of key material
            -> IO (Maybe AESKey128)
generateKey128 keyPtr = do
    raw <- do
            a <- peekLE (castPtr keyPtr)
            let keyPtr2 = (castPtr keyPtr) `plusPtr` sizeOf a
            b <- peekLE keyPtr2
            return (RKey128 b a)
    k <- c_allocate_key
    c_aes_initkey k (castPtr keyPtr) 16
    fmap (Just . AESKey128 raw) (newForeignPtr c_free_key k)
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
{-# INLINE generateKey128 #-}

-- Given a 16 byte buffer, allocate and return an AESKey
generateKey192 :: Ptr Word64
            -- ^ Buffer of 16 bytes of key material
            -> IO (Maybe AESKey192)
generateKey192 keyPtr = do
    raw <- do
            a <- peekLE (castPtr keyPtr)
            let keyPtr2 = (castPtr keyPtr) `plusPtr` sizeOf a
            b <- peekLE keyPtr2
            let keyPtr3 = (castPtr keyPtr) `plusPtr` sizeOf a `plusPtr` sizeOf b
            c <- peekLE keyPtr3
            return (RKey192 c b a)
    k <- c_allocate_key
    c_aes_initkey k (castPtr keyPtr) 24
    fmap (Just . AESKey192 raw) (newForeignPtr c_free_key k)
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
{-# INLINE generateKey192 #-}

-- Given a 16 byte buffer, allocate and return an AESKey
generateKey256 :: Ptr Word64
            -- ^ Buffer of 16 bytes of key material
            -> IO (Maybe AESKey256)
generateKey256 keyPtr = do
    raw <- do
            a <- peekLE (castPtr keyPtr)
            let keyPtr2 = (castPtr keyPtr) `plusPtr` sizeOf a
            b <- peekLE keyPtr2
            let keyPtr3 = (castPtr keyPtr) `plusPtr` sizeOf a `plusPtr` sizeOf b
            c <- peekLE keyPtr3
            let keyPtr4 = (castPtr keyPtr) `plusPtr` sizeOf a `plusPtr` sizeOf b `plusPtr` sizeOf c
            d <- peekLE keyPtr4
            return (RKey256 d c b a)
    k <- c_allocate_key
    c_aes_initkey k (castPtr keyPtr) 32
    fmap (Just . AESKey256 raw) (newForeignPtr c_free_key k)
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
{-# INLINE generateKey256 #-}

-- Given a 16 byte buffer, allocate and return an key expansion useful for
-- GCM
generateGCM :: GetExpanded k
            => k
            -> IO (GCM k)
generateGCM keyStruct = do
    let gcmPC = precomputeGCMdata keyStruct
    withForeignPtr (expandedKey keyStruct) $ \k -> do
      c <- c_allocate_ctx
      allocaBytes 12 $ \ivPtr -> withGCMpc gcmPC $ \g -> do
          mapM_ (\i -> pokeElemOff ivPtr i (0::Word8)) [0..11]
          c_ctx_init g c k ivPtr 12
      cFP <- newForeignPtr c_free_ctx c
      return (GCM gcmPC keyStruct cFP)
{-# INLINE generateGCM #-}

precomputeGCMdata :: GetExpanded k => k -> GCMpc
precomputeGCMdata k = unsafePerformIO $ do
    withForeignPtr (expandedKey k) $ \kp -> do
        g <- c_allocate_gcm
        c_gcm_init g kp
        gFP <- newForeignPtr c_free_gcm g
        return (GCMpc gFP)

withGCMpc :: GCMpc -> (AESGcmPtr -> IO a) -> IO a
withGCMpc (GCMpc p) = withForeignPtr p

-- An encrypt function that can handle up to blks < maxBound `div` 16 :: Word32
-- simultaneous blocks.
encryptECB :: GetExpanded k
           => k         -- ^ The key
           -> Ptr Word8 -- ^ The result buffer
           -> Ptr Word8 -- ^ The source buffer
           -> Int       -- ^ The input size in blocks
           -> IO ()
encryptECB (expandedKey -> k) dst src blks = withForeignPtr k $ \p -> c_encrypt_ecb dst p src (fromIntegral blks)
{-# INLINE encryptECB #-}

decryptECB :: GetExpanded k
           => k         -- ^ The key
           -> Ptr Word8 -- ^ The result buffer
           -> Ptr Word8 -- ^ The source buffer
           -> Int       -- ^ The input size in blocks
           -> IO ()
decryptECB (expandedKey -> k) dst src blks
  | blks > fromIntegral (maxBound `div` blkSzC :: Word32) = error "Can not decrypt so many blocks at once"
  | otherwise = withForeignPtr k $ \p -> c_decrypt_ecb dst p src (fromIntegral blks)
{-# INLINE decryptECB #-}

aadGCM :: GetExpanded k => GCM k -> Ptr Word8 -> Int -> IO ()
aadGCM gcm aad aadLen = withForeignGCM gcm $ \(g,_k,c) ->
    c_gcm_aad g c aad (fromIntegral aadLen)

cipherOnlyGCM :: GetExpanded k
              => GCM k
              -> Ptr Word8         -- CT  (length assumed to match PT)
              -> Ptr Word8 -> Int  -- PT and length
              -> IO ()
cipherOnlyGCM gcm ct pt ptlen = withForeignGCM gcm $ \(g,k,c) ->
    c_gcm_encrypt ct g c k pt  (fromIntegral ptlen)

decipherOnlyGCM :: GetExpanded k
                => GCM k
                -> Ptr Word8         -- PT (length assumed to match CT)
                -> Ptr Word8 -> Int  -- CT and length
                -> IO ()
decipherOnlyGCM gcm pt ct ctlen = withForeignGCM gcm $ \(g,k,c) ->
    c_gcm_decrypt pt g c k ct (fromIntegral ctlen)

finishGCM :: GetExpanded k
          => GCM k     -- GCM context (which is mutated!)
          -> Ptr Word8 -- Tag, must point to 16 byte buffer (or larger)
          -> IO ()
finishGCM gcm tagPtr =
    withForeignGCM gcm $ \(gp,kp,cp) -> c_gcm_finish tagPtr gp kp cp

withForeignGCM :: GetExpanded k => GCM k -> ((AESGcmPtr, AESKeyPtr, AESCtxPtr) -> IO a) -> IO a
withForeignGCM (GCM g k c) f =
    withForeignPtr (unGCMpc g) $ \gp -> withForeignPtr (expandedKey k) $ \kp -> withForeignPtr c $ \cp -> f (gp,kp,cp)

encryptCTR :: GetExpanded k
           => k
           -> Ptr Word8 -- ^ IV
           -> Ptr Word8 -- ^ NEW IV
           -> Ptr Word8 -- ^ CT
           -> Ptr Word8 -- ^ PT
           -> Int       -- ^ Length in bytes
           -> IO ()
encryptCTR (expandedKey -> k) iv niv ct pt len = withForeignPtr k $ \p -> do
    c_encrypt_ctr ct p iv niv pt (fromIntegral len)
{-# INLINE encryptCTR #-}

decryptCTR :: GetExpanded k
           => k
           -> Ptr Word8 -- ^ IV
           -> Ptr Word8 -- ^ NEW IV
           -> Ptr Word8 -- ^ PT
           -> Ptr Word8 -- ^ CT
           -> Int       -- ^ Length in bytes
           -> IO ()
decryptCTR (expandedKey -> k) iv niv pt ct len = withForeignPtr k $ \p -> do
    c_decrypt_ctr pt p iv niv ct (fromIntegral len)

encryptGCM :: GetExpanded k
           => k                   -- AES{128,192,256}
           -> GCMpc               -- Precomputed GCM Data
           -> Ptr Word8 -> Word32 -- IV, len
           -> Ptr Word8 -> Word32 -- AAD, len
           -> Ptr Word8 -> Word32 -- PT, len
           -> Ptr Word8 -- CT  (out)
           -> Ptr Word8 -- Tag (128 bits out)
           -> IO ()
encryptGCM (expandedKey -> k) (GCMpc g) iv ivLen aad aadLen pt ptLen ct tag =
    withForeignPtr k $ \kp ->
      withForeignPtr g $ \gp ->
       c_gcm_full_encrypt kp gp iv ivLen aad aadLen pt ptLen ct tag

decryptGCM :: GetExpanded k
           => k
           -> GCMpc
           -> Ptr Word8 -> Word32 -- IV, len
           -> Ptr Word8 -> Word32 -- AAD, len
           -> Ptr Word8 -> Word32 -- CT, len
           -> Ptr Word8           -- PT (out)
           -> Ptr Word8           -- Tag (out)
           -> IO ()
decryptGCM (expandedKey -> k) (GCMpc g) iv ivLen aad aadLen ct ctLen pt tag =
    withForeignPtr k $ \kp ->
      withForeignPtr g $ \gp ->
       c_gcm_full_decrypt kp gp iv ivLen aad aadLen ct ctLen pt tag

{-# INLINE decryptCTR #-}
