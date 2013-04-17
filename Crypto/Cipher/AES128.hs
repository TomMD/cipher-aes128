module Crypto.Cipher.AES128
  ( AESKey
  ) where

import Crypto.Cipher.AES128.Internal
import Crypto.Classes
import Crypto.Types
import Control.Monad (when)
import Data.Serialize
import Data.Tagged
import Foreign.Ptr
import Foreign.ForeignPtr
import System.IO.Unsafe
import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as B
import qualified Data.ByteString.Unsafe as B

instance Serialize AESKey where
    put k = do
        let RKey l h = (rawKey k)
        putWord64be h
        putWord64be l

    get = do
        b <- getByteString 16
        case buildKey b of
            Nothing -> fail "Invalid key on 'get'"
            Just k  -> return k

instance BlockCipher AESKey where
    blockSize = Tagged 128
    keyLength = Tagged 128
    buildKey bs 
      | B.length bs >= 16 = unsafePerformIO $
          B.unsafeUseAsCString bs $ \ptr -> do
            k <- generateKey (castPtr ptr)
            return (Just k)
      | otherwise = Nothing
    encryptBlock k b = unsafePerformIO $ do
        B.unsafeUseAsCStringLen b $ \(inP,len) -> do
         B.create (B.length b) $ \outP -> do
            encryptECB k (castPtr outP) (castPtr inP) (len`div`blkSize)
    decryptBlock k b = unsafePerformIO $ do
        B.unsafeUseAsCStringLen b $ \(inP,len) -> do
         B.create (B.length b) $ \outP -> do
            decryptECB k (castPtr outP) (castPtr inP) (len`div`blkSize)
    ctr k (IV bs) pt = unsafePerformIO $ do
        B.unsafeUseAsCStringLen pt $ \(inP, len) -> do
         B.unsafeUseAsCStringLen bs $ \(ivP, ivLen) -> do
            when (ivLen /= (blockSizeBytes .::. k))
                (error "Cipher-AES128: IV is too short!  They type system would have/should have caught this if you didn't use the IV constructor...")
            newIVFP <- B.mallocByteString ivLen
            ct <- B.create len $ \outP -> withForeignPtr newIVFP $ \newIVP -> do
                encryptCTR k (castPtr ivP) (castPtr newIVP) (castPtr outP) (castPtr inP) len
            let newIV = B.fromForeignPtr newIVFP 0 ivLen
            return (ct,IV newIV)
    unCtr = ctr

blkSize :: Int
blkSize = 16
