module Crypto.Cipher.AES128
  ( AES128
  ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Unsafe as B
import qualified Data.ByteString.Internal as B
import Data.Tagged
import Crypto.Cipher.Internal.AES128
import Crypto.Classes
import Foreign.Ptr
import System.IO.Unsafe

import Data.Serialize

newtype AES128 = AES128 AESKey

instance Serialize AES128 where
    put (AES128 k) = do
        let RKey l h = (rawKey k)
        putWord64be h
        putWord64be l

    get = do
        b <- getByteString 16
        case buildKey b of
            Nothing -> fail "Invalid key on 'get'"
            Just k  -> return k

instance BlockCipher AES128 where
    blockSize = Tagged 128
    keyLength = Tagged 128
    buildKey bs 
      | B.length bs >= 16 = unsafePerformIO $
          B.unsafeUseAsCString bs $ \ptr -> do
            k <- generateKey (castPtr ptr)
            return (Just (AES128 k))
      | otherwise = Nothing
    encryptBlock (AES128 k) b = unsafePerformIO $ do
        B.unsafeUseAsCStringLen b $ \(inP,len) -> do
         B.create (B.length b) $ \outP -> do
            encrypt k (castPtr inP) (castPtr outP) (len`div`blkSize)
    decryptBlock (AES128 k) b = unsafePerformIO $ do
        B.unsafeUseAsCStringLen b $ \(inP,len) -> do
         B.create (B.length b) $ \outP -> do
            decrypt k (castPtr inP) (castPtr outP) (len`div`blkSize)

blkSize :: Int
blkSize = 16
