module Crypto.Cipher.AES128
  ( AESKey
  ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Unsafe as B
import qualified Data.ByteString.Internal as B
import Data.Tagged
import Crypto.Cipher.AES128.Internal
import Crypto.Classes
import Foreign.Ptr
import System.IO.Unsafe

import Data.Serialize

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

blkSize :: Int
blkSize = 16
