import qualified Crypto.Cipher.AES128 as AES128
import Crypto.Classes
import Crypto.Types
import Criterion
import Criterion.Main
import System.Entropy
import Data.Serialize
import qualified Data.ByteString as B

main = do
    let iv  = zeroIV
        ivV = B.replicate 16 0
    pt <- getEntropy (2^16)
    k  <- buildKeyIO :: IO AES128.AESKey128
    defaultMain
        [ bench "aes-ecb cipher-aes128" $ nf (AES128.encryptBlock k) pt
        , bench "aes-ctr cipher-aes128" $ nf (fst . AES128.ctr k iv) pt
        ]
