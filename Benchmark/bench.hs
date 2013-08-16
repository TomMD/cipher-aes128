import Crypto.Cipher.AES128
import Crypto.Cipher.AES
import Crypto.Classes
import Crypto.Modes (zeroIV)
import Criterion
import Criterion.Main
import System.Entropy
import Data.Serialize
import qualified Data.ByteString as B

main = do
    let iv = zeroIV
        ivV = IV (B.replicate 16 0)
    pt <- getEntropy (2^12)
    k  <- buildKeyIO :: IO AESKey
    let kV = initKey (B.pack [0..15])
    defaultMain
        [ bench "aes-ctr cipher-aes128" $ nf (fst . ctr k iv) pt
        , bench "aes-ctr cipher-aes" $ nf (encryptCTR kV ivV) pt
        , bench "aes-gcm cipher-aes" $ nf (encryptGCM kV ivV B.empty) pt]
