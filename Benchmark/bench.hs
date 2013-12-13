import Crypto.Cipher.AES128
import Crypto.Cipher.AES
import Crypto.Classes
import Crypto.Types
import Crypto.Modes (zeroIV)
import Criterion
import Criterion.Main
import System.Entropy
import Data.Serialize
import qualified Data.ByteString as B

main = do
    let iv  = zeroIV
        ivV = B.replicate 16 0
    pt <- getEntropy 16 -- (2^11)
    k  <- buildKeyIO :: IO AESKey
    let kV = initAES (B.pack [0..15])
    defaultMain
        [ bench "aes-ecb cipher-aes128" $ nf (encryptBlock k) pt
        , bench "aes-ctr cipher-aes128" $ nf (fst . ctr k iv) pt
        , bench "aes-ecb cipher-aes"    $ nf (encryptECB kV) pt
        , bench "aes-ctr cipher-aes"    $ nf (encryptCTR kV ivV) pt
        , bench "aes-gcm cipher-aes"    $ nf (fst . encryptGCM kV ivV B.empty) pt]
