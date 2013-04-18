import Crypto.Cipher.AES128
import Crypto.Classes
import Crypto.Modes (zeroIV)
import Criterion
import Criterion.Main
import System.Entropy

main = do
    let iv = zeroIV
    pt <- getEntropy (2^20)
    k  <- buildKeyIO :: IO AESKey
    defaultMain
        [ bench "aes-ctr" $ nf (fst . ctr k iv) pt ]
