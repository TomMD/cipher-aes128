{-# LANGUAGE CPP #-}
import Control.Monad (unless)
import Distribution.Simple
import Distribution.Simple.LocalBuildInfo
import Distribution.Simple.Utils
import Distribution.Simple.Program
import Distribution.Verbosity
import System.Process
import System.Exit
import System.IO (hFlush, stdout)

main :: IO ()
main = defaultMainWithHooks hk
 where
 hk = simpleUserHooks { buildHook = \pd lbi uh bf -> do
                                        let mConf  = lookupProgram gccProgram (withPrograms lbi)
                                            hcConf = lookupProgram ghcProgram (withPrograms lbi)
                                            err = error "Could not determine C compiler"
                                            _cc  = locationPath . programLocation  . maybe err id $ mConf
                                            hc  = locationPath . programLocation  . maybe err id $ hcConf
                                        b <- canUseAesIntrinsicsFlag hc
                                        let newWithPrograms1 = userSpecifyArgs "gcc" aesArgs (withPrograms lbi)
                                            newWithPrograms  = userSpecifyArgs "ghc" aesArgsHC newWithPrograms1
                                            lbiNew = if b then (lbi {withPrograms = newWithPrograms }) else lbi
                                        buildHook simpleUserHooks pd lbiNew uh bf
                      }

aesArgs :: [String]
aesArgs = ["-mpclmul", "-maes", "-mssse3", "-DHAVE_AES_INTRINSICS", "-DWITH_AESNI"]

aesArgsHC :: [String]
aesArgsHC = map ("-optc" ++) aesArgs

canUseAesIntrinsicsFlag :: FilePath -> IO Bool
canUseAesIntrinsicsFlag cc = withTempDirectory normal "" "testIntrinsic" $ \tmpDir -> do
          writeFile (tmpDir ++ "/testIntrinsic.c")
                (unlines        [ "#include <wmmintrin.h>"
                                , "int real_main() {"
                                , "return 0; }"
                                ])
          ec <- myRawSystemExitCode normal cc (aesArgsHC ++ ["-c", tmpDir ++ "/testIntrinsic.c"])
          notice normal $ "Result of NI Intrinsics Test: " ++ show (ec == ExitSuccess)
          return (ec == ExitSuccess)

myRawSystemExitCode :: Verbosity -> FilePath -> [String] -> IO ExitCode
#if __GLASGOW_HASKELL__ >= 704
-- We know for sure, that if GHC >= 7.4 implies Cabal >= 1.14
myRawSystemExitCode = rawSystemExitCode
#else
-- Legacy branch:
-- We implement our own 'rawSystemExitCode', this will even work if
-- the user happens to have Cabal >= 1.14 installed with GHC 7.0 or
-- 7.2
myRawSystemExitCode verbosity path args = do
    printRawCommandAndArgs verbosity path args
    hFlush stdout
    exitcode <- rawSystem path args
    unless (exitcode == ExitSuccess) $ do
        debug verbosity $ path ++ " returned " ++ show exitcode
    return exitcode
  where
    printRawCommandAndArgs :: Verbosity -> FilePath -> [String] -> IO ()
    printRawCommandAndArgs verbosity path args
      | verbosity >= deafening = print (path, args)
      | verbosity >= verbose = putStrLn $ unwords (path : args)
      | otherwise = return ()
#endif
