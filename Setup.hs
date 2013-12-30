import Distribution.Simple
import Distribution.Simple.LocalBuildInfo
import Distribution.Simple.Setup
import Distribution.PackageDescription
import Distribution.Simple.Utils
import Distribution.Simple.Program
import Distribution.Verbosity
import System.Process
import System.Directory
import System.Exit

main = defaultMainWithHooks hk
 where
 hk = simpleUserHooks { buildHook = \pd lbi uh bf -> do
                                        let ccProg = Program "gcc" undefined undefined undefined
                                            hcProg = Program "ghc" undefined undefined undefined
                                            mConf  = lookupProgram ccProg (withPrograms lbi)
                                            hcConf = lookupProgram hcProg (withPrograms lbi)
                                            err = error "Could not determine C compiler"
                                            cc  = locationPath . programLocation  . maybe err id $ mConf
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
canUseAesIntrinsicsFlag cc = do
        withTempDirectory normal "" "testIntrinsic" $ \tmpDir -> do
        writeFile (tmpDir ++ "/testIntrinsic.c")
                (unlines        [ "#include <wmmintrin.h>"
                                , "int real_main() {"
                                , "return 0; }"
                                ])
        ec <- rawSystemExitCode normal cc (aesArgsHC ++ ["-c", tmpDir ++ "/testIntrinsic.c"])
        notice normal $ "Result of NI Intrinsics Test: " ++ show (ec == ExitSuccess)
        return (ec == ExitSuccess)
