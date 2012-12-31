import Distribution.Simple
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
 hk = simpleUserHooks { preBuild = \as fs -> do
                                        b <- (preBuild simpleUserHooks) as fs
                                        checkAndAddAES fs b }

checkAndAddAES :: BuildFlags -> HookedBuildInfo -> IO HookedBuildInfo
checkAndAddAES fs x@(m,as) = do
        b  <- canUseAesIntrinsicsFlag fs
        b2 <- haveNIInstrs fs
        let bi = maybe emptyBuildInfo id m
            op = if b && b2 then addNIintrinsicOpt else id
        return (Just (op emptyBuildInfo), as)

addNIintrinsicOpt :: BuildInfo -> BuildInfo
addNIintrinsicOpt bi = bi { ccOptions = ccOptions bi ++ ["-maes", "-mssse3", "-DHAVE_AES_INTRINSICS", "-DHAVE_NI"] }

-- Detect if we have AES NI instructions for acceleration on x86 CPUs
haveNIInstrs :: BuildFlags -> IO Bool
haveNIInstrs cf = do
        -- FIXME cf is always empty, how do we ensure we're testing the right C compiler?
        -- TODO: I am hooking Cabal at the wrong spot, need to hook one stage
        -- later!
        let prog = lookup "cc" (buildProgramPaths cf)
            cc = maybe "gcc" id prog
        withTempDirectory normal "" "testNI" $ \tmpDir -> do
         writeFile (tmpDir ++ "/testNI.c")
               (unlines ["#include <stdint.h>",
                        "/**",
                        " * Returns zero if false, non-zero otherwise",
                        " */",
                        "int cpu_has_ni()",
                        "{",
                        "uint32_t ax,bx,cx,dx,func=1;",
                        "uint32_t regs[4];",
                        "asm volatile (\"cpuid\":",
                        "\"=a\" (ax), \"=b\" (bx), \"=c\" (cx), \"=d\" (dx) : \"a\" (func));",
                        "return (cx & 0x2000000);",
                        "}",
                        "int main()",
                        "{",
                        "    if(cpu_has_ni()) return 0; else return -1;",
                        "}"]
                                )
         ec <- rawSystemExitCode normal cc ["-maes",tmpDir ++ "/testNI.c"]
         notice normal $ "Result of AES NI Test: " ++ show (ec == ExitSuccess)
         return (ec == ExitSuccess)

canUseAesIntrinsicsFlag :: BuildFlags -> IO Bool
canUseAesIntrinsicsFlag cf = do
        -- FIXME cf is always empty, how do we ensure we're testing the right C compiler?
        -- TODO: I am hooking Cabal at the wrong spot, need to hook one stage
        -- later!
        let prog = lookup "cc" (buildProgramPaths cf)
            cc = maybe "gcc" id prog
        withTempDirectory normal "" "testIntrinsic" $ \tmpDir -> do
        writeFile (tmpDir ++ "/testIntrinsic.c")
                (unlines        [ "#include <wmmintrin.h>"
                                , "int main() {"
                                , "return 0; }"
                                ])
        ec <- rawSystemExitCode normal cc ["-maes",tmpDir ++ "/testIntrinsic.c"]
        notice normal $ "Result of NI Intrinsics Test: " ++ show (ec == ExitSuccess)
        return (ec == ExitSuccess)
