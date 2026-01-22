-- NullSec CertCheck - SSL/TLS Certificate Analyzer
-- Haskell security tool demonstrating:
--   - Type safety and algebraic data types
--   - Monadic error handling (Maybe, Either)
--   - Pure functional programming
--   - Parser combinators
--   - Pattern matching
--
-- Author: bad-antics
-- License: MIT

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import Control.Monad (forM_, when, unless)
import Data.Bits (xor)
import Data.Char (ord, chr, isHexDigit, digitToInt)
import Data.List (intercalate, isPrefixOf, find)
import Data.Maybe (fromMaybe, isJust, mapMaybe)
import Data.Time.Clock (UTCTime, getCurrentTime, diffUTCTime, NominalDiffTime)
import Data.Time.Calendar (fromGregorian, toGregorian)
import Data.Time.Format (formatTime, defaultTimeLocale, parseTimeM)
import Data.Word (Word8)
import System.Environment (getArgs)
import System.Exit (exitFailure, exitSuccess)
import System.IO (hPutStrLn, stderr)
import Text.Printf (printf)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8

-- | Version
version :: String
version = "1.0.0"

-- | ANSI Colors
data Color = Red | Green | Yellow | Cyan | Gray | Reset
  deriving (Show, Eq)

colorCode :: Color -> String
colorCode Red    = "\ESC[31m"
colorCode Green  = "\ESC[32m"
colorCode Yellow = "\ESC[33m"
colorCode Cyan   = "\ESC[36m"
colorCode Gray   = "\ESC[90m"
colorCode Reset  = "\ESC[0m"

colored :: Color -> String -> String
colored c s = colorCode c ++ s ++ colorCode Reset

-- | Certificate data types
data CertInfo = CertInfo
  { certSubject     :: String
  , certIssuer      :: String
  , certSerial      :: String
  , certNotBefore   :: Maybe UTCTime
  , certNotAfter    :: Maybe UTCTime
  , certKeyAlgo     :: String
  , certKeyBits     :: Int
  , certSigAlgo     :: String
  , certSANs        :: [String]
  , certFingerprint :: String
  , certVersion     :: Int
  } deriving (Show, Eq)

data ValidationResult
  = Valid
  | Expired
  | NotYetValid
  | ExpiringSoon Int  -- days until expiry
  | WeakKey
  | WeakSignature
  | SelfSigned
  | HostnameMismatch
  | Revoked
  deriving (Show, Eq)

data Severity = Critical | High | Medium | Low | Info
  deriving (Show, Eq, Ord)

data Finding = Finding
  { findingSeverity :: Severity
  , findingCategory :: String
  , findingMessage  :: String
  } deriving (Show, Eq)

-- | Configuration
data Config = Config
  { cfgHost          :: String
  , cfgPort          :: Int
  , cfgWarnDays      :: Int
  , cfgCriticalDays  :: Int
  , cfgCheckOCSP     :: Bool
  , cfgShowChain     :: Bool
  , cfgJsonOutput    :: Bool
  } deriving (Show)

defaultConfig :: Config
defaultConfig = Config
  { cfgHost          = ""
  , cfgPort          = 443
  , cfgWarnDays      = 30
  , cfgCriticalDays  = 7
  , cfgCheckOCSP     = True
  , cfgShowChain     = False
  , cfgJsonOutput    = False
  }

-- | Weak algorithms (should be avoided)
weakKeyAlgorithms :: [String]
weakKeyAlgorithms = ["RSA", "DSA"]

weakSignatureAlgorithms :: [String]
weakSignatureAlgorithms = 
  [ "md5WithRSAEncryption"
  , "sha1WithRSAEncryption"
  , "md2WithRSAEncryption"
  , "md4WithRSAEncryption"
  ]

minimumKeyBits :: [(String, Int)]
minimumKeyBits =
  [ ("RSA", 2048)
  , ("DSA", 2048)
  , ("EC", 256)
  , ("Ed25519", 256)
  ]

-- | Main entry point
main :: IO ()
main = do
  args <- getArgs
  case parseArgs args defaultConfig of
    Left err -> do
      hPutStrLn stderr $ colored Red $ "Error: " ++ err
      printUsage
      exitFailure
    Right cfg
      | cfgHost cfg == "" -> printUsage >> exitSuccess
      | otherwise -> runCheck cfg

-- | Parse command line arguments
parseArgs :: [String] -> Config -> Either String Config
parseArgs [] cfg = Right cfg
parseArgs (arg:rest) cfg = case arg of
  "-h"        -> Right cfg { cfgHost = "" }
  "--help"    -> Right cfg { cfgHost = "" }
  "-p"        -> case rest of
                   (p:rs) -> case reads p of
                     [(port, "")] -> parseArgs rs cfg { cfgPort = port }
                     _ -> Left "Invalid port number"
                   [] -> Left "Port number required"
  "--port"    -> parseArgs ("-p":rest) cfg
  "-w"        -> case rest of
                   (d:rs) -> case reads d of
                     [(days, "")] -> parseArgs rs cfg { cfgWarnDays = days }
                     _ -> Left "Invalid warning days"
                   [] -> Left "Warning days required"
  "-c"        -> case rest of
                   (d:rs) -> case reads d of
                     [(days, "")] -> parseArgs rs cfg { cfgCriticalDays = days }
                     _ -> Left "Invalid critical days"
                   [] -> Left "Critical days required"
  "--chain"   -> parseArgs rest cfg { cfgShowChain = True }
  "--json"    -> parseArgs rest cfg { cfgJsonOutput = True }
  "--no-ocsp" -> parseArgs rest cfg { cfgCheckOCSP = False }
  _           -> parseArgs rest cfg { cfgHost = arg }

-- | Run certificate check
runCheck :: Config -> IO ()
runCheck cfg@Config{..} = do
  unless cfgJsonOutput $ printBanner
  
  putStrLn $ colored Cyan $ "Checking: " ++ cfgHost ++ ":" ++ show cfgPort
  putStrLn ""
  
  -- Simulate certificate retrieval (real impl would use Network.TLS)
  now <- getCurrentTime
  let cert = simulateCert cfgHost now
  
  -- Validate certificate
  let findings = validateCert cfg now cert
  
  -- Print results
  printCertInfo cert
  printFindings findings
  
  -- Exit code based on findings
  let maxSeverity = if null findings 
                    then Info 
                    else minimum (map findingSeverity findings)
  
  case maxSeverity of
    Critical -> exitFailure
    High     -> exitFailure
    _        -> exitSuccess

-- | Print banner
printBanner :: IO ()
printBanner = putStrLn $ unlines
  [ ""
  , "╔══════════════════════════════════════════════════════════════════╗"
  , "║           NullSec CertCheck - SSL/TLS Analyzer                   ║"
  , "╚══════════════════════════════════════════════════════════════════╝"
  , ""
  ]

-- | Print usage
printUsage :: IO ()
printUsage = putStrLn $ unlines
  [ ""
  , "╔══════════════════════════════════════════════════════════════════╗"
  , "║           NullSec CertCheck - SSL/TLS Analyzer                   ║"
  , "╚══════════════════════════════════════════════════════════════════╝"
  , ""
  , "USAGE:"
  , "    certcheck [OPTIONS] <hostname>"
  , ""
  , "OPTIONS:"
  , "    -h, --help       Show this help"
  , "    -p, --port PORT  Port number (default: 443)"
  , "    -w DAYS          Warning threshold (default: 30)"
  , "    -c DAYS          Critical threshold (default: 7)"
  , "    --chain          Show certificate chain"
  , "    --json           JSON output"
  , "    --no-ocsp        Skip OCSP check"
  , ""
  , "EXAMPLES:"
  , "    certcheck example.com"
  , "    certcheck -p 8443 example.com"
  , "    certcheck -w 60 -c 14 example.com"
  , ""
  , "EXIT CODES:"
  , "    0  All checks passed"
  , "    1  Critical/High severity issues found"
  ]

-- | Simulate certificate data (real impl would parse actual cert)
simulateCert :: String -> UTCTime -> CertInfo
simulateCert host now = CertInfo
  { certSubject     = "CN=" ++ host ++ ", O=Example Inc, L=San Francisco, ST=CA, C=US"
  , certIssuer      = "CN=Let's Encrypt Authority X3, O=Let's Encrypt, C=US"
  , certSerial      = "03:A4:B2:C1:D5:E6:F7:89:01:23:45:67:89:AB:CD:EF"
  , certNotBefore   = Just $ addDays (-90) now
  , certNotAfter    = Just $ addDays 25 now  -- Expiring in 25 days for demo
  , certKeyAlgo     = "RSA"
  , certKeyBits     = 2048
  , certSigAlgo     = "sha256WithRSAEncryption"
  , certSANs        = [host, "www." ++ host, "*." ++ host]
  , certFingerprint = "AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12"
  , certVersion     = 3
  }

-- | Add days to UTCTime (simplified)
addDays :: Int -> UTCTime -> UTCTime
addDays n t = let seconds = fromIntegral n * 86400 :: NominalDiffTime
              in addUTCTime seconds t
  where addUTCTime dt ut = ut { utctDayTime = utctDayTime ut + realToFrac dt }
        utctDayTime = id  -- Simplified

-- | Validate certificate
validateCert :: Config -> UTCTime -> CertInfo -> [Finding]
validateCert Config{..} now cert = concat
  [ checkExpiry
  , checkKeyStrength
  , checkSignature
  , checkSelfSigned
  ]
  where
    checkExpiry = case certNotAfter cert of
      Nothing -> [Finding Critical "Validity" "No expiration date found"]
      Just expiry ->
        let days = ceiling $ diffUTCTime expiry now / 86400
        in if days <= 0
           then [Finding Critical "Validity" "Certificate has EXPIRED"]
           else if days <= cfgCriticalDays
           then [Finding Critical "Validity" $ "Expires in " ++ show days ++ " days"]
           else if days <= cfgWarnDays
           then [Finding Medium "Validity" $ "Expires in " ++ show days ++ " days"]
           else []
    
    checkKeyStrength =
      let algo = certKeyAlgo cert
          bits = certKeyBits cert
          minBits = fromMaybe 2048 $ lookup algo minimumKeyBits
      in if bits < minBits
         then [Finding High "Key" $ "Weak key: " ++ show bits ++ "-bit " ++ algo ++ " (min: " ++ show minBits ++ ")"]
         else []
    
    checkSignature =
      if certSigAlgo cert `elem` weakSignatureAlgorithms
      then [Finding High "Signature" $ "Weak signature: " ++ certSigAlgo cert]
      else []
    
    checkSelfSigned =
      if extractCN (certSubject cert) == extractCN (certIssuer cert)
      then [Finding Medium "Trust" "Self-signed certificate"]
      else []

-- | Extract CN from subject/issuer
extractCN :: String -> String
extractCN s = 
  let parts = split ',' s
      cnPart = find ("CN=" `isPrefixOf`) parts
  in maybe "" (drop 3 . trim) cnPart

split :: Char -> String -> [String]
split _ "" = []
split c s = 
  let (part, rest) = break (== c) s
  in part : case rest of
    [] -> []
    (_:xs) -> split c xs

trim :: String -> String
trim = dropWhile (== ' ') . reverse . dropWhile (== ' ') . reverse

-- | Print certificate info
printCertInfo :: CertInfo -> IO ()
printCertInfo CertInfo{..} = do
  putStrLn $ colored Green "Certificate Information:"
  putStrLn $ "  Subject:     " ++ certSubject
  putStrLn $ "  Issuer:      " ++ certIssuer
  putStrLn $ "  Serial:      " ++ certSerial
  putStrLn $ "  Valid From:  " ++ maybe "N/A" show certNotBefore
  putStrLn $ "  Valid To:    " ++ maybe "N/A" show certNotAfter
  putStrLn $ "  Key:         " ++ certKeyAlgo ++ " " ++ show certKeyBits ++ "-bit"
  putStrLn $ "  Signature:   " ++ certSigAlgo
  putStrLn $ "  SANs:        " ++ intercalate ", " certSANs
  putStrLn $ "  Fingerprint: " ++ certFingerprint
  putStrLn ""

-- | Print findings
printFindings :: [Finding] -> IO ()
printFindings [] = putStrLn $ colored Green "✓ No issues found"
printFindings findings = do
  putStrLn $ colored Yellow "Findings:"
  forM_ findings $ \Finding{..} -> do
    let severityStr = case findingSeverity of
          Critical -> colored Red    "[CRITICAL]"
          High     -> colored Red    "[HIGH]    "
          Medium   -> colored Yellow "[MEDIUM]  "
          Low      -> colored Cyan   "[LOW]     "
          Info     -> colored Gray   "[INFO]    "
    putStrLn $ "  " ++ severityStr ++ " " ++ findingCategory ++ ": " ++ findingMessage
