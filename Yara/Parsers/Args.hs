{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleContexts #-}
-- |
-- Module      :  Yara.Parsing.Args
-- Copyright   :  David Heras 2018-2019
-- License     :  GPL-3
--
-- Maintainer  :  dheras@protonmail.com
-- Stability   :  experimental
-- Portability :  unknown
--
-- Parse and handle command line arguments
module Args (parseArgs , showHelp) where

import Prelude hiding ((++), takeWhile, all, unlines, unwords, head, take, drop, concat, splitAt)
import Data.ByteString hiding (takeWhile, length)
import Data.ByteString.Char8 (unlines, unwords)
import Control.Monad.State.Strict
import Data.Sequence ((<|))
import GHC.Word

import qualified Data.Map.Strict as Map
import qualified Data.Sequence as Seq

import Types
import Utils
import Buffer

{-- SHOULD BE MOVED TO RULES AND IMPORTED. FOR NOW> ---}
import qualified Data.Set as Set

isUnderscore, isLeadingByte, isIdByte :: Word8 -> Bool
isUnderscore  = (==) 0x5F
isLeadingByte = isAlpha <> isUnderscore
isIdByte      = isAlphaNum <> isUnderscore

checkIfIdentifier :: ByteString -> Bool
checkIfIdentifier bs = case uncons bs of
  Nothing      -> False
  Just (x,"")  -> isAlpha x
  Just (h,r)   -> (isLeadingByte h && all isIdByte r)
                        && Set.notMember bs yaraKeywords

yaraKeywords :: Set.Set ByteString
yaraKeywords = Set.fromDistinctAscList [
   "all"       , "and"       , "any"      , "ascii"      ,
   "at"        , "condition" , "contains" , "entrypoint" ,
   "false"     , "filesize"  , "for"      , "fullword"   ,
   "global"    , "import"    , "in"       , "include"    ,
   "int16"     , "int16be"   , "int32"    , "int32be"    ,
   "int8"      , "int8be"    , "matches"  , "meta"       ,
   "nocase"    , "not"       , "of"       , "or"         ,
   "private"   , "rule"      , "strings"  , "them"       ,
   "true"      , "uint16"    , "uint16be" , "uint32"     ,
   "uint32be"  , "uint8"     , "uint8be"  , "wide"       ]


{----------------------}



value :: YaraParser Value
value = Value_B <$> bool <|> Value_I <$> decimal <|> Value_S <$> (takeWhile $ const True)




-- | A version of 'when' that returns failure if predicate is False.
when_ :: Bool
      -> ByteString
      -- ^ If false, return failure with this bytestring
      -> YaraParser a
      -- ^ Otherwise, run parser
      -> YaraParser a
when_ b p q = if b then q else fault p
{-# INLINE when_ #-}

-- Return the next command line argument.
-- !!!!
-- NOT CORRECT
-- It needs to handle escaped spaces in filepath names as well
-- as quoted filepaths.
-- !!!!!
getArg :: YaraParser ByteString
getArg = do
      spaces
      bs <- takeTill isSpace
      space1 -- Ensures followed by a space
      return bs
{-# INLINE getArg #-}

showHelp :: ByteString
showHelp = unlines [
      "YARA-HS 0.0.1, the pattern matching swiss army knife."
    , "Usage: yara [OPTION]... [NAMESPACE:]RULES_FILE... FILE | DIR | PID"
    , ""
    , "Mandatory arguments to long options are mandatory for short options too."
    , ""
    , showArgs
    , ""
    , "Send bug reports and suggestions to: dheras@protonmail.com." ]

showArgs :: ByteString
showArgs = Map.foldlWithKey go "" args
  where untabs = intercalate "\t"
        eqs = intercalate "="
        go acc (s,d) arg = acc ++ untabs ["  -" ++ singleton s, df, g ++ "\n"]
                       where (df,g) = case arg of
                               (Arg0 h _)     -> (eqs["--" ++ d], h)
                               (Arg1 h l _)   -> (eqs["--" ++ d,l], h)
                               (Arg2 h l m _) -> (eqs["--" ++ d,l,m], h)
{-# INLINE showArgs #-}

data ArgN = Arg0 ByteString             (YaraParser ())
          | Arg1 ByteString Label       (ByteString -> YaraParser ())
          | Arg2 ByteString Label Label (ByteString -> ByteString -> YaraParser ())



-- Helps reability by avoiding (visible) tuple nesting
(=?) :: a -> b -> (a,b)
(=?) a b = (a,b)
infixl 1 =?
{-# INLINE (=?) #-}

args :: Map.Map (Word8, ByteString) ArgN
args = Map.fromList [
    65  =? "atom-quality-table"   =? Arg1 "path to a file with the atom quality table" "FILE" handleAtomTable
  , 67  =? "compiled-rules"       =? Arg0 "load compiled rules" (modify $ \e -> e { compiledRules = True })
  , 99  =? "count"                =? Arg0 "print only number of matches" (modify $ \e -> e { printNumMatches = True })
  , 100 =? "define"               =? Arg2 "define external variable" "VAR" "VALUE" handleExternalVar
  , 87  =? "fail-on-warnings"     =? Arg0 "fail on warnings" (modify $ \e -> e { failOnWarnings = True })
  , 102 =? "fast-scan"            =? Arg0 "fast matching mode" (modify $ \e -> e { fastScan = True })
  , 104 =? "help"                 =? Arg0 "show this help and exit" (modify $ \e -> e { printHelp = True })
  , 105 =? "identifier"           =? Arg1 "print only rules named IDENTIFIER" "IDENTIFIER" handleIdentifier
  , 108 =? "max-rules"            =? Arg1 "abort scanning after matching a NUMBER of rules" "NUMBER" handleMaxRules
  , 77  =? "max-strings-per-rule" =? Arg1 "set maximum number of strings per rule (default=10000)" "NUMBER" handleMaxStrings
  , 120 =? "module-data"          =? Arg2 "pass FILE's content as extra data to MODULE" "MODULE" "FILE" handleModuleData
  , 110 =? "negate"               =? Arg0 "print only not satisfied rules (negate)" (modify $ \e -> e { oppositeDay = True })
  , 119 =? "no-warnings"          =? Arg0 "disable warnings" (modify $ \e -> e { disableWarnings = True })
  , 109 =? "print-meta"           =? Arg0 "print metadata" (modify $ \e -> e { printMetadata = True })
  , 68  =? "print-module-data"    =? Arg0 "print module data" (modify $ \e -> e { printModule = True })
  , 101 =? "print-namespace"      =? Arg0 "print rules' namespace" (modify $ \e -> e { printNamespace = True })
  , 83  =? "print-stats"          =? Arg0 "print rules' statistics" (modify $ \e -> e { printStats = True })
  , 115 =? "print-strings"        =? Arg0 "print matching strings" (modify $ \e -> e { printStrings = True })
  , 76  =? "print-string-length"  =? Arg0 "print length of matched strings" (modify $ \e -> e { printStrLength = True })
  , 103 =? "print-tags"           =? Arg0 "print tags" (modify $ \e -> e { printTags = True })
  , 114 =? "recursive"            =? Arg0 "recursively search directories" (modify $ \e -> e { recursivelySearch = True })
  , 107 =? "stack-size"           =? Arg1 "set maximum stack size (default=16384)" "SLOTS" handleStackSize
  , 116 =? "tag"                  =? Arg1 "print only rules tagged as TAG" "TAG" handleTag
  , 112 =? "threads"              =? Arg1 "use the specified NUMBER of threads to scan a directory" "NUMBER" handleThreads
  , 97  =? "timeout"              =? Arg1 "abort scanning after the given number of SECONDS" "SECONDS" handleTimeout
  , 118 =? "version"              =? Arg0 "show version information" (modify $ \e -> e { printVersion = True } )
  ]
  where
    -- The following parses a bytestring of decimal characters. Its a bit of a hack
    -- without re-writing the decimal parser. Itll do for now.
    parseInt u = parse (decimal <* spaces <* endOfBuffer) defaultEnv (u ++ " ")
    handleMaxStrings u = case parseInt u of
      Done _ i  -> modify $ \e -> e { maxStrPerRule = i }
      _         -> fault "option \"max-strings-per-rule\" ('M') requires an integer argument"
    handleStackSize u = case parseInt u of
      Done _ i  -> modify $ \e -> e { stackSize = i }
      _         -> fault "option \"stack-size\" ('k') requires an integer argument"
    handleThreads u = case parseInt u of
      Done _ i  -> modify $ \e -> e { threads = i }
      _         -> fault "option \"threads\" ('p') requires an integer argument"
    handleMaxRules u = case parseInt u of
      Done _ i  -> modify $ \e -> e { maxRules = i }
      _         -> fault "option \"max-rules\" ('l') requires an integer argument"
    handleTimeout u = case parseInt u of
      Done _ i  -> modify $ \e -> e { timeout =  i }
      _         -> fault "option \"timeout\" ('a') requires an integer argument"
    handleAtomTable u = modify $ \e -> e { atomTable = Just u }
    handleModuleData u v = modify $ \e ->
      let new = Map.insert u v (moduleData e) in e { moduleData = new }
    handleIdentifier u = when_ (not $ checkIfIdentifier u) badIdenChars $ modify $ \e ->
      let new = u <| (onlyIdens e) in e { onlyIdens = new }
    handleTag u = when_ (checkIfIdentifier u) badIdenChars $ modify $ \e ->
      let new = u <| (onlyTags e) in e { onlyTags = new }
    handleExternalVar u v = case parse value defaultEnv v of
      Done _ i ->  when_ (checkIfIdentifier u) badIdenChars $ modify $ \e ->
                       let new = Map.insert u i (externVars e) in e { externVars = new }
      _        -> fault "option \"define\" ('d') requires integer/bool/string argument"

    -- Error Messages
    badIdenChars = "yara: indentifier contains exlcuded chars"

unknownFlag :: ByteString -> YaraParser a
unknownFlag bs = fault $ "unknown option '" ++ bs ++ "'"
{-# INLINE unknownFlag #-}

querySingleFlag :: Word8 -> Maybe ArgN
querySingleFlag w = Map.lookup w $ Map.mapKeysMonotonic fst args

-- | Parse a single flag.
parseSingleFlag :: YaraParser ()
parseSingleFlag = do
  -- Since command line arguments are stored in the parser
  -- buffer, we pull the next character
  s <- anyWord8
  let msg = "option `-" ++ singleton s ++ "` requires an argument"
  case querySingleFlag s of
    Nothing             -> unknownFlag $ singleton s
    Just (Arg0 _ par)   -> par
    Just (Arg1 _ _ par) -> do
      -- Any char flag that takes arguments must be followed
      -- by a space character seperating the arguments
      b <- not . isSpace <$> peekWord8
      -- If so, throw error, otherwise run parser.
      when_ b msg $ par =<< getArg
    Just (Arg2 _ _ _ par) -> do
      -- Identical to Arg1 handling
      b <- not . isSpace <$> peekWord8
      when_ b msg $ join $ liftA2 par getArg getArg

queryDoubleFlag :: ByteString -> Maybe ArgN
queryDoubleFlag w = Map.lookup w $ Map.mapKeysMonotonic snd args

-- | Parse a double flag
-- The line argument is passed in with the "--" already stripped
parseDoubleFlag :: ByteString -> YaraParser ()
parseDoubleFlag bs =
  let (h:hs) = split 61 bs
      l = length hs
      msg n = unwords ["yara: wrong number of arguments: option", h, "requires", n]
  in case queryDoubleFlag h of
    Nothing               -> unknownFlag h
    Just (Arg0 _ par)     -> when_ (l == 0) (msg "0") par
    Just (Arg1 _ _ par)   -> when_ (l == 1) (msg "1") $ par (hs !! 0)
    Just (Arg2 _ _ _ par) -> when_ (l == 2) (msg "2") $ par (hs !! 0) (hs !! 1)

-- | parseArgs_ actually handles the command line arguments
parseArgs_ :: YaraParser Env
parseArgs_ = do
  --- needs to handle
  w <- getArg
  let (dh,dt) = splitAt 2 w -- peel off potential "--"
      (sh,st) = splitAt 1 w
  if | dh == "--" && dt /= ""    -> parseDoubleFlag dt *> parseArgs_
     | sh == "-"  && st /= ""    -> parseSingleFlag *> parseArgs_
     | otherwise                 -> undefined

-- | parseArgs initiates the buffer
parseArgs :: [ByteString] -> Result Env
parseArgs bs = parse parseArgs_ defaultEnv $ unwords bs





--    span' :: ByteString -> (ByteString, ByteString)
--    span' bs = mapSnd (drop 1) $ span (/= bs)
--               where mapSnd f (x,y) = (x, f y)

--  splitAtEqs :: YaraParser [ByteString]
--  splitAtEqs bs = parse (sepBy1 (word8 61) (takeWhile (/=61))) defaultEnv bs



-- need a filepath parser.
