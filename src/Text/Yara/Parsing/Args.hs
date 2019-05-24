{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleContexts #-}
-- |
-- Module      :  Text.Yara.Parsing.Args
-- Copyright   :  David Heras 2018-2019
-- License     :  GPL-3
--
-- Maintainer  :  dheras@protonmail.com
-- Stability   :  experimental
-- Portability :  unknown
--
-- Parse and handle command line arguments
--
module Text.Yara.Parsing.Args (
    parseArgs  --  :: [ByteString] -> Result Env
  , showHelp   --  :: ByteString
  ) where

import Prelude hiding ((++), takeWhile, reverse, all, unlines, unwords,
                       head, take, drop, concat, splitAt)
import Data.ByteString hiding (takeWhile, elem, length)
import qualified Data.ByteString as B (length)
import Data.ByteString.Char8 (unlines, unwords)
import qualified Data.Map.Strict as Map
import Data.Sequence ((<|))
import Control.Monad.State.Strict
    -----
import Text.Yara.Parsing.Combinators
import Text.Yara.Parsing.Parser
import Text.Yara.Parsing.Rules
import Text.Yara.Parsing.Types
import Text.Yara.Shared

-- Doesn't accept non-visible characters for Windows or Posix
-- Windows excludes:  <  >  :  "  /  \  |  ?  *
badFilepathByte :: Byte -> Bool
badFilepathByte w = not $ if onWindows
  then w - 35 <= 6 || w - 43 <= 3 || w - 48 <= 9 || w == 59
                          || w == 61 || w - 64 <= 27 || w == 93
                          || w - 95 <= 28 || w == 123 || w == 126
  else w - 33 <= 58 || w - 93 <= 33
{-# INLINE badFilepathByte #-}
{-
filepathQuoted :: YaraParser ByteString
filepathQuoted = quotedStringWith badFilepathByte
      | w == 42 && not b   = Just True  -- if escaped wildcard, keep going
{-# INLINE filepathQuoted #-}
-}
filepathUnquoted :: YaraParser ByteString
filepathUnquoted = do
  fp <- scan False $ \b w -> if
      | badFilepathByte w  -> Nothing    -- if not fp char, done
      | w == 32 && not b   -> Nothing    -- if unescaped space, done
      | w == 92 && not b   -> Just True  -- if escaped space, keep going
      | otherwise          -> Just False -- else keep going
  -- 'scan' will exit on any non-filepath character.
  -- So, check if 'scan' exited due to that or unescaped space.
  n  <- peekByte
  when_ (isSpace n)
        ("Encounter bad filepath character '" +> n ++ "'")
        (return fp)
  <?> "filepath"
{-# INLINE filepathUnquoted #-}
{-
-- | `filepath` parses filepath passed into the command line, either style
--  quoted style:    $ prog --flag="some/random filepath"
--  unquoted style:  $ prog --flag=some/random\ filepath
filepath :: YaraParser ByteString
filepath = filepathQuoted <|> filepathUnquoted
{-# INLINE filepath #-}
-}



-- Return the next command line argument.
getArg :: YaraParser ByteString
getArg = do
  spaces
  arg <- scan False p
  w <- peekByte
  when_ (w < 32) "Encountered bad command line character!" $ pure arg
  <?> "getArg"
  where p b w | w < 32            = Nothing
              | w == 32 && not b  = Nothing
              | w == 92 && not b  = Just True
              | otherwise         = Just False
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
        go acc (s,d) arg = acc ++ untabs ["  -" +> s, df, g ++ "\n"]
          where (df,g) = case arg of
                  (Arg0 h _)     -> ("--" ++ d                        , h)
                  (Arg1 h l _)   -> ("--" ++ d ++ "=" ++l             , h)
                  (Arg2 h l m _) -> ("--" ++ d ++ "=" ++ l ++ "=" ++ m, h)
{-# INLINE showArgs #-}

data ArgN = Arg0 ByteString             (YaraParser ())
          | Arg1 ByteString Label       (ByteString -> YaraParser ())
          | Arg2 ByteString Label Label (ByteString -> ByteString -> YaraParser ())

-- Helps reability by avoiding (visible) tuple nesting
(=?) :: a -> b -> (a,b)
(=?) a b = (a,b)
infixl 1 =?
{-# INLINE (=?) #-}

args :: Map.Map (Byte, ByteString) ArgN
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
  , 114 =? "recursive"            =? Arg0 "recursively search directories" (modify $ \e -> e { recursiveSearch = True })
  , 107 =? "stack-size"           =? Arg1 "set maximum stack size (default=16384)" "SLOTS" handleStackSize
  , 116 =? "tag"                  =? Arg1 "print only rules tagged as TAG" "TAG" handleTag
  , 112 =? "threads"              =? Arg1 "use the specified NUMBER of threads to scan a directory" "NUMBER" handleThreads
  , 97  =? "timeout"              =? Arg1 "abort scanning after the given number of SECONDS" "SECONDS" handleTimeout
  , 118 =? "version"              =? Arg0 "show version information" (modify $ \e -> e { printVersion = True } )
  ]
  where
    -- The following parses a bytestring of decimal characters. Its a bit of a hack
    -- without re-writing the decimal parser. Itll do for now.
    parseInt u = parse_ (decimal <* spaces <* endOfInput) (u ++ " ")
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
      let new = u <| onlyIdens e in e { onlyIdens = new }
    handleTag u = when_ (checkIfIdentifier u) badIdenChars $ modify $ \e ->
      let new = u <| onlyTags e in e { onlyTags = new }
    handleExternalVar u v = case parse_ value v of
      Done _ i ->  when_ (checkIfIdentifier u) badIdenChars $ modify $ \e ->
                       let new = Map.insert u i (externVars e) in e { externVars = new }
      _        -> fault "option \"define\" ('d') requires integer/bool/string argument"

    -- Error Messages
    badIdenChars :: ByteString
    badIdenChars = "yara: indentifier contains exlcuded chars"

unknownFlag :: ByteString -> YaraParser a
unknownFlag bs = fault $ "unknown option '" ++ bs ++ "'"
{-# INLINE unknownFlag #-}

-- | Parse a single flag.
parseSingleFlag :: YaraParser ()
parseSingleFlag = do
  -- Since command line arguments are stored in the parser
  -- buffer, we pull the next character
  s <- anyByte
  let msg = "option `-" +> s ++ "` requires an argument"
  case querySingleFlag s of
    Nothing             -> unknownFlag $ singleton s
    Just (Arg0 _ par)   -> par
    Just (Arg1 _ _ par) -> do
      -- Any char flag that takes arguments must be followed
      -- by a space character seperating the arguments
      b <- not . isSpace <$> peekByte
      -- If so, throw error, otherwise run parser.
      when_ b msg $ par =<< getArg
    Just (Arg2 _ _ _ par) -> do
      -- Identical to Arg1 handling
      b <- not . isSpace <$> peekByte
      when_ b msg $ join $ liftA2 par getArg getArg
  where
    querySingleFlag :: Byte -> Maybe ArgN
    querySingleFlag w = Map.lookup w $ Map.mapKeysMonotonic fst args

-- | Parse a double flag
-- The line argument is passed in with the "--" already stripped
parseDoubleFlag :: ByteString -> YaraParser ()
parseDoubleFlag bs =
  let (_,bs') = splitAt 2 bs
      (h:hs) = split 61 bs'
      l = length hs
      msg n = unwords ["yara: wrong number of arguments: option", h, "requires", n]
  in case queryDoubleFlag h of
    Nothing               -> unknownFlag h
    Just (Arg0 _ par)     -> when_ (l == 0) (msg "0") par
    Just (Arg1 _ _ par)   -> when_ (l == 1) (msg "1") $ par (hs !! 0)
    Just (Arg2 _ _ _ par) -> when_ (l == 2) (msg "2") $ par (hs !! 0) (hs !! 1)
  where
    queryDoubleFlag :: ByteString -> Maybe ArgN
    queryDoubleFlag w = Map.lookup w $ Map.mapKeysMonotonic snd args

-- | parseArgs_ actually handles the command line arguments
parseArgs_ :: YaraParser Env
parseArgs_ = do
  w <- getArg
  if | argIsLong w   -> parseDoubleFlag w *> parseArgs_
     | argIsShort w  -> parseSingleFlag *> parseArgs_
     | otherwise     -> undefined
     where argIsLong w = isPrefixOf "--" w && B.length w > 2
           argIsShort w = isPrefixOf "-" w && B.length w > 1

-- | parseArgs initiates the buffer
parseArgs :: [ByteString] -> Result Env
parseArgs bs = parse_ parseArgs_ $ unwords bs





{-
data OPT = 
    OPT_STRING_MULTI Byte ByteString [ByteString] ([ByteString] -> Parser ())
  | OPT_STRING       Byte ByteString  ByteString  ( ByteString  -> Parser ())
  | OPT_INTEGER      Byte ByteString  ByteString  ( ByteString  -> Parser ())
  | OPT_BOOL         Byte ByteString                              (Parser ())
-}



{-

-- Parse an unquoted-style filepath passed into the command line
-- No size limit is imposed.
-- Loaded with errors.
filepath :: YaraParser ByteString
filepath = go ""
  where
    go acc = do
      bs <- takeWhile filepathByte
      let acc' = acc ++ bs
      end <- atEnd
      if end
        then return acc'
        else peekWord8 >>= \case
--#if defined(mingw32_HOST_OS) || defined(__MINGW32__)
          58 -> if null acc
            then do
              c <- anyWord8
              go $ acc' +> c
            else badFPByte 58
--#endif
          32 -> return acc'
          92 -> do
            r <- anyWord8
            s <- anyWord8
            if s == 20
              then go $ acc' +> s -- No need to keep escape any longer
              else go $ acc' +> r +> s
          _  -> badFPByte =<< anyWord8
    badFPByte w = fault $ "Unrecognized filepath character '" +> w "'"
{-# INLINE filepath #-}

-}





--    span' :: ByteString -> (ByteString, ByteString)
--    span' bs = mapSnd (drop 1) $ span (/= bs)
--               where mapSnd f (x,y) = (x, f y)

--  splitAtEqs :: YaraParser [ByteString]
--  splitAtEqs bs = parse (sepBy1 (word8 61) (takeWhile (/=61))) defaultEnv bs



-- need a filepath parser.

{-
-- Few error messages needed below

-- Alas, Haskell doesn't support disjunctive patterns.
handleArgs :: [ByteString] -> Env -> Conf -> Either ByteString Env
handleArgs [] env conf
  | null (_rules env)           = noRules
  | isNothing $ env ^. _target  = noTarget
  | otherwise                   = Right env
handleArgs [a] env conf
  | null a                      = Left "Empty string got through?"
  | null $ env ^. _rules        = wrongNumArgs
  | otherwise                   = Right $ _target .~ a env
handleArgs (a:as) env conf
  | take 1 a == "-"  -> unrecognizedFlag (drop 1 a)
  | otherwise        -> undefined
  --let u = a <| rules env in handleArgs (env { onlyTags = u }) as
  where


    uncons1 = List.uncons
    uncons2 cs = go =<< List.uncons cs
      where go (c,cs) = if null cs then Nothing else Just (c, head cs, tail cs)

    addRule :: Env -> ByteString -> [ByteString] -> Either ByteString Env
    addRule e b bs = case span (/=0x3A) b of
      ("", _) -> Left $ "Missing namespace value: " ++ b
      (rl,"") -> modAs bs (Map.insert rl rl) _rules
      (ns,rl) -> undefined -- something was found, deal with cases
-}
