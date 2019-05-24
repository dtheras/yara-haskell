{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE BlockArguments #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE GADTs #-}
-- |
-- Module      :  Text.Yara.Parsing.Rules
-- Copyright   :  David Heras 2018-2019
-- License     :  GPL-3
--
-- Maintainer  :  dheras@protonmail.com
-- Stability   :  experimental
-- Portability :  unknown
--
-- To annotate.
--
{-Zip -- haskell lib
based on LibZip
This is a binding to C library libzip.-}
module Text.Yara.Parsing.Rules where

import Prelude hiding ((++), takeWhile, unlines, quot, sequence, null,
                       unwords, putStrLn, replicate, replicate, head,
                       FilePath, span, all, take, drop, concat, length)
import Data.ByteString hiding (foldl1, foldl, foldr1, putStrLn,
                               zip, map, replicate, takeWhile, empty,
                               elem, count, tail, unpack, pack)
import Control.Monad.Reader
import Data.Default
import Text.Regex.Posix.Wrap
import Text.Regex.Posix ()
    -----
import qualified Data.Map.Strict as Map
import qualified Data.Sequence   as Seq
import qualified Data.Set        as Set
    -----
import Text.Yara.Parsing.Combinators
import Text.Yara.Parsing.Parser
import Text.Yara.Parsing.Types
import Text.Yara.Parsing.Hash
import Text.Yara.Shared


badModule i = fault $ "'" ++ i ++ "' is not an imported module"

--data ConditionOperator a =
  --MkHash :: Hash -> ConditionOperator Hash
 -- MkFile ::
bool :: YaraParser Bool
bool = (string "false" $> False)
   <|> (string "true" $> True)
   <?> "bool"
{-# INLINE bool #-}

value :: YaraParser Value
value = (ValueB <$> bool) <|> {-ValueS <$> quotedString,-} (ValueI <$> decimal)
{-# INLINE value #-}

-- KEYWORD SETS

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

isKeyword :: ByteString -> Bool
isKeyword = flip Set.member yaraKeywords
-- IDENTIFIERS

isUnderscore, isLeadingByte, isIdByte :: Byte -> Bool
isUnderscore  = (== 95)
isLeadingByte = isAlpha <> isUnderscore
isIdByte      = isAlphaNum <> isUnderscore

-- | Parses an identifier.
--
-- Identifiers must follow the same lexical conventions of C identifiers:
-- > They can contain any alphanumeric character and the underscore character
-- > But the first character can not be a digit.
-- > Rule identifiers are case sensitive.
-- > Identifiers cannot exceed 128 characters.
--
-- The yara keywords are reserved and cannot be used as an identifier; see
-- @yaraKeywords@ for a list.
--
-- We additionally imposed that identifiers cannot be a single number or
-- just an underscore for the time being, due to parsing issues.
identifier :: YaraParser ByteString
identifier = do
  -- must start with underscore or letter
  w <- satisfy isLeadingByte
  r <- scan 0 p
  let i = w <+ r
  if | isKeyword i -> fault $ "Identifier cannot be a keyword: '" ++ i ++ "'"
     -- Simply an underscore or digit is not an acceptable identifier
     | null r && not (isAlpha w) -> fault $ "Unacceptable identifier: " +> w
     -- Otherwise, we have an acceptable identifier
     | otherwise   -> pure i
  <?> "identifier"
  where -- Read only upto 128 bytes (127 plus leading byte)
    p :: Int -> Byte -> Maybe Int
    p n w | n < 0 || 127 <= n  = Nothing
          | isIdByte w         = Just $ n + 1
          | otherwise          = Nothing
{-# INLINE identifier #-}

identifier_ :: YaraParser Identifier
identifier_ = do
  i <- identifier
  b <- isDot <$> peekByte
  -- If the next byte is a dot, may be trying to import a module.
  -- Parse another identifier and check if it was imported
  forkA b (pure i) $ do
    -- Ensure that possible module is an imported one.
    m <- reader moduleImports
    if Set.member i m
       then dot *> identifier
       else badModule i
  <?> "identifier_"
{-# INLINE identifier_ #-}

checkIfIdentifier :: ByteString -> Bool
checkIfIdentifier bs = case uncons bs of
  Nothing      -> False
  Just (x,"")  -> isAlpha x
  Just (h,r)   -> (isLeadingByte h && all isIdByte r)
                        && Set.notMember bs yaraKeywords
{-# INLINE checkIfIdentifier #-}

ruleType :: YaraParser RuleType
ruleType = do
  b <- peekByte
  case b of
    114 -> rule $> Normal
    103 -> (liftA2 (<>) global $ option Normal private) <* rule
    112 -> (liftA2 (<>) private $ option Normal global) <* rule
    _   -> fault $ "Encountered unexpected byte: '" +> b ++ "'"
  <?> "ruleType"
  where global = string "global" <* space1 $> Global <?> "global"
        private = string "private" <* space1 $> Private <?> "private"
        rule = string "rule" <?> "rule"
{-# INLINE ruleType #-}



-- |
--
--               | Type        -> RuleType
--  RuleBlock -- | Name        -> Identifier
--               | :
--               | Tags        -> [Identifiers]
--               | {
--               | Metadata    -> [String Literal]
--               | Strings     -> [Hex-byte String | String Literal | Regex]
--               | Conditions  -> Many types
--               | }
--
--
ruleBlock :: YaraParser ByteString
ruleBlock = do
  spaces
  r <- ruleType
  n <- skipTo identifier
  t <- option mempty $ do
      skipTo colon
      skipTo (sepBy1Set identifier space1)
  skipTo openCurl
  m <- perhaps metadata
  --s <- perhaps strings
  --c <- perhaps conditions

         -- return t) <|> pure [""] -- tags-}
  -- need to merge if multiple of same tags
  def
  --return $ RuleBlock r n t _ _ _ --

-- ruleBlock = RuleBlock <$> ruleType
                      -- <*> ruleName
                     --  <*> ruleTags
                     --  <*  openCurl
                      -- <*> ruleMetadata
                      -- <*> ruleStrings
                     --  <*> ruleConditions
                     --  <* closeCurl

label :: YaraParser ByteString
label = liftA2 seq (byte 36) identifier

-- type Metadata = Map.Map Identifier Value
metadata :: YaraParser Metadata
metadata = do
  skipTo $ string "meta:"
  space1
  sepByMap (pair identifier (Just $ space1 *> equal *> space1) value)  space1

sss :: YaraParser Metadata
sss = do
  skipTo $ string "strings:"
  space1
  sepByMap (pair label (Just $ space1 *> equal *> space1) value)  space1



data Comment = MultiLineComment ByteString
             | SingleLineComment ByteString

-- | @comment@ parses either a single-line or multi-line
--
-- YARA rules can be comment just as if a C source file
-- >
-- > /*
-- >    This is a multi-line comment ...
-- > */
-- >
-- > // ... and this is single-line comment
--
-- Returns the just the comment contents
comment :: YaraParser Comment
comment = do -- Double Line
  string "/*"
  bs <- scan False $ \s b -> if
      | b == 42       -> Just True  -- If '*', set 's' to 'True'
      | b == 47 && s  -> Nothing    -- If '/' following a '*', end scan
      | otherwise     -> Just False -- Else, set 's' to False
  {- With how 'scan' is written, we will have the need to strip a '*'
     off the end. Thankfully ByteStrings allow O(1) 'unsnoc'.         -}
  pure $ MultiLineComment $ maybe "" fst $ unsnoc bs
  <|>     do -- Singe Line
  string "--"
  -- scan until a new line byte is found ('\n' or '\r')
  bs <- scan () $ \_ b -> if b == 10 || b == 13 then Nothing else Just ()
  pure $ SingleLineComment bs
{-# INLINE comment #-}

-- | Parse a regex string -- Text.Regex.TDFA
regex :: YaraParser (ByteString -> ByteString)
regex = (=~) <$> (byte 47 *> scan False p) <?> "error building regex map"
  where p s w | s && w /= 47  = Nothing
              | w == 47       = Just True
              | otherwise     = Just False

{-
block :: (a -> f a -> f a)
      -> ByteString
      -> YaraParser a
      -> YaraParser (f a)
block s p = do
  string s <* colon
  skipTo $ sepBy p space1


-}


{-
strModifiers :: YaraParser
strModifiers = do
  skipTo $ perhaps "xor"
  sepBy1Set space1 $ foldMap string ["ascii", "fullword", "nocase", "wide"]
-}

{-
-- PARSE RULE BLOCK
-- YARA rules consist of:
--    - Possible keyword of "global" and/or "private"
--    - "rule" keyword
--    - Possible semicolon, followed by space seperated tags
--    - open curl bracket
--    - metadata block
--    - strings block
--    - conditions block (depends on the strings block)
parseRuleBlock :: YaraParser ()
parseRuleBlock = do
  oCurl
  meta <- parseMetadata keep_meta
  ss <- block "strings" patterns
  -- >>= (block "condition:") . conditions
  cCurl
  return $ Seq.singleton () -- Data.Map.empty <?> "Parse Rule Block"
  where


-- HEX

hexPr :: YaraParser HexTokens
hexPr = Seq.singleton . uncurry Pair <$> (hexDigit `pair` hexDigit)
     where hexDigit = satisfy $ \w -> w == 63 || w - 48 <=  9
                              || w - 97 <= 25 || w - 65 <= 25

hexJump :: YaraParser HexTokens
hexJump = between sqBra sqKet $ do
  l <- optional decimal
  flank space dash
  u <- optional decimal
  return $ maybe Seq.empty Seq.singleton $ if
    | isNothing l && isNothing u  -> IJmp 0
    | isNothing l                 -> RJmp 0 <$> u
    | isNothing u                 -> IJmp <$> l
    | otherwise                   -> uncurry RJmp <$> untuple (l,u)

hex :: YaraParser HexStr
hex = between oCurl cCurl $ sepBy1 (hexGrp <|> hexStd) space1
  where
    hexAux = Seq.fromList <$> sepBy1 (hexPr <|> hexJump) space1
    hexStd = Std <$> hexAux
    hexGrp = Grp <$> between oPar cPar (sepBy1 hexAux $ flank space vBar)

-- PARSE YARA STRING

patterns :: YaraParser YaraStr
patterns = do
  l <- label
  skipTo eq
  let regex'  = YReg l <$> regex
      string' = YStr l <$> string
      hex'    = YHex l <$> hex
  skipTo (regex' <|> string' <|> hex') <*> skipTo modifiers
  <?> "patterns"
  where
    -- Using a set here to automatically remove dupicates. Since modifiers as a "set"
    -- data structure will later be consumed in conditional clauses (and not used
    -- futher) they will shortly be dropped

    scan' = liftA2 Set.insert keys ((space1 *> scan') <|> pure Set.empty)
    scan = foldl (|>) empty <$> scan' -- change to a sequence


parseConditions :: YaraParser ()--[(ByteString,Pattern)]->Parser[ByteString->Bool]
parseConditions = do
  string "condition:"
  skipSpace

data Condition = FileSize { size :: Int, ordering :: Ordering }
               | Empty
               deriving Show

-- | IN BYTES!!
-- An unadorned filesize number of "10" means 10 bytes, not bits.
fileSize :: YaraParser Condition
fileSize = do
  string "filesize"
  skipSpace
  o <- (word8 0x3C $> LT) <|> (word8 0x3D $> EQ) <|> (word8 0x3E $> GT)
  skipSpace
  s <- decimal
  u <- ext
  space1
  return $ maybe (FileSize s o) (\x -> FileSize (x * s) o) u
  where
    check = foldMap string
    ext = option Nothing (Just <$> asum
             $ foldMap string
            <$> [ foldMap string ["B", "b"] $> 1
                , foldMap string ["KB", "kb", "Kb"] $> 1000
                , foldMap string ["MB", "mb", "Mb"] $> 1000000
                , foldMap string ["GB", "gb", "Gb"] $> 1000000000 ])

data RelOp = RelOpLEQ
           | RelOpLT
           | RelOpEQ
           | RelOpGT
           | RelOpGEQ

relOp :: YaraParser RelOp
relOp = asum [ lt $> RelOpLT
               , gt $> RelOpGT
               , eq *> eq $> RelOpEQ
               , gt *> eq $> RelOpGEQ
               , lt *> eq $> RelOpLEQ ]



launch :: IO (Env, ExitCode)
launch = do
  res <- parseArgs `liftM` getArgs
  case res of
   Fail b1 bs b2 -> undefined
   Partial _     -> undefined
   Done b e      -> when (printHelp e) $ hPutStrLn stderr help $> ExitSuccess {- start running the program-}


main :: IO ()
main =
  (env,ec) <- launch
  case ec of
    ExitSuccess   -> if showHelp env == True
      then undefined
      else undefined {- if show help true, do so, else if show version true do so, otherwise proceeed-}
    ExitFailure 0 -> return ()
    ExitFailure 1 -> return ()
-}
