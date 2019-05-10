{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE BlockArguments #-}
{-Zip -- haskell lib

based on LibZip
This is a binding to C library libzip.-}
module Rules where

import Prelude hiding ((++), takeWhile, unlines, quot, sequence, null,
                       unwords, putStrLn, replicate, replicate, head,
                       FilePath, span, all, take, drop, concat, length)
import Data.ByteString hiding (foldl1, foldl, foldr1, putStrLn,
                               zip, map, replicate, takeWhile, empty,
                               elem, count, tail, unpack)
--import Data.ByteString.Char8 (intercalate, unpack, unlines, unwords)
--import Control.Applicative hiding (liftA2)
import Control.Monad
--import Data.Maybe
import GHC.Word
--import System.Exit
--import System.Posix.Env.ByteString
import Text.Regex.Posix.Wrap
import Text.Regex.Posix -- Needed only for typeclass witnesses


import qualified Data.Map       as Map
import qualified Data.Sequence  as Seq
import qualified Data.Set       as Set

import Buffer
import Combinators
import Parser
import Types
import Utilities


{- These are here since they are in transition and constantly changing. Saves from switching back and forth between documents.  -}
type RuleBlock = Map.Map Identifier [ByteString -> Bool]

data ConMap where
  ConBool :: (ByteString -> Bool) -> ConMap
  ConList :: ([ByteString] -> Bool) -> ConMap
  ConOr   :: (ConMap -> ConMap -> Bool) -> ConMap

type HexStr = Seq.Seq HexSubStr

data HexSubStr where
  Std ::         HexTokens -> HexSubStr
  Grp :: Seq.Seq HexTokens -> HexSubStr
  deriving Show

type HexTokens = Seq.Seq HexToken

data HexToken where
  Pair :: Word8 -> Word8 -> HexToken
  RJmp :: Word  -> Word  -> HexToken
  IJmp ::          Word  -> HexToken

instance Show HexToken where
  show (Pair x y) = show x <> show y
  show (RJmp x y) = "[" <> show x <> "-" <> show y <> "]"
  show (IJmp x)   = "[" <> show x <> "-]"

data YaraStr
  = YStr Label ByteString                 (Seq.Seq ByteString)
  | YReg Label (ByteString -> ByteString) (Seq.Seq ByteString)
  | YHex Label HexStr                     (Seq.Seq ByteString)

instance Show YaraStr where
  show _ = "YaraStr :: Str"


bool :: YaraParser Bool
bool = (string "false" $> False) <|> (string "true" $> True) <?> "bool"
{-# INLINE bool #-}


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

-- IDENTIFIERS

isUnderscore, isLeadingByte, isIdByte :: Word8 -> Bool
isUnderscore  = (== 95)
isLeadingByte = isAlpha <> isUnderscore
isIdByte      = isAlphaNum <> isUnderscore

-- | Parses an identifier.
-- Meets specification of reading only up to 128 bytes
identifier :: YaraParser Identifier
identifier = do
  w <- satisfy isLeadingByte
  rest <- scan 0 pred
  -- Simply an underscore or digit is not an acceptable identifier
  guard $ null rest && (isUnderscore w || isDigit w)
  let iden = w <+ rest
  guard $ Set.notMember iden yaraKeywords
  return iden
  <?> "identifier"
  where
    -- Read only upto 127 identifier bytes
    -- (127 since already parsed leading byte)
    pred :: Int -> Word8 -> Maybe Int
    pred n w
          | n < 0 || 127 <= n  = Nothing
          | isIdByte w         = Just $ n + 1
          | otherwise          = Nothing


checkIfIdentifier :: ByteString -> Bool
checkIfIdentifier bs = case uncons bs of
  Nothing      -> False
  Just (x,"")  -> isAlpha x
  Just (h,r)   -> (isLeadingByte h && all isIdByte r)
                        && Set.notMember bs yaraKeywords

ruleType :: YaraParser RuleType
ruleType = peekWord8 >>= \case
  114 -> rule $> Normal
  103 -> (global <^> option Normal private) <* rule
  112 -> (private <^> option Normal global) <* rule
  _   -> fault =<< (\w ->
           "Encountered unexpected byte at '" ++ w ++ "'") <$> getPosByteStringP1
  <?> "ruleType"
  where global = string "global" <* space1 $> Global <?> "global"
        private = string "private" <* space1 $> Private <?> "private"
        rule = string "rule" <?> "rule"


tags :: YaraParser [Identifier]
tags =  sepBy identifier space1
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
  env <- get
  let keep_meta = printMetadata env
  ty <- ruleType
  id <- skipTo1 identifier
  tg <- option [""] (colon *> tags)
  oCurl
  meta <- parseMetadata keep_meta
  ss <- block "strings" patterns
  -- >>= (block "condition:") . conditions
  cCurl
  return $ Seq.singleton () -- Data.Map.empty <?> "Parse Rule Block"
  where
    block :: ByteString -> YaraParser a -> YaraParser (Seq.Seq a)
    block s p = do
      string s <* colon
      skipTo $ sepBy p space1



meta :: YaraParser ()
meta = void $ do
  string "meta:"
  skipTo $ sepBy metaDatas space1
  where
    metaDatas = do
      identifier
      skipTo eq
      skipTo $ asum [void bool, void quotedString, void decimal]



------Text.Regex.TDFA
regex :: YaraParser (ByteString -> ByteString)
regex = (=~~) regex' <?> "error building regex map"
  where
    regex' = fSlash *> acc
    acc = do
      c <- takeTill (== 0x2F)
      option c $ fSlash *> ((c ++ "//" ++) <$> acc)
      <?> "error parsing the regex string avoinding fSlash delims"

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

label :: YaraParser ByteString
label = str "$" *> identifier

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
    keys = foldMap string ["ascii", "fullword", "nocase", "wide", "xor"]
    scan' = liftA2 Set.insert keys ((space1 *> scan') <|> pure Set.empty)
    scan = foldl (|>) empty <$> scan' -- change to a sequence
    modifiers = scan <|> pure empty

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






---- write as a takeTill
{-

-- | A more general form of @notFollowedBy@.  This one allows any
-- type of parser to be specified, and succeeds only if that parser fails.
-- It does not consume any input.
notFollowedBy' :: (Show b, Stream s m a) => ParserT s st m b -> ParserT s st m ()
notFollowedBy' p  = try $ join $  do  a <- try p
                                      return (unexpected (show a))
                                  <|>
                                  return (return ())
-- (This version due to Andrew Pimlott on the Haskell mailing list.)

-}



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
