{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE BlockArguments #-}

{-# LANGUAGE BangPatterns #-}
{-Zip -- haskell lib

based on LibZip
This is a binding to C library libzip.-}
module Rules where

import Prelude hiding ((++), takeWhile, unlines, quot, sequence,
                       unwords, putStrLn, replicate, replicate, head,
                       FilePath, span, all, take, drop, concat)
import Data.ByteString hiding (cons,uncons,foldl1, foldl, foldr1, putStrLn,
                               zip, map, replicate, takeWhile, empty, null,
                               elem, count, tail, length, unpack)
import Data.ByteString.Char8 (intercalate, unpack, unlines, unwords)
import Control.Applicative
import Control.Monad
import Data.Functor
import Data.Maybe
import GHC.Word
import System.Exit
import System.Posix.Env.ByteString
import Text.Regex.Posix.Wrap
import Text.Regex.Posix -- Needed only for typeclass witnesses
import Control.Lens.TH
import Control.Lens

import qualified Data.List      as List
import qualified Data.Map       as Map
import qualified Data.Sequence  as Seq
import qualified Data.Set       as Set

import Args
import Buffer
import Types
import Utils

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
isUnderscore  = (==) 0x5F
isLeadingByte = isAlpha <> isUnderscore
isIdByte      = isAlphaNum <> isUnderscore

{- needs to be altered ONLY read up to 128 and no more. Otherwise
any extra bytes must be loaded in to memory first. Should be doable
with the 'scan' function that keeps track of 'state' as being
number of bytes read to point. -}
identifier :: YaraParser Identifier
identifier = do
  ls <- liftM2 cons leadByte idBytes
  guard (Set.notMember ls yaraKeywords)
  guard (length ls <= 128)
  return ls
  <?> "identifier"
  where
    underscore = (==) 0x5F
    leadByte = satisfy isLeadingByte
    idBytes = takeWhile isIdByte

checkIfIdentifier :: ByteString -> Bool
checkIfIdentifier bs = case uncons bs of
  Nothing      -> False
  Just (x,"")  -> isAlpha x
  Just (h,r)   -> (isLeadingByte h && all isIdByte r)
                        && Set.notMember bs yaraKeywords

ruleType :: YaraParser RuleType
ruleType = do
  c <- peekWord8
  case c of
    103 -> global <> option Normal private
    112 -> private <> option Normal global
    _   -> return Normal
  where global = string "global" *> space1 $> Global
        private = string "private" *> space1 $> Private

-- PARSE RULE BLOCK

parseRuleBlock :: YaraParser (Seq.Seq ())
parseRuleBlock = do
  ty <- ruleType
  string "rule"
  id <- skipTo1 identifier
  tg <- option [""] (colon *> tags)
  oCurl
  meta
  ss <- block "strings" patterns
  -- >>= (block "condition:") . conditions
  cCurl
  return $ singleton () -- Data.Map.empty <?> "Parse Rule Block"
  where
    block :: ByteString -> YaraParser a -> YaraParser (Seq.Seq a)
    block s p = do
      string s <* colon
      skipTo $ sepBy p space1

tags :: YaraParser [Identifier]
tags = flank space1 $ sepBy identifier space1

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
hexPr = singleton . uncurry Pair <$> (hexDigit `pair` hexDigit)
     where hexDigit = satisfy $ \w -> w == 63 || w - 48 <=  9
                              || w - 97 <= 25 || w - 65 <= 25

hexJump :: YaraParser HexTokens
hexJump = between sqBra sqKet $ do
  l <- optional decimal
  flank space dash
  u <- optional decimal
  return $ maybe Seq.empty singleton $ if
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

data RelOp = RelOp_LEQ
           | RelOp_LT
           | RelOp_EQ
           | RelOp_GT
           | RelOp_GEQ

relOp :: YaraParser RelOp
relOp = asum [ lt $> RelOp_LT
               , gt $> RelOp_GT
               , eq *> eq $> RelOp_EQ
               , gt *> eq $> RelOp_GEQ
               , lt *> eq $> RelOp_LEQ ]



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
handleArgs (a:as) env conf  = case a !! 1 of
  _ -> if
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



launch :: IO (ExitCode)
launch = do
  res <- parseArgs `liftM` getArgs
  case res of
   Fail b1 bs b2 -> undefined
   Partial _     -> undefined
   Done b e      -> when (printHelp e) $ hPutStrLn stderr help $> ExitSuccess {- start running the program-}


main :: IO ()
main = do
  launch >>= \case
    ExitSuccess   -> return () {- if show help true, do so, else if show version true do so, otherwise proceeed-}
    ExitFailure 0 -> return ()
    ExitFailure 1 -> return ()
