{-# OPTIONS_GHC -Wno-unused-do-bind #-}
-- |
-- Module      :  Yara.Parsing.Patterns
-- Copyright   :  David Heras 2019
-- License     :  GPL-3
--
-- Maintainer  :  dheras@protonmail.com
-- Stability   :  experimental
-- Portability :  unknown
--
-- Parser combinators for 3 types of string patterns contained in
-- yara rules (See Section 2.2 of the yara spec).
--
-- TODO: 'hexBound'. Easy, just being a bit of a thorn.
--
module Yara.Parsing.Patterns (
    parsePatterns -- :: Yp s Patterns
  ) where

import Yara.Prelude
import Yara.Parsing.AST
import Yara.Parsing.ByteStrings
import Yara.Parsing.Combinators
import Yara.Parsing.Parser

import qualified Data.HashMap.Strict as HM
import qualified Data.Set as S

------------------------------------------------------------------------
-- Text & Regex Patterns

data Modifications = Modifications {
    ascii_    :: ByteString -> ByteString
  , fullword_ :: ByteString -> ByteString
  , nocase_   :: ByteString -> ByteString
  , wide_     :: ByteString -> ByteString
  , xor_      :: Maybe (T2 Byte Byte)
  , private_  :: Bool
  }

instance Default Modifications where
  -- The yara spec never specifies what the
  -- "ascii" keyword does; set as 'id' placeholder.
  def = Modifications id id id id Nothing False

-- | `hasPattern` returns whether or not a string label matches the
-- name of an inscope pattern.
hasPattern :: ByteString -> Patterns -> Bool
hasPattern bs Patterns{..} = HM.member bs stdPatterns
{-# INLINE hasPattern #-}

-- | `patterModifiers` parses the set of pattern modifiers for
-- regex and text patterns.
patternModifiers :: Yp s Modifications
patternModifiers = do
  r <- seek $ sepByAcc keyword (void space1)
  notFollowedBy isAlpha
  pure r
  <?> "patternModifiers"
  where
    mkNocase, mkFullword, mkWide :: ByteString -> ByteString
    mkNocase bs = bs ++ "i"
    mkFullword bs = "[^[:alnum:]]{1}" ++ bs ++ "[^[:alnum:]]{1}"
    mkWide bs = intersperse 0 bs

    xor :: Yp s (Modifications -> Modifications)
    xor = do
      string "xor"
      let hexBound :: Yp s Byte
          hexBound = undefined
      r <- (Just <$> tuple hexBound) <|> notFollowedBy isAlpha $> Nothing
      pure $ \m -> m { xor_ = r }

    keyword :: Yp s (Modifications -> Modifications)
    keyword = xor <|> tokens [
        T2 "ascii"    id --(\m -> m { ascii    = id         })
      , T2 "fullword" (\m -> m { fullword_ = mkFullword })
      , T2 "nocase"   (\m -> m { nocase_   = mkNocase   })
      , T2 "wide"     (\m -> m { wide_     = mkWide     })
      , T2 "private"  (\m -> m { private_  = True       })
      ] <?> "keyword"

-- | Converts a pattern with its modifications to regex
toRegex :: ByteString -> Modifications -> Pattern
toRegex b Modifications{..} = Pattern (nocase_ $ fullword_ $ wide_ b) private_
{-# INLINE toRegex #-}
-- TODO: impliment xor
-- Per the spec, the xor-condition applied last

-- | Parse a text string pattern
textPattern :: Yp s Pattern
textPattern = liftA2 toRegex textString patternModifiers <?> "text pattern"

-- | Parse a regex string pattern
regexPattern :: Yp s Pattern
regexPattern = liftA2 toRegex regexPat patternModifiers <?> "regex pattern"
  where -- 1) Open regex with a forward slash '/'
        -- 2) Scan source until unescaped forward slash '/' is encountered
    p s w | s && w /= 47  = Nothing
          | w == 47       = Just True
          | otherwise     = Just False
    regexPat :: Yp s ByteString
    regexPat = fSlash *> scan False p <&> unsafeInit

------------------------------------------------------------------------
-- Hex Patterns

-- | 'lessthan'
-- Compares two bytestrings as if they were natural numbers,
-- rather than strings. Written to serve specific situation
-- below so its minimally robust.
--
-- The default 'Ord' instance for example would yield:
--    "1" < "5"  == True
--    "5" < "10" == False
--
-- 'bsLessthan' fixes this so that:
--    "1" < "5"  == True
--    "5" < "10" == True
--
-- * Really writen to serve our specific purpose.
-- * Handles leading zeros.
-- * Doesn't handle negatives and will generally
--     give wrong results.
-- * ASSUMES BYTES ARE DIGITS ALREADY
--     Doesn't check that the bytes are digits,
--     so anything will just pass through and
--     may provide bad results.
--
lessthan :: ByteString -> ByteString -> Bool
lessthan b1 b2
  | (PS p1 o1 l1) <- dropLeadingZeros b1 -- so the first number
  , (PS p2 o2 l2) <- dropLeadingZeros b2 -- is always >0
  = let lessthan_ :: Int -> IO Bool
        lessthan_ c = do             -- Need disambiguate type of stored value
          w_1 <- withForeignPtr p1 $ \p -> peekByteOff p (o1 + c) :: IO Word8
          w_2 <- withForeignPtr p2 $ \p -> peekByteOff p (o2 + c)
          if | w_1 >= w_2 -> pure False
             | c == l1    -> pure True
             | otherwise  -> lessthan_ (c+1)
    in if
      | l1 > l2   -> False -- If the first string is longer, we are done.
      | l2 > l1   -> True  -- If the second string is longer, we are done.
      | otherwise -> accursedUnutterablePerformIO $ lessthan_ 0
  where
    dropLeadingZeros = dropWhile (==48)
{-# INLINABLE lessthan #-}

hexPair :: Yp s ByteString
hexPair = do
  h1 <- hexDigit
  h2 <- hexDigit
  pure $ if
    | h1 == 63, h2 == 63 -> "[\\d|\\D]" -- '??' means match any byte
    | h1 == 63           -> "[\\x[a-f0-9A-F]" ++ sig h2 ++ "]"
    | h2 == 63           -> "[\\x" ++ sig h1 ++ "[0-9a-fA-F]]"
    | otherwise          -> "[\\x" ++ pack [h1,h2] ++ "]"
  <?>  "hexPair"
  where hexDigit = satisfy $ (==63) <> isHexByte
        {-# INLINE hexDigit #-}
{-# INLINABLE hexPair #-}

hexRange :: Yp s ByteString
hexRange = do
  (T2 l u) <- range $ takeWhile isDigit -- No need to "read" in values
  let ret bs = pure $ "[\\d\\D]" ++ bs
  if | isEmpty u
        , isEmpty l -> ret $ "*"
     | isEmpty u    -> ret $ "{" ++ l ++ ",}"
     | isEmpty l    -> ret $ "{0," ++ u ++ "}"
     | u == l       -> ret $ "{" ++ l ++ "}"
     | lessthan u l -> fault BadRangeBounds
         "found bad hex-pattern range, must be lower <= upper"
     | otherwise    -> ret $ "{" ++ l ++ "," ++ u ++ "}"
  <?> "hexRange"
{-# INLINABLE hexRange #-}

hexJump :: Yp s ByteString
hexJump = between sqBra sqKet $ do
  j <- takeWhile isDigit
  if isEmpty j
    then fault BadRangeBounds
           "found bad hex-pattern range, single must be defined"
    else pure $ "[\\d\\D]{" ++ j ++ "}"
  <?> "hexJump"
{-# INLINABLE hexJump #-}

hexPattern :: Yp s Pattern
hexPattern = do
  h <- between oCurly cCurly $ grouped spaces (hexTokens <|> hexSubPatGrp)
  s <- seek $ optional (sepBy1 (void "private") space1)
  pure $ Pattern (fold h) (isJust s)
  <?> "hexPattern"
  where
    hexTokens = fold <$> sepBy1 (hexPair <|> hexJump <|> hexRange) spaces
    {-# INLINABLE hexTokens #-}
    hexSubPatGrp = do
      h <- grouped vertBar hexTokens
      pure $ "(" ++ intercalate "|" h ++ ")"
    {-# INLINABLE hexSubPatGrp #-}
{-# INLINABLE hexPattern #-}

------------------------------------------------------------------------
-- Parse Patterns

parsePattern :: Yp s (Patterns -> Patterns)
parsePattern = seek $ do
  i <- dollar *> optional _identifier
  seek equal
  s <- seek $ textPattern <|> regexPattern <|> hexPattern
  pure $ case i of
    Nothing -> \m ->
      let p = anonPatterns m in m {anonPatterns = S.insert s p}
    Just f  -> \m ->
      let p = stdPatterns m in m {stdPatterns = HM.insert f s p}
  <?> "parserPattern"
{-# INLINABLE parsePattern #-}

parsePatterns :: Yp s Patterns
parsePatterns = do
  string "strings:"
  seek $ sepByAcc parsePattern (void spaces)


