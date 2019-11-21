{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE BlockArguments #-}
{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ViewPatterns #-}
{-# OPTIONS_GHC -funbox-strict-fields #-}
-- |
-- Module      :  Yara.Parsing.Patterns
-- Copyright   :  David Heras 2018-2019
-- License     :  GPL-3
--
-- Maintainer  :  dheras@protonmail.com
-- Stability   :  experimental
-- Portability :  unknown
--
-- YARA rules contain 3 types of strings:
-- * Hexadecimal strings
-- * Text strings
-- * Regular expressions
-- These are the following modifiers for "text strings"
-- * wide
-- * xor
-- * nocase
-- * acsii
-- * fullword
--
module Yara.Parsing.Patterns ( parsePatterns ) where

import Yara.Prelude
import Yara.Parsing.AST
import Yara.Parsing.ByteStrings
import Yara.Parsing.Combinators
import Yara.Parsing.Parser

import Data.ByteString.Unsafe
import Data.Maybe
import qualified Data.HashMap.Strict as H
import qualified Data.HashSet as S

textPattern :: Yp Pattern
textPattern = do
  s <- textString
  w <- seek $ sepByHashSet keyWords space1
  pure $ StringPattern s w
  where keyWords =
          asum [string "ascii", string "wide", string "nocase"]

------------------
-- Hex Strings

hexPattern :: Yp Pattern
hexPattern =
  HexPattern <$> (between oCurly cCurly $
      sepBy1 (hexSubPatStr <|> hexSubPatGrp) spaces)
  <?> "hexPattern"
  where
    hexPair :: Yp HexToken
    hexPair = liftA2 HexPair hexDigit hexDigit
      where hexDigit = satisfy $ (==63) <> isHexByte
            {-# INLINE hexDigit #-}
    {-# INLINE hexPair #-}

    hexJump :: Yp HexToken
    hexJump = between sqBra sqKet $ do
      l <- seek $ perhaps decimal
      seek dash
      u <- seek $ perhaps decimal
      if | Just False <- liftA2 (<) l u           -> badBounds
         | isNothing u, Just False <- (==0) <$> l -> badBounds
         | otherwise                              -> pure $ HexJump l u
      where
        badBounds = fault BadRangeBounds
           "found bad hex-pattern range, must be lower <= upper"
    {-# INLINE hexJump #-}

    hexSubPatStr :: Yp HexSubPattern
    hexSubPatStr = HexString <$> sepBy1 (hexPair <|> hexJump) space1
    {-# INLINABLE hexSubPatStr #-}

    hexSubPatGrp :: Yp HexSubPattern
    hexSubPatGrp = HexGrouping <$> (between oParen cParen $
                        sepBy1 hexSubPatStr (seek vertBar *> spaces))
    {-# INLINABLE hexSubPatGrp #-}

-------------------
-- Regex Patterns

-- | Parse a regex string pattern
regexPattern :: Yp Pattern
-- 1) Opens with a forward slash '/'
-- 2) Scan source until unescaped forward slash '/' is encountered
regexPattern = do
  fSlash *> scan False p <&> RegexPattern . unsafeInit
  <?> "error building regex map"
  where p s w | s && w /= 47  = Nothing
              | w == 47       = Just True
              | otherwise     = Just False

-----------------------
-- Parse patterns

putPatterns :: (Patterns -> Patterns) -> Yp ()
putPatterns f = modify $ \s ->
  let p = localPatterns s in s {localPatterns = f p}
{-# INLINE putPatterns #-}

putStdPattern :: ByteString -> Pattern -> Yp ()
putStdPattern v k = putPatterns $ \s ->
  let p = stdPatterns s in s {stdPatterns = H.insert v k p}
{-# INLINABLE putStdPattern #-}
putAnonPattern :: Pattern -> Yp ()
putAnonPattern a = putPatterns $ \s ->
  let p = anonPatterns s in s {anonPatterns = S.insert a p}
{-# INLINABLE putAnonPattern #-}

parsePattern :: Yp ()
parsePattern = seek $ do
  dollarSign
  i <- perhaps _identifier
  seek equal
  s <- seek $ textPattern <|> regexPattern <|> hexPattern
  maybe (putAnonPattern s) (flip putStdPattern s) i
  <?> "parserPattern"
{-# INLINE parsePattern #-}

parsePatterns :: Yp ()
parsePatterns = do
  string "strings:"
  seek $ oddSepBy spaces parsePattern
  where
    odd !_ !_ = ()
    {-# INLINE odd #-}

    oddSepBy1 :: Yp a -> Yp s -> Yp ()
    oddSepBy1 p s = fix $ \go -> liftA2 odd p ((s *> go) `mplus` def)
    {-# INLINE oddSepBy1 #-}

    oddSepBy :: Yp a -> Yp s -> Yp ()
    oddSepBy p s = liftA2 odd p ((s *> oddSepBy1 p s) <|> def) <|> def
    {-# INLINE oddSepBy #-}
