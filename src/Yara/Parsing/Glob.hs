{-# LANGUAGE PatternGuards #-}
-- |
-- Module      :  Yara.Parsing.Glob
-- Copyright   :  David Heras 2018-2019
-- License     :  GPL-3
--
-- Maintainer  :  dheras@protonmail.com
-- Stability   :  experimental
-- Portability :  unknown
--
-- To annotate.
-- Glob patterns specify sets of filenames with wildcard characters
--
-- Syntax overview:
--
-- Token   Description
--  *       Matches any number of any characters including none
--  ?       Matches any single character
-- [abc]    Matches one character given in the bracket
-- [a-z]    Matches one character from the range given in the bracket
-- [!abc]   Matches one character that is not given in the bracket^
-- [!a-z]   Matches one character not from the range given in the bracket^
--                            ^Posix Only Syntax
--
-- Source: https://everipedia.org/wiki/lang_en/glob_%28programming%29/
--
-- The design of the library is modeled after System.FilePath.Glob, however
-- tailored to our needs by using ByteStrings natively and removing superfluous -- (for us) monad transforms support.
module Yara.Parsing.Glob where

import Prelude hiding (FilePath, (++), null, head)
import Data.ByteString hiding (elem)
import Text.Regex.Posix ((=~~))
import qualified Data.Sequence as Seq
    -----
import Yara.Shared

glob :: ByteString -> IO (Seq.Seq FilePath)
glob = undefined -- =~~ undefined

isRegexByte :: Byte -> Bool
isRegexByte w = w -92 <= 2 || w - 123 <= 2 || w `elem` [36,40,41,43,46]

globToRegex :: ByteString -> Maybe ByteString
globToRegex path = (\bs -> sig 94 ++ bs ++ sig 24) <$> go path
  where

    go :: ByteString -> Maybe ByteString
    go bs
      | Just (42,as) <- uncons bs       = lAp ".*" $ go as
      | Just (63,as) <- uncons bs       = lAp "." $ go as
      | Just (91,33,a,as) <- uncons3 bs = lAp (pack [91,94,a]) $ byteCl as
      | Just (91,a,as) <- uncons2 bs    = lAp (pack [91,a]) $ byteCl as
      | Just (91,_) <- uncons bs        = Nothing
      | Just (a,as) <- uncons bs        = lAp (esc a) $ go as
      | Nothing <- uncons bs            = Just bs

    byteCl :: ByteString -> Maybe ByteString
    byteCl fp | Just (93,bs) <- uncons fp  = lAp (sig 93) $ go bs
    byteCl fp | Just (b,bs)  <- uncons fp  = lAp (sig b) $ byteCl bs
    byteCl ""                              = Nothing

    esc b = if isRegexByte b then pack [92,b] else sig b

    -- Lift a bytestring and append it
    lAp :: ByteString -> Maybe ByteString -> Maybe ByteString
    lAp u v = liftA2 (++) (pure u) v


