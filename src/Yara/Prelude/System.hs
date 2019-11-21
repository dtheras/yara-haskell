-- |
-- Module      :  Yara.Prelude.System
-- Copyright   :  David Heras 2019
-- License     :  GPL-3
--
-- Maintainer  :  dheras@protonmail.com
-- Stability   :  experimental
-- Portability :  unknown
--
-- Systems programming core.
--
module Yara.Prelude.System (
    module Yara.Prelude.System
  , module Export
  ) where

import System.Posix.Types as Export

import Yara.Prelude.Internal

import Data.ByteString hiding (elem)
import Text.Regex.Posix ((=~~))
import qualified Data.Sequence as Seq




{-


------------------------------------------------------------------------------
-- Glob pattern matching

-- | Glob patterns specify sets of filenames with wildcard characters
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
-- Modeled after System.FilePath.Glob, but handles ByteStrings.

glob :: ByteString -> IO (Seq.Seq FilePath)
glob = undefined -- =~~ undefined

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
-}
