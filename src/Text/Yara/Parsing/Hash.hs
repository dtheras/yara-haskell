{-# OPTIONS_GHC -funbox-strict-fields #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE BlockArguments #-}
{-# LANGUAGE  UnboxedSums #-}
-- PackageImports
--
-- After several hours of attempting to resolve ghci complaint:
--     |  Ambiguous module name ‘Crypto.Hash’:
--     |    it was found in multiple packages:
--     |    cryptohash-0.11.9 cryptonite-0.25
-- it was descovered the only (not-hackish) solution that has worked is the
-- PackageImports pragma. Another hack suggested was the used of
-- -ignore-package. However, that flag doesn't parse within a
-- {-# OPTIONS_GHC #-} in a source file.
-- Read here: https://downloads.haskell.org/~ghc/latest/docs/html/
--                     users_guide/glasgow_exts.html#package-qualified-imports
{-# LANGUAGE PackageImports #-}
-- |
-- Module      :  Text.Yara.Parsing.Hash
-- Copyright   :  David Heras 2018-2019
-- License     :  GPL-3
--
-- Maintainer  :  dheras@protonmail.com
-- Stability   :  experimental
-- Portability :  unknown
--
-- The hash module provides 2 different flavors of hash functions:
--
-- A) Single string literal argument passed in.
--
--       It operates on the string argument by returning its respective
--       hash so that the literal can be contained within the yara rule
--       rather than its cryptic hash. (similar to an imported numerical
--       function).
--
-- B) Pair of (64-bit) integers passed in.
--
--       The first is a file offset and second is length of portion of
--       file.
--
module Text.Yara.Parsing.Hash ( parseHash ) where

import Control.Monad.IO.Class
import Control.Applicative
import "cryptonite" Crypto.Hash
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString as S
import Data.Digest.Adler32 ()
import Data.ByteArray.Encoding
import Data.ByteArray hiding (null)
import Data.Int
    -----
import Text.Yara.Shared
import Text.Yara.Parsing.Types
import Text.Yara.Parsing.Parser
import Text.Yara.Parsing.Combinators

-- | Store results of parsing hash in yara rule.
--
-- Note: not certain this is the best method yet.
--       The latter end of developing the program needs to be written.
data Hash
  -- | returned hash of string litera
  = LiteralHash S.ByteString
  -- |
  | FileHash (L.ByteString -> Bool)

-- Exclusively used to shuffle an result around.
-- Strict fields so compiler should optimized away.
--
-- Considered using UnboxedSums but Int64s and ByteStrings
-- are lifted types which cannot be used with UnboxedSums.
-- BoxedSum types are not supported by GHC.
data HashArgs = Int64Args !Int64 !Int64
              | StringArg S.ByteString

parseHash :: YaraParser Hash
parseHash = flip (<?>) "parseHash" $ do
  -- Parse hash name
  hs <- strings ["md5", "sha1", "sha256", "checksum32"] <?> noImportMsg
  spaces
  openParen <?> "No hash argument found! Seeking '('"
  spaces
  -- Get either a quoted string or pair of Int64 numbers
  args <- parseLiteralArg <|> parseFileArgs
            <?> "Bad hash arg: expecting literal string or pair of integers"
  spaces
  closeParen <?> "Hash argument(s) lacked closing ')'"
  --let hashAlg = case hs of
  case args of
    StringArg l -> return $ handleLiteralArg hs l
    Int64Args m n -> do
      spaces
      equal *> equal <?> "=="
      spaces
      r <- quotedString <?> "Hash: Expecting literal string"
      if S.null r
        then fault "Hash: expected hash cannot be empty."
        else return $ handleFileArgs hs m n r

  where

    parseLiteralArg :: YaraParser HashArgs
    parseLiteralArg = StringArg <$> quotedString

    parseFileArgs :: YaraParser HashArgs
    parseFileArgs = do
        u <- (hexadecimal <|> decimal) :: YaraParser Int64
        spaces
        comma
        spaces
        v <- (hexadecimal <|> decimal) :: YaraParser Int64
        return $ Int64Args u v

    quotedString = undefined
    comma = undefined
    noImportMsg = "Hash Module: Expected one of the following imported \
                  \hash functions: 'md5', 'sha1', 'sha256','checksum32'"

--digestToByteString :: Digest a -> S.ByteString
--digestToByteString (Digest bs) = convertToBase (Base16 bs :: S.ByteString)

handleLiteralArg :: S.ByteString -> S.ByteString -> Hash
handleLiteralArg hs b = LiteralHash case hs of
  "md5"         -> convert (hash b :: Digest MD5   ) -- :: S.ByteString
  "sha1"        -> convert (hash b :: Digest SHA1  ) -- :: S.ByteString
  "sha256"      -> convert (hash b :: Digest SHA256) -- :: S.ByteString
 --   "checksum32"  -> (hash b :: Digest CHECKSUM32)
  _             -> error "How did you get here?"


---- hashWith (read hs) b
handleFileArgs :: S.ByteString
               -> Int64
               -> Int64
               -> S.ByteString -- ^ String to match
               -> Hash
handleFileArgs = undefined
