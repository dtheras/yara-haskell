{-# LANGUAGE ApplicativeDo     #-}
{-# LANGUAGE BangPatterns      #-}
{-# LANGUAGE CPP               #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -funbox-strict-fields #-}
{-# OPTIONS_GHC -Wno-orphans   #-}
{-# OPTIONS_GHC -Wno-unused-imports #-}
-- |
-- Module      :  Yara.Prelude
-- Copyright   :  David Heras 2018-2019
-- License     :  GPL-3
--
-- Maintainer  :  dheras@protonmail.com
-- Stability   :  experimental
-- Portability :  unknown
--
-- Prelude replacement, imported by 99% of source files. The extension
-- NoImplicitPrelude is enabled globally.
--
-- See Yara.Prelude.Internal for design targets.
--
module Yara.Prelude (
    module Export
  , module Yara.Prelude
  ) where

import Yara.Prelude.Internal as Export
import Yara.Prelude.System as Export

-- | Imports used internally
import Control.Exception (assert)
import qualified Data.ByteString as B (map, null)
import Data.ByteString.Builder (toLazyByteString, intDec)
import qualified Data.ByteString.Char8 as C8 (pack, unpack)
import qualified Data.ByteString.Lazy as BL (toStrict)
import Data.ByteString.Unsafe (unsafeIndex, unsafeDrop)
import qualified Data.Foldable as F (length)
import Data.Word (Word8)
import Foreign hiding (void)

infixl 5 ++, +>
infixr 5 <+

#define GO(func,pred) func :: Byte -> Bool; func = pred; {-# INLINE func #-}
GO(isDot,(==46))
GO(isEqual, (==61))
GO(isAlpha,\b -> b - 65 < 26 || b - 97 < 26)
-- | A fast digit predicate.
GO(isDigit,\b -> b - 48 <= 9)
GO(isAlphaNum, isDigit <> isAlpha)
GO(isSpace, \b -> b == 32 || b - 9 <= 4)
-- | A predicate that matches either a carriage return @\'\\r\'@ or
-- newline @\'\\n\'@ character.
GO(isEndOfLine, (== 13) <> (== 10))
-- | A predicate that matches either a space @\' \'@ or horizontal tab
-- @\'\\t\'@ character.
GO(isHorizontalSpace, (== 32) <> (== 9))
GO(isHexByte,\b-> (b>=48 && b<=57) || (b>=97 && b<=102) || (b>=65 && b<=70))
GO(isUnderscore,(== 95))
GO(isLeadingByte,isAlpha <> isUnderscore)
GO(isIdByte,isAlphaNum <> isUnderscore)
#undef GO

-- | Shorter version of 'singleton'
sig :: Byte -> ByteString
sig = singleton
{-# INLINE sig #-}

-- | Concatenate operator for bytestrings (Prelude.++ is hidden)
(++) :: ByteString -> ByteString -> ByteString
(++) = append
{-# INLINE (++) #-}

-- | Operator alias for `cons`
(<+) :: Byte -> ByteString -> ByteString
(<+) = cons
{-# INLINE (<+) #-}

-- | Operator alias for `snoc`
(+>) :: ByteString -> Byte -> ByteString
(+>) = snoc
{-# INLINE (+>) #-}

-- | Alias for 'null' on bytestrings, resolves namespace conflict with 'null' on
-- Foldables.
isEmpty :: ByteString -> Bool
isEmpty = B.null
{-# INLINE isEmpty #-}

-- | Alias for 'map'-ing over bytestrings. Resolves a namespace conflict with
-- 'map'-ing over a standard list.
bmap :: (Byte -> Byte) -> ByteString -> ByteString
bmap = B.map
{-# INLINE bmap #-}

-- | Disambiguates the following by giving the second a unique alias:
--            Data.ByteString.pack :: [Word8] -> ByteString
--      Data.ByteString.Char8.pack :: [Char]  -> ByteString
s2bs :: [Char] -> ByteString
s2bs = C8.pack
{-# INLINE s2bs #-}

-- | Disambiguates the following by giving the second a distinguishing alias:
--            Data.ByteString.unpack :: ByteString -> [Word8]
--      Data.ByteString.Char8.unpack :: ByteString -> [Char]
bs2s :: ByteString -> [Char]
bs2s = C8.unpack
{-# INLINE bs2s #-}

-- | @int2bs@ converts an int to a bytestring.
--
-- @VERY SLOW@ Uses the really slow 'toStrict', but even if parsing
-- a 100,00 word novel, at over-estimate of 7 characters a word, leaves
-- us converting a number less than 850,000 into a bytestring, max.
-- As a computation, that would probably be utterly dwarfed by the
-- actual loading "War & Peace" into the buffer. First estimates in ghci
-- suggest this is the fastest method.
int2bs :: Int -> ByteString
int2bs =  BL.toStrict . toLazyByteString . intDec
{-# INLINE int2bs #-}

-- | unsafely moves bytestring pointer to new offset & keeps only length
-- number of bytes
unsafeDropTake :: ByteString -> Int -> Int -> ByteString
unsafeDropTake (PS s off len) m n =
  assert (0 <= n && n <= (len-m)) $ PS s (off+m) n
{-# INLINE unsafeDropTake #-}

-- | 'dropEndWhile' a variant of 'Data.ByteString.dropWhile' that drops
-- from the end of the bytestring, moving "backwards"
--
-- >>> dropEndWhile (>70) "ABCDEFGHIJKLMNOPQRST"
-- "ABCDEF"
dropEndWhile :: (Byte -> Bool) -> ByteString -> ByteString
dropEndWhile k (PS x s l) =
    accursedUnutterablePerformIO $
      withForeignPtr x $ \f ->
        go (f ~+ (s+l-1)) 0
  where
    go !ptr !n | n >= l    = return ""
               | otherwise = do
                   w <- peek ptr
                   if k w
                     then go (ptr ~+ (-1)) (n+1)
                     else return (PS x s (l-n))
{-# INLINE dropEndWhile #-}

-- | 'takeEndWhile' a variant of 'Data.ByteString.takeWhile' that takes
-- starting from the end of the bytestring, moving "backwards"
--
-- >>> takeEndWhile (>70) "ABCDEFGHIJKLMNOPQRST"
-- "GHIJKLMNOPQRST"
takeEndWhile :: (Byte -> Bool) -> ByteString -> ByteString
takeEndWhile k (PS x s l) =
    accursedUnutterablePerformIO $
      withForeignPtr x $ \f ->
        go (f ~+ (s+l-1)) 0
  where
    go !ptr !n | n >= l    = return ""
               | otherwise = do
                   w <- peek ptr
                   if k w
                     then go (ptr ~+ (-1)) (n+1)
                     else return (PS x (s+l-n) n)
{-# INLINE takeEndWhile #-}

-- | Concatenate after reversing order of its elements (not reversing
-- the individual bytestrings).
concatReverse :: [ByteString] -> ByteString
concatReverse = go ""
  where go !acc []     = acc
        go acc  (x:xs) = go (x ++ acc) xs
 -- or? go acc (x:xs) = go $! x ++ acc xs
 -- Because we would rather let the compiler optimize rather that force WHNF
{-# INLINE concatReverse #-}

-- | Convert all upper case letters to lower case. Other
-- characters are unaffected.
toLower :: ByteString -> ByteString
toLower = bmap $ \b ->
  if b >= 65 && b <= 90 then b + 32 else b
{-# INLINE toLower #-}

-- | Convert all lower case letters to upper case. Other
-- characters are unaffected.
toUpper :: ByteString -> ByteString
toUpper = bmap $ \b ->
  if b >= 97 && b <= 122 then b - 32 else b
{-# INLINE toUpper #-}

-- | @toShows@ used for writting 'Show' instances involving bytestrings.
--
-- Only /show/s the first 11 bytes as patterns will often run very long.
toShows :: Show a => a -> ShowS
toShows x = showChar ' ' . showsPrec 11 x
{-# INLINE toShows #-}

uncons2 :: ByteString -> Maybe (Byte, Byte, ByteString)
uncons2 x@(PS _ _ l)
    | l <= 1    = Nothing
    | otherwise = assert (l > 1) $
        Just (unsafeIndex x 0, unsafeIndex x 1, unsafeDrop 2 x)
{-# INLINE uncons2 #-}

-- | @atomicModification@ runs a tortise-hare algorithm
-- used to atomically modify bytestrings using a state token.
--
-- `atomic` roughly-traverses the bytestring using a
-- state `S`, coupled with two offset counters to atomically
-- modify the bytestring. The offets are labeled as follows:
--    * `hare` offset corresponds to read-byte location
--    * `tort` offset corresponds to write-byte location
--
-- `hare` gets incramented at the end of the loop block.
--
-- `tort` gets adjused exclusively through the update function.
--
-- So, when entering a loop the
-- `tort` location is `empty` since writing is only done when it
-- gets moved (an byte is writen in the previous spot)
atomicModification :: (s -> Ptr Byte -> Int -> Int -> IO (Int, s))
                   -> s -> ByteString -> (ByteString, s)
atomicModification atomic s0 (PS fp off len) =
  accursedUnutterablePerformIO $ do
    (t,s) <- withForeignPtr fp $ \a -> atomic s0 (a ~+ off) 0 0
    assert (t <= len) $! pure (PS fp 0 t, s)
