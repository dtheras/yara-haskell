{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}
-- |
-- Module      :  Yara.Shared
-- Copyright   :  David Heras 2018-2019
-- License     :  GPL-3
--
-- Maintainer  :  dheras@protonmail.com
-- Stability   :  experimental
-- Portability :  unknown
--
-- Imported by almost all source files, this is a shared batch of types,
-- operators, functions, class instances.
--
module Yara.Shared (
    Byte, FilePath, liftA2,

    -- Systems check
    onWindows, onPosix,

    -- ByteString operators & utilities
    (++), (<+), (+>), sig, dropEndWhile, takeEndWhile, concatReverse,

    -- Re-exporting
    ($>), (<|>), asum,

    -- UnconsN series
    uncons2, uncons3, uncons4, uncons5

  ) where

import Prelude hiding ((++), FilePath)
import Control.Applicative ((<|>))
import Control.Exception
import Data.ByteString
import Data.ByteString.Internal (ByteString(..), accursedUnutterablePerformIO)
import Data.ByteString.Unsafe
import Data.Default
import Data.Foldable (asum)
import Data.Functor
import Data.Word
import Foreign hiding (void)

import qualified Data.List       as List
import qualified Data.Map.Strict as Map
import qualified Data.Set        as Set
import qualified Data.Sequence   as Seq

infixl 5 ++
infixr 5 <+
infixl 5 +>

-- | @<> := ||@.
-- Simplifies writing bool checks:
-- (\b -> b <= 10 || b == 20 || b >= 30)  <=>  (<=10) <> (==20) <> (>=30)
instance Semigroup Bool where
  (<>) = (||)

-- | The default bytestring is the empty string.
-- Best to write '""' rather than 'def'. May remove later.
instance Default ByteString where
  def = ""

-- | Type alias that assists in reading, since whole library views
-- input as a stream of bytes in the structure of a ByteString.
type Byte = Word8

-- | A bit neater than "RawFilePath"
type FilePath = ByteString

-- | On a windows system?
onWindows :: Bool
#if defined(mingw32_HOST_OS) || defined(__MINGW32__)
onWindows = True
#else
onWindows = False
#endif
{-# INLINE onWindows #-}

-- | On a posix system? onPosix := not onWindows
onPosix :: Bool
onPosix = not onWindows

-- | Shorter version of 'singleton'
sig :: Byte -> ByteString
sig = singleton

-- | Concatenate operator for bytestrings (Prelude to be imported hiding (++))
(++) :: ByteString -> ByteString -> ByteString
(++) = append
{-# INLINE (++) #-}

-- | Operator for `cons`
(<+) :: Byte -> ByteString -> ByteString
(<+) = cons
{-# INLINE (<+) #-}

-- | Operator for `snoc`
(+>) :: ByteString -> Byte -> ByteString
(+>) = snoc
{-# INLINE (+>) #-}

-- | Version of liftA2, strict in second argument
liftA2 :: (Applicative f) => (a -> b -> c) -> f a -> f b -> f c
liftA2 f a b = do
  x <- a
  !y <- b
  pure $ f x y
{-# INLINE liftA2 #-}

-- | unsafely moves bytestring pointer to new offset & keeps only length
-- number of bytes
unsafeDropTake :: ByteString -> Int -> Int -> ByteString
unsafeDropTake (PS s off len) m n =
    -- Writen as a faster version of composing unsafeDrop & unsafeTake
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
        go (f `plusPtr` (s+l-1)) 0
  where
    go !ptr !n | n >= l    = return ""
               | otherwise = do
                   w <- peek ptr
                   if k w
                     then go (ptr `plusPtr` (-1)) (n+1)
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
        go (f `plusPtr` (s+l-1)) 0
  where
    go !ptr !n | n >= l    = return ""
               | otherwise = do
                   w <- peek ptr
                   if k w
                     then go (ptr `plusPtr` (-1)) (n+1)
                     else return (PS x (s+l-n) n)
{-# INLINE takeEndWhile #-}

-- | Concatenate after reversing order of its elements (not reversing the
-- individual bytestrings).
concatReverse :: [ByteString] -> ByteString
concatReverse = go ""
  where go !acc []     = acc
        go acc  (x:xs) = go (x ++ acc) xs
 -- or? go acc (x:xs) = go $! x ++ acc xs
 -- Because we would rather let the compiler optimize rather that force WHNF
{-# INLINE concatReverse #-}



-- | unconsN series allow pattern matching on the begining of a bytestring
-- similar to the initial elements of a list (which is lost when using
-- bytestrings)
uncons2 :: ByteString -> Maybe (Byte, Byte, ByteString)
uncons2 x@(PS _ _ l)
    | l <= 1    = Nothing
    | otherwise = Just (unsafeIndex x 0, unsafeIndex x 1, unsafeDrop 2 x)
{-# INLINE uncons2 #-}

uncons3 :: ByteString -> Maybe (Byte, Byte, Byte, ByteString)
uncons3 x@(PS _ _ l)
    | l <= 2    = Nothing
    | otherwise = Just (unsafeIndex x 0, unsafeIndex x 1, unsafeIndex x 2,
                        unsafeDrop 3 x)
{-# INLINE uncons3 #-}

uncons4 :: ByteString -> Maybe (Byte, Byte, Byte, Byte, ByteString)
uncons4 x@(PS _ _ l)
    | l <= 3    = Nothing
    | otherwise = Just (unsafeIndex x 0, unsafeIndex x 1, unsafeIndex x 2,
                        unsafeIndex x 3, unsafeDrop 4 x)
{-# INLINE uncons4 #-}

uncons5 :: ByteString -> Maybe (Byte, Byte, Byte, Byte, Byte, ByteString)
uncons5 x@(PS _ _ l)
    | l <= 4    = Nothing
    | otherwise = Just (unsafeIndex x 0, unsafeIndex x 1, unsafeIndex x 2,
                        unsafeIndex x 3, unsafeIndex x 4, unsafeDrop 5 x)
{-# INLINE uncons5 #-}
