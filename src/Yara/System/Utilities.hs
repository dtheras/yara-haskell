{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE CPP #-}
-- |
-- Module      :  Yara.Parsers.Utilities
-- Copyright   :  David Heras 2018-2019
-- License     :  GPL-3
--
-- Maintainer  :  dheras@protonmail.com
-- Stability   :  experimental
-- Portability :  unknown
--
-- To annotate.
--
module Utilities (
    liftA2, concatReverse,

    -- Systems check
    onWindows,

    -- ByteString operators & utilities
    (++), (<+), (+>), dropEndWhile, takeEndWhile,

    -- Re-exporting
    ($>), (<|>), asum
  ) where

import Prelude hiding ((++))
import Control.Applicative ((<|>))
import Data.ByteString
import Data.ByteString.Internal (ByteString(..), accursedUnutterablePerformIO)
import Data.Foldable (asum)
import Data.Functor
import qualified Data.List
import Foreign hiding (void)
    -----
import Parsers.Types

infixl 5 ++
infixr 5 <+
infixl 5 +>

-- | @<> = ||@. Simplifies writing bool checks:
-- (\b -> b == 10 || b == 20 || b == 30)  <=>  (==10) <> (==20) <> (==30)
instance Semigroup Bool where
  (<>) = (||)

onWindows :: Bool
#if defined(mingw32_HOST_OS) || defined(__MINGW32__)
onWindows = True
#else
onWindows = False
#endif
{-# INLINE onWindows #-}

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

-- | Concatenate a monoid after reversing its elements.  Used to
-- glue together a series of textual chunks that have been accumulated
-- \"backwards\".
concatReverse :: Monoid m => [m] -> m
concatReverse [x] = x
concatReverse xs  = mconcat (Data.List.reverse xs)
{-# INLINE concatReverse #-}


{--
concatReverse ["david"] = "david"
concatReverse ["david","jeras","maggie"] = "maggeherasdavid"
-}



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
{-# INLINABLE takeEndWhile #-}

