{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE CPP #-}
module Utilities (
    onWindows
  , (++)
  , (<+)
  , (+>)
  , putErr
  , liftA2
  , concatReverse
  , ($>) -- Re-exporting
  ) where

import Prelude hiding ((++))
import Data.ByteString
import Data.Functor
import Data.Word
import qualified Data.List
import System.IO (stderr)

instance Semigroup Bool where
  (<>) = (||)

infixl 5 ++
infixr 5 <+
infixl 5 +>

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
(<+) :: Word8 -> ByteString -> ByteString
(<+) = cons
{-# INLINE (<+) #-}

-- | Operator for `snoc`
(+>) :: ByteString -> Word8 -> ByteString
(+>) = snoc
{-# INLINE (+>) #-}

-- | Version of liftA2, strict in second argument
liftA2 :: (Applicative f) => (a -> b -> c) -> f a -> f b -> f c
liftA2 f a b = do
  x <- a
  !y <- b
  pure $ f x y
{-# INLINE liftA2 #-}

putErr :: ByteString -> IO ()
putErr = hPutStrLn stderr

-- | Concatenate a monoid after reversing its elements.  Used to
-- glue together a series of textual chunks that have been accumulated
-- \"backwards\".
concatReverse :: Monoid m => [m] -> m
concatReverse [x] = x
concatReverse xs  = mconcat (Data.List.reverse xs)
{-# INLINE concatReverse #-}
