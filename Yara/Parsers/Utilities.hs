{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ApplicativeDo #-}
module Utilities (
    (++)
  , (<+)
  , (+>)
  , putErr
  , liftA2
  , concatReverse
  , ($>) -- Re-exporting
  ) where

import Prelude hiding ((++))
--import Control.Applicative hiding (liftA2)
import Data.ByteString
import Data.Functor
import Data.Word
import qualified Data.List as List
import System.IO (stderr)

instance Semigroup Bool where
  (<>) = (||)

infixl 5 ++
infixr 5 <+
infixl 5 +>

(++) :: ByteString -> ByteString -> ByteString
(++) = append
{-# INLINE (++) #-}

(<+) :: Word8 -> ByteString -> ByteString
(<+) = cons
{-# INLINE (<+) #-}

(+>) :: ByteString -> Word8 -> ByteString
(+>) = snoc
{-# INLINE (+>) #-}

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
concatReverse xs  = mconcat (List.reverse xs)
{-# INLINE concatReverse #-}
