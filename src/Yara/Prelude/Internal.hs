{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
-- |
-- Module      :  Yara.Prelude.Internal
-- Copyright   :  David Heras 2018-2019
-- License     :  GPL-3
--
-- Maintainer  :  dheras@protonmail.com
-- Stability   :  experimental
-- Portability :  unknown
--
-- Shared plumbing for internal prelude files.
--
-- SHOULD NOT be imported directly, only for source files contained
-- within the folder "Yara//Prelude//Internal/". Please use "Yara.Prelude"
-- instead.
--
-- Having an internal prelude module allows the breaking up of a massive
-- prelude file into reasonable chunks.
--
--     Prelude.hs
--     ^        ^
--     |         \
--     |      Prelude/System.hs
--     |           ^
--     |           |
--   Prelude/Internal.hs
--
module Yara.Prelude.Internal (
    module Yara.Prelude.Internal
  , module Export
  ) where

-- | Modules to re-export.
import Control.Applicative as Export hiding (liftA2)
import Control.DeepSeq as Export
import Control.Exception as Export
import Control.Monad as Export
import Control.Monad.Except as Export
import Control.Monad.Extra as Export hiding (unit)
import Control.Monad.IO.Class as Export
import Control.Monad.Reader as Export
import Control.Monad.State.Strict as Export
import Data.ByteString  as Export hiding (map, concat, any, foldr, foldl,
  foldl1, foldr1, foldl', foldr', all, maximum, minimum, notElem, empty,
  null, elem, takeWhile, count, putStrLn)
import Data.ByteString.Char8 as Export (putStrLn)
import Data.ByteString.Internal as Export (ByteString(..),
  accursedUnutterablePerformIO)
import Data.Default as Export
import Data.Either as Export
import Data.Foldable as Export hiding (length, find, concatMap)
import Data.Functor as Export
import Data.Maybe as Export
import Data.Semigroup as Export hiding (Any, option)
import Data.Tuple as Export
import GHC.Base as Export hiding (liftA2, foldr, (++), sequence, mapM)
import GHC.Classes as Export
import GHC.Generics as Export (Generic)
import GHC.Num as Export
import GHC.Prim as Export
import GHC.Real as Export
import GHC.Show as Export

import Data.ByteString
import qualified Data.Foldable as F (length)
import Data.Word (Word8)
import Foreign hiding (void)

infixl 6 ~+, ~-

-- | @<> := ||@.
-- Simplifies writing bool checks:
-- (\b -> b <= 10 || b == 20 || b >= 30)  <=>  (<=10) <> (==20) <> (>=30)
instance Semigroup Bool where
  (<>) = (||)

-- | Alias to assist in readability, as all files are viewed
-- as streams of bytes (via ByteString data structure)
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

-- | 'onPosix := not onWindows'
--
-- Should be fine grain enough for general purpose.
onPosix :: Bool
onPosix = not onWindows
{-# INLINE onPosix #-}

-- | Alias for 'length' of Foldables using the math terminology of 'cardinality'.
cardinality :: Foldable f => f a -> Int
cardinality = F.length
{-# INLINE cardinality #-}

-- | Version of liftA2, strict in second argument
liftA2 :: (Applicative f) => (a -> b -> c) -> f a -> f b -> f c
liftA2 f a b = do
  x <- a
  !y <- b
  pure $ f x y
{-# INLINE liftA2 #-}

unit :: Applicative f => f ()
unit = pure ()
{-# INLINE unit #-}


--------------------------------------------------------------------------------
-- Pointer operators

-- | Alias for @plusPtr@
(~+) :: Ptr a -> Int -> Ptr b
(~+) = plusPtr
{-# INLINE (~+) #-}

-- | Alias for @minusPtr@
(~-) :: Ptr a -> Ptr b -> Int
(~-) = minusPtr
{-# INLINE (~-) #-}

--------------------------------------------------------------------------------
-- Strict/Unpacked Tuples

-- Note: the -funbox-strict-fields lets us to omit the UNPACK pragmas
--
-- The following reasoning was used in choosing using.
--
--  * [To the extent of my knowledge] The fusion optimization GHC does in
--    eliminating intermediate tuples is in the following case:
--      > f (a,b) = f' a b
--      > f' a b = doSomething
--    In those cases, we use normal tuples since syntactically its nicer
--    and computationally irrevant. However, quite often there is the
--    following:
--    > someFun = do
--    >   (a,b) <- crazyComputation
--    >   if | f a -> doFirstBranch
--    >      | h b -> doSecondBranch
--    Ostensibly there is much bigger step in the code that would prevent
--    fusion. In reality, the compiler may still be able to optimize that
--    away. No information has been found, and we have yet to be able to
--    test.
--
--  * Unboxed tuples are very nice, sytactically convinent but have two
--    limitations.
--
--    Again, it is unknown the speed gains.
data T2 a s = T2 !a !s

data T3 a b s = T3 !a !b !s
