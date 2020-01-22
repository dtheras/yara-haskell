{-# OPTIONS_GHC -Wno-orphans #-} -- quiets ghc over Semigroup instance for Bool
-- |
-- Module      :  Yara.Prelude.Internal
-- Copyright   :  David Heras 2019-2020
-- License     :  GPL-3
--
-- Maintainer  :  dheras@protonmail.com
-- Stability   :  experimental
-- Portability :  unknown
--
-- Local prelude. Not to be imported directly since the system level functions
-- are contained in a seperate file. Use "Yara.Prelude".
--
-- Prelude design targets/parameters:
--   o Generic boilerplate
--   o import "standard" modules
--   o ByteString based
--   o Systems functions that arn't application specific
--
-- There is an issue of namespace conflicts, especially since several functions
-- are  defined for ByteStrings that cannot be overloaded from their counter
-- parts (eg.  fold, all,...). If there is a conflict and...
--    | only one of the two is needed, don't import the unused.
--    | both are needed,
--             -> if its used many times, try to rename one something intuitive.
--             -> otherwise, import locally.
--    | neither are used, OK.
--
module Yara.Prelude.Internal (
    module Yara.Prelude.Internal
  , module Export
  ) where

-- | Rexported modules
import Control.DeepSeq            as Export
import Control.Exception          as Export
import Control.Monad              as Export
import Control.Monad.Combinators  as Export hiding (between, many, some)
import Control.Monad.Except       as Export
import Control.Monad.Extra        as Export hiding (unit)
import Control.Monad.Reader       as Export
import Control.Monad.State.Strict as Export
import Data.Bool                  as Export hiding (bool)
import Data.ByteString            as Export hiding (map, concat, any, foldr,
  foldl, foldl1, foldr1, foldl', foldr', all, maximum, minimum, notElem,
  empty, null, elem, takeWhile, count, putStrLn, intercalate)
import Data.ByteString.Char8      as Export (putStrLn)
import Data.ByteString.Internal   as Export (ByteString(..),
  accursedUnutterablePerformIO, memcpy)
import Data.ByteString.Short      as Export (ShortByteString, toShort,
  fromShort)
import Data.ByteString.Unsafe     as Export
import Data.Default               as Export
import Data.Either                as Export
import Data.Foldable              as Export hiding (length, find, concatMap)
import Data.Function              as Export
import Data.Functor               as Export
import Data.Hashable              as Export
import Data.Maybe                 as Export
import Data.Scientific            as Export
import Data.Semigroup             as Export hiding (Any, option)
import Data.Typeable              as Export
import Data.Tuple                 as Export
import Data.Word                  as Export
import Foreign                    as Export hiding (void)
import Foreign.Ptr                as Export
import GHC.Base                   as Export hiding (sequence, liftA2, foldr,
  (++), mapM)
import GHC.ForeignPtr             as Export
import GHC.Generics               as Export (Generic)
import GHC.Num                    as Export
import GHC.Real                   as Export hiding (odd)
import GHC.Show                   as Export

import qualified Data.ByteString as B hiding (intercalate)
import qualified Data.ByteString.Short as S
import Data.ByteString.Builder
import qualified Data.ByteString.Char8 as C8 hiding (intercalate)
import qualified Data.ByteString.Lazy as BL
import Data.ByteString.Unsafe
import Data.Default
import qualified Data.Foldable as F
import qualified Data.HashMap.Strict as HM
import qualified Data.HashSet as HS
import Foreign hiding (void)

infixl 6 ~+, ~-
infixl 5 ++, +>
infixr 5 <+
infixr 1 >>?

-- | Alias to assist in readability, as all files are viewed
-- as streams of bytes (via ByteString data structure)
type Byte = Word8

-- | A bit neater than "RawFilePath"
type FilePath = ByteString

-- | Strict, unpacked tuple.
data T2 a s = T2 {-# UNPACK #-} !a  {-# UNPACK #-} !s

instance (Show a, Show s) => Show (T2 a s) where
  show (T2 x y) = concat ["T2(",show x,",",show y,")"]

-- | @<> := ||@.
-- Simplifies writing bool checks:
-- (\b -> b <= 10 || b == 20 || b >= 30)  <=>  (<=10) <> (==20) <> (>=30)
instance Semigroup Bool where
  (<>) = (||)

instance Default (HM.HashMap k v) where
  def = HM.empty

instance Default (HS.HashSet v) where
  def = HS.empty

instance Default S.ShortByteString where
  def = S.empty

------------------------------------------------------------
-- Systems check

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

-------------------------------------------------------------------
-- Byte predicates

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
GO(isRegexByte,(\w -> w-92 <= 2 || w-123 <= 2 || w `elem` [36,40,41,43,46] ))
#undef GO

-------------------------------------------------------------------
-- ByteStrings

instance Default ByteString where
  def = B.empty

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

-- May remove the following. We should be operating faster.
unpackSBS :: ShortByteString -> [Word8]
unpackSBS = S.unpack
{-# INLINE unpackSBS #-}

packSBS :: [Word8] -> ShortByteString
packSBS = S.pack
{-# INLINE packSBS #-}

-- | @int2bs@ converts an int to a bytestring.
--
-- @VERY SLOW@ Uses the really slow 'toStrict', but even if parsing
-- a 100,00 word novel, at over-estimate of 7 characters a word, leaves
-- us converting a number less than 850,000 into a bytestring, max.
-- As a computation, that would probably be utterly dwarfed by the
-- actual loading "War & Peace" into the buffer. First estimates in ghci
-- suggest this is the fastest method.
int2bs :: Int -> ByteString
int2bs = BL.toStrict . toLazyByteString . intDec
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
    go !ptr !n
      | n >= l    = pure def
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
    withForeignPtr x $ \f -> go (f ~+ (s+l-1)) 0
  where
    go !ptr !n
      | n >= l    = pure def
      | otherwise = do
          w <- peek ptr
          if k w
            then go (ptr ~+ (-1)) (n+1)
            else return (PS x (s+l-n) n)
{-# INLINE takeEndWhile #-}

-- | Concatenate after reversing order of its elements (not reversing
-- the individual bytestrings).
concatReverse :: [ByteString] -> ByteString
concatReverse = go def
  where go !acc []     = acc
        go acc  (x:xs) = go (x ++ acc) xs
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

-- | unsafeHead2 the first two bytes of a bytestring and return them
-- as a pair.
unsafeHead2 :: ByteString -> (Byte, Byte)
unsafeHead2 (PS x s l) = assert (l > 1) $
  accursedUnutterablePerformIO $ withForeignPtr x $ \p ->
    liftA2 (,) (peekByteOff p s) (peekByteOff p (s+1))

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

intercalate :: Monoid m => m -> [m] -> m
intercalate _ []     = mempty
intercalate s (x:xs) = foldl (\a b -> a `mappend` s `mappend` b) x xs
{-# INLINABLE intercalate #-}
{-# SPECIALIZE Yara.Prelude.Internal.intercalate :: ByteString
                                                 -> [ByteString]
                                                 -> ByteString        #-}
{-# SPECIALIZE Yara.Prelude.Internal.intercalate :: ShortByteString
                                                 -> [ShortByteString]
                                                 -> ShortByteString   #-}

------------------------------------------------------------
-- Misc.

-- | Alias for 'length' of Foldables using the mathematical terminology
-- of 'cardinality'. To avoid namespace collision.
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

-- | Does nothing, just returns () in an Applicative. Cleaner than a litany
-- of "pure ()"
unit :: Applicative f => f ()
unit = pure ()
{-# INLINE unit #-}

-- | Infix for 'catchError'
(>>?) :: MonadError e m => m a -> (e -> m a) -> m a
(>>?) = catchError
{-# INLINE (>>?) #-}

-- | Infix for 'flip'
($/) :: (a -> b -> c) -> b -> a -> c
($/) f x y = f y x
{-# INLINE ($/) #-}

-- | 'asumMap'
-- A function oddly missing from the standard libraries.
asumMap :: (Alternative p, Foldable f) => (a -> p b) -> f a -> p b
asumMap f = foldr ((<|>) . f) empty
{-# INLINE asumMap #-}
