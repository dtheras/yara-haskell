{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedLists #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TupleSections #-}
{-# OPTIONS_GHC -funbox-strict-fields #-}
{-# OPTIONS_GHC -Wno-orphans #-} -- quiets ghc over Semigroup instance for Bool
-- |
-- Module      :  Yara.Prelude.Internal
-- Copyright   :  David Heras 2019
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
-- Prelude design targets/parameters:
--
--
module Yara.Prelude.Internal (
    module Yara.Prelude.Internal
  , module Export
  ) where

-- Re-exports
import Control.DeepSeq            as Export
import Control.Exception          as Export
import Control.Monad              as Export
import Control.Monad.Except       as Export
import Control.Monad.Extra        as Export hiding (unit)
import Control.Monad.Reader       as Export
import Control.Monad.State.Strict as Export
import Data.Bool                  as Export
import Data.ByteString            as Export hiding (map, concat, any, foldr,
  foldl, foldl1, foldr1, foldl', foldr', all, maximum, minimum, notElem,
  empty, null, elem, takeWhile, count, putStrLn)
import Data.ByteString.Char8      as Export (putStrLn)
import Data.ByteString.Internal   as Export (ByteString(..),
  accursedUnutterablePerformIO)
import Data.Default               as Export
import Data.Either                as Export
import Data.Foldable              as Export hiding (length, find, concatMap)
import Data.Function              as Export
import Data.Functor               as Export
import Data.Maybe                 as Export
import Data.Semigroup             as Export hiding (Any)
import Data.Typeable              as Export
import Data.Tuple                 as Export
import Data.Word                  as Export
import GHC.Base                   as Export hiding (sequence, liftA2, foldr,
  (++), mapM)
import GHC.Generics               as Export (Generic)
import GHC.Num                    as Export
import GHC.Real                   as Export
import GHC.Show                   as Export

-- Local imports
import qualified Data.ByteString as B
import Data.ByteString.Builder
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Lazy as BL
import Data.ByteString.Unsafe
import Data.Default
import qualified Data.Foldable as F
import qualified Data.HashMap.Strict as H
import qualified Data.HashSet as S
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

-- | @<> := ||@.
-- Simplifies writing bool checks:
-- (\b -> b <= 10 || b == 20 || b >= 30)  <=>  (<=10) <> (==20) <> (>=30)
instance Semigroup Bool where
  (<>) = (||)

instance Default (H.HashMap k v) where
  def = H.empty

instance Default (S.HashSet v) where
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
      | n >= l    = def
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
      | n >= l    = def
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

----------------------
-- Contants

#define CO(label,val) label :: Word64; label = val; {-# INLINE label #-}
CO(defaultMaxTags,32)
CO(defaultMaxIdentifiers,32)
CO(defaultMaxExternalVariables,32)
CO(defaultMaxModuleData,32)
CO(defaultMaxQueuedFiles,64)
#undef CO

-------------------------
-- Keywords

yaraKeywords :: H.HashSet ByteString
yaraKeywords = [
   "all"       , "and"       , "any"      , "ascii"      ,
   "at"        , "condition" , "contains" , "entrypoint" ,
   "false"     , "filesize"  , "for"      , "fullword"   ,
   "global"    , "import"    , "in"       , "include"    ,
   "int16"     , "int16be"   , "int32"    , "int32be"    ,
   "int8"      , "int8be"    , "matches"  , "meta"       ,
   "nocase"    , "not"       , "of"       , "or"         ,
   "private"   , "rule"      , "strings"  , "them"       ,
   "true"      , "uint16"    , "uint16be" , "uint32"     ,
   "uint32be"  , "uint8"     , "uint8be"  , "wide"       ]

isKeyword :: ByteString -> Bool
isKeyword = flip member yaraKeywords

------------------------------------------------------------
-- Misc.

-- | Alias for 'length' of Foldables using the math terminology of 'cardinality'
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

(>>?) :: MonadError e m => m a -> (e -> m a) -> m a
(>>?) = catchError
{-# INLINE (>>?) #-}

asumMap :: (Alternative m, Foldable f) => (a -> m b) -> f a -> m b
asumMap f = foldr ((<|>) . f) empty
