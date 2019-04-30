{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE Rank2Types #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ApplicativeDo #-}

-- |
-- Module      :  Yara.Parsers.Types
-- Copyright   :  David Heras 2018-2019
-- License     :  GPL-3
--
-- Maintainer  :  dheras@protonmail.com
-- Stability   :  experimental
-- Portability :  unknown
--
-- Fundamental YARA parser/data types and
-- based on the Attoparsec library.

module Types
  ( (++)
  , liftA2
  , FilePath
  , Result(..)
  , More(..)
  , Pos(..)
  , Failure
  , Success
  , Env(..)
  , defaultEnv
  , Buffer(..)
  , YaraParser(..)
  , RuleType(..)
  , Identifier
  , Label
  , Value(..)
  , maxArgsTag
  , maxArgsIdentifier
  , maxArgsExternVar
  , maxArgsModuleData
  , fault

  -- Re-exporting. 
  , (<|>)
  ) where

import Prelude hiding (FilePath, (++))
import Control.Applicative hiding (liftA2)
import Control.DeepSeq
import Control.Monad.Reader
import Control.Monad.State.Strict
import Data.ByteString.Char8 (append, pack)
import Data.ByteString.Internal (ByteString(..))
import Data.String
import GHC.Word
import Foreign.ForeignPtr

import qualified Data.Map      as Map
import qualified Data.Sequence as Seq

infixl 5 ++
(++) :: ByteString -> ByteString -> ByteString
(++) = append
{-# INLINE (++) #-}

liftA2 :: (Applicative f) => (a -> b -> c) -> f a -> f b -> f c
liftA2 f a b = do
  x <- a
  !y <- b
  pure $ f x y
{-# INLINE liftA2 #-}

-- GENERAL TYPE & INSTANCES

type FilePath = ByteString

type Identifier = ByteString

type Label = ByteString

data RuleType = Normal | Global | Private | GblPrv deriving Show

instance Semigroup RuleType where
  _       <> GblPrv   = GblPrv
  GblPrv  <> _        = GblPrv
  Global  <> Global   = Global
  Private <> Private  = Private
  Global  <> Private  = GblPrv
  Private <> Global   = GblPrv
  Normal  <> m        = m
  n       <> Normal   = n

instance Semigroup Bool where
  (<>) = (||)

-- BUFFER TYPE

data Buffer = Buf {
    _fp  :: {-# UNPACK #-} !(ForeignPtr Word8)
  , _off :: {-# UNPACK #-} !Int
  , _len :: {-# UNPACK #-} !Int
  , _cap :: {-# UNPACK #-} !Int
  , _gen :: {-# UNPACK #-} !Int
  }

data Result r = Fail ByteString [ByteString] ByteString
              | Partial (ByteString -> Result r)
              | Done ByteString r

instance (Show r) => Show (Result r) where
  showsPrec d ir = showParen (d > 10) $
    case ir of
      (Fail t stk msg) -> shows "Fail" . f t . f stk . f msg
      (Partial _)      -> shows "Partial _"
      (Done t r)       -> shows "Done" . f t . f r
    where f :: Show a => a -> ShowS
          f x = showChar ' ' . showsPrec 11 x

instance (NFData r) => NFData (Result r) where
    rnf (Fail t stk msg) = rnf t `seq` rnf stk `seq` rnf msg
    rnf (Partial _)  = ()
    rnf (Done t r)   = rnf t `seq` rnf r
    {-# INLINE rnf #-}

data More = Complete | Incomplete deriving (Eq, Show)

newtype Pos = Pos { fromPos :: Int } deriving (Eq, Ord, Show, Num)

type Failure r = Buffer -> Pos -> More -> [ByteString] -> ByteString -> Result r

type Success a r = Buffer -> Pos -> More -> a -> Result r

data Value = Value_I Int
           | Value_S ByteString
           | Value_B Bool
           deriving Show

data Env = Env {
    rules             :: !(Map.Map Label FilePath)
  , moduleImports     :: !(Map.Map Label FilePath)
  , target            :: FilePath
  ----
  , externVars        :: !(Map.Map Label Value)
  , moduleData        :: !(Map.Map Label FilePath)
  , onlyTags          :: !(Seq.Seq Label)
  , onlyIdens         :: !(Seq.Seq Label)
  , atomTable         :: Maybe FilePath
  , maxRules          :: Int
  , timeout           :: Int
  , maxStrPerRule     :: Int
  , stackSize         :: Int
  , threads           :: Int
  , fastScan          :: Bool
  , failOnWarnings    :: Bool
  , compiledRules     :: Bool
  , oppositeDay       :: Bool
  , disableWarnings   :: Bool
  , recursivelySearch :: Bool
  , printNumMatches   :: Bool
  , printMetadata     :: Bool
  , printModule       :: Bool
  , printNamespace    :: Bool
  , printStats        :: Bool
  , printStrings      :: Bool
  , printStrLength    :: Bool
  , printTags         :: Bool
  , printVersion      :: Bool
  , printHelp         :: Bool
  } deriving Show

defaultEnv :: Env
defaultEnv = Env {
    rules = Map.empty
  , moduleImports = Map.empty
  , target = ""
  , externVars = Map.empty
  , moduleData = Map.empty
  , onlyTags = Seq.empty
  , onlyIdens = Seq.empty
  , atomTable = Nothing
  , maxRules = 32
  , timeout = 100000
  , maxStrPerRule = 10000
  , stackSize = 16384
  , threads = 1
  , fastScan = True
  , failOnWarnings = False
  , compiledRules = False
  , oppositeDay = False
  , disableWarnings = False
  , recursivelySearch = False
  , printNumMatches = False
  , printMetadata = False
  , printModule = False
  , printNamespace = False
  , printStats = False
  , printStrings = False
  , printStrLength = False
  , printTags = False
  , printVersion = False
  , printHelp = False
  }

maxArgsTag :: Int
maxArgsTag = 32

maxArgsIdentifier :: Int
maxArgsIdentifier = 32

maxArgsExternVar :: Int
maxArgsExternVar = 32

maxArgsModuleData :: Int
maxArgsModuleData = 32

-- YARAPARSER TYPE & INSTANCES

newtype YaraParser a = YaraParser {
  runParser :: forall r. Env -> Buffer -> Pos -> More
                                  -> Failure r -> Success a r -> Result r
  }

instance Functor YaraParser where
    fmap f par = YaraParser $ \e t p m l s ->
      let s' t' p' m' a = s t' p' m' (f a)
      in runParser par e t p m l s'
    {-# INLINE fmap #-}

instance Applicative YaraParser where
  pure v = YaraParser $ \_ b !p m _ s -> s b p m v
  {-# INLINE pure #-}
  (<*>) w b = do
    !f <- w
    f <$> b
  {-# INLINE (<*>) #-}
  m *> k = m >>= \_ -> k
  {-# INLINE (*>) #-}
  x <* y = x >>= \a -> y *> pure a
  {-# INLINE (<*) #-}

instance Alternative YaraParser where
  empty = fail "empty"
  {-# INLINE empty #-}
  (<|>) = mplus
  {-# INLINE (<|>) #-}
  many p = many_p
     where many_p = some_p `mplus` pure []
           some_p = liftA2 (:) p many_p
  {-# INLINE many #-}
  some v = some_v
     where many_v = some_v <|> pure []
           some_v = liftA2 (:) v many_v
  {-# INLINE some #-}

instance Monad YaraParser where
  v >>= k = YaraParser $ \e t !p m l s ->
     let s' t' !p' m' a = runParser (k a) e t' p' m' l s
     in runParser v e t p m l s'
  {-# INLINE (>>=) #-}
  (>>) = (*>)
  {-# INLINE (>>) #-}
  return = pure
  {-# INLINE return #-}
  fail = fault . pack
  {-# INLINE fail #-}

-- Version of "fail" that operates on bytestrings
fault :: ByteString -> YaraParser a
fault err = YaraParser $ \_ t pos more lose _ -> lose t pos more [] msg
   where msg = "Failed parsing: " ++ err

instance MonadPlus YaraParser where
  mzero = fail "mzero"  -- this is creating a circular issue
  {-# INLINE mzero #-}
  mplus f g = YaraParser $ \e t pos more lose suc ->
    let lose' t' _pos' more' _ctx _msg
                 = runParser g e t' pos more' lose suc
    in runParser f e t pos more lose' suc
  {-# INLINE mplus #-}

instance Semigroup (YaraParser a) where
  (<>) = mplus
  {-# INLINE (<>) #-}

instance Monoid (YaraParser a) where
  mempty  = fail "mempty"
  {-# INLINE mempty #-}
  mappend = (<>)
  {-# INLINE mappend #-}

instance MonadState Env YaraParser where
  get = YaraParser $ \e b !p m _ s -> s b p m e
  {-# INLINE get #-}
  put env = let par = return ()
    in YaraParser $ \_ b !p m f s -> runParser par env b p m f s
  {-# INLINE put #-}

instance MonadReader Env YaraParser where
  ask = get
  {-# INLINE ask #-}
  local fun par = YaraParser $ \e b !p m f s -> runParser par (fun e) b p m f s
  {-# INLINE local #-}
  reader fun = YaraParser $ \e b !p m _ s -> s b p m (fun e)
  {-# INLINE reader #-}
