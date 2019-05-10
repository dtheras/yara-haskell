{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE Rank2Types #-}
{-# LANGUAGE MultiParamTypeClasses #-}

-- |
-- Module      :  Yara.Parsers.Parser
-- Copyright   :  David Heras 2018-2019
-- License     :  GPL-3
--
-- Maintainer  :  dheras@protonmail.com
-- Stability   :  experimental
-- Portability :  unknown
--
-- Fundamental YARA parser/data types and
-- based on the Attoparsec library.

module Parser
  ( FilePath
  , Result(..)
  , More(..)
  , Failure
  , Success
  , Env(..)
  , defaultEnv
  , YaraParser(..)
  , Identifier
  , Label
  , Value(..)
  , maxArgsTag
  , maxArgsIdentifier
  , maxArgsExternVar
  , maxArgsModuleData
  , fault
  , (<|>)
  , parse
  , parseDef
  , advance
  , prompt
  , posMap
  ) where

import Prelude hiding (map, FilePath, length, drop, (++), null)
import Control.Applicative hiding (liftA2)
import Control.DeepSeq
import Control.Monad.Reader
import Control.Monad.State.Strict
import Data.ByteString hiding (pack)--(cons, snoc)
import Data.ByteString.Char8 hiding (map, cons, snoc)
import Data.ByteString.Internal (ByteString(..))
import Data.String ()
import GHC.Word
import qualified Data.Map      as Map
import qualified Data.Sequence as Seq
import Buffer
import Types
import Utilities

-- GENERAL TYPE & INSTANCES

data Result r = Fail ByteString [ByteString] ByteString
              | Partial (ByteString -> Result r)
              | Done ByteString r

instance Eq r => Eq (Result r) where
  (Done b1 r1) == (Done b2 r2) = (b1 == b2) && (r1 == r2)
  _            == _            = False

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

-- | More input avialable?
data More = Complete | Incomplete deriving (Eq, Show)

type Failure r = Buffer -> Env -> [ByteString] -> ByteString -> Result r

type Success a r = Buffer -> Env -> a -> Result r

-- YARAPARSER TYPE & INSTANCES

-- | To annotate
newtype YaraParser a = YaraParser {
  runParser :: forall r. Buffer -> Env -> Failure r -> Success a r -> Result r
  }

instance Functor YaraParser where
  fmap f par = YaraParser $ \b e l s ->
    runParser par b e l (\b_ e_ a -> s b_ e_ $ f a)
  {-# INLINE fmap #-}

instance Applicative YaraParser where
  pure v = YaraParser $ \b !e _ s -> s b e v
  {-# INLINE pure #-}
  (<*>) w b = do
    !f <- w
    f <$> b
  {-# INLINE (<*>) #-}
  m *> k = m >>= \_ -> k
  {-# INLINE (*>) #-}
  x <* y = x >>= \a -> y $> a
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
  v >>= k = YaraParser $ \b !e l s ->
     runParser v b e l (\t_ e_ a_ -> runParser (k a_) t_ e_ l s)
  {-# INLINE (>>=) #-}
  (>>) = (*>)
  {-# INLINE (>>) #-}
  return = pure
  {-# INLINE return #-}
  fail = fault . pack
  {-# INLINE fail #-}

-- | Version of 'fail' that uses bytestrings instead
fault :: ByteString -> YaraParser a
fault err = YaraParser $ \b !e l _ -> l b e [] $ "Failed parsing: " ++ err

instance MonadPlus YaraParser where
  mzero = fail "mzero"
  {-# INLINE mzero #-}
  mplus f g = YaraParser $ \b e l s ->
    runParser f b e (\nb _ _ _ -> runParser g nb e l s) s
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
  get = YaraParser $ \b !e _ s -> s b e e
  {-# INLINE get #-}
  put env = let par = return ()
    in YaraParser $ \b !e l s -> runParser par b env l s
  {-# INLINE put #-}

instance MonadReader Env YaraParser where
  ask = get
  {-# INLINE ask #-}
  local fun par = YaraParser $ \b !e l s -> runParser par b (fun e) l s
  {-# INLINE local #-}
  reader fun = YaraParser $ \b !e _ s -> s b e (fun e)
  {-# INLINE reader #-}

--- RUNNING A PARSER

-- Do not export 'movePos' beyond parser folder, internal parser use only.
posMap :: (Int -> Int) -> Env -> Env
posMap f e = e { position = p } where p = f $ position e
{-# INLINE posMap #-}

-- | Run a parser
parse :: YaraParser a
      -- ^ Parser to run
      -> Env
      -- ^ Env to run with (ie starting state)
      -> ByteString
      -- ^ ByteString to parse
      -> Result a
parse p env b =
  runParser p (toBuffer b)
              (env { position = 0, moreInput = Incomplete })
              (\t e -> Fail (bufferUnsafeDrop (position e) t))
              (\t e -> Done (bufferUnsafeDrop (position e) t))
{-# INLINE parse #-}

-- | Parse with defaults sets
parseDef :: YaraParser a -> ByteString -> Result a
parseDef p = parse p defaultEnv
{-# INLINE parseDef #-}

-- | Advance the position pointer
advance :: Int -> YaraParser ()
advance n = YaraParser $ \b e _ s -> s b (posMap (+n) e) ()
{-# INLINE advance #-}

-- | Ask for input.  If we receive any, pass the augmented input to a
-- success continuation, otherwise to a failure continuation.
prompt :: (Buffer -> Env -> Result r)
       -> (Buffer -> Env -> Result r)
       -> Buffer -> Env -> Result r
prompt l s b e = Partial $ \bs -> if null bs
  then l b (e { moreInput = Complete })
  else s (bufferPappend b bs) (e { moreInput = Incomplete })
{-# INLINE prompt #-}

-- | To annotate
data Env = Env {
    position         :: !Pos
  , moreInput        :: !More
  , sourceFiles      :: !(Map.Map Label FilePath)
  , moduleImports    :: !(Map.Map Label FilePath)
  , targetFilepath   :: !FilePath
  , externVars       :: !(Map.Map Label Value)
  , moduleData       :: !(Map.Map Label FilePath)
  , onlyTags         :: !(Seq.Seq Label)
  , onlyIdens        :: !(Seq.Seq Label)
  , atomTable        :: !(Maybe FilePath)
  , maxRules         :: Word8
  , timeout          :: Int
  , maxStrPerRule    :: Int
  , stackSize        :: Int
  , threads          :: Int
  , fastScan         :: Bool
  , failOnWarnings   :: Bool
  , compiledRules    :: Bool
  , oppositeDay      :: Bool
  , disableWarnings  :: Bool
  , recursiveSearch  :: Bool
  , printNumMatches  :: Bool
  , printMetadata    :: Bool
  , printModule      :: Bool
  , printNamespace   :: Bool
  , printStats       :: Bool
  , printStrings     :: Bool
  , printStrLength   :: Bool
  , printTags        :: Bool
  , printVersion     :: Bool
  , printHelp        :: Bool
  } deriving Show

-- | A default set of environmental variables.
defaultEnv :: Env
defaultEnv = Env {
    position = 0
  , moreInput = Incomplete
  , sourceFiles = Map.empty
  , moduleImports = Map.empty
  , targetFilepath = ""
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
  , recursiveSearch = False
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















{-


-- | Use to get position of buffer
-- Allows access to view without exposing record name.
pos :: Env -> Int
pos = position
{-# INLINE position #-}

-- | Use to get whether more input is available
-- Allows access to view without exposing record name.
more :: Env -> More
more = moreInput
{-# INLINE more #-}



printEnv :: Env -> ByteString
printEnv e = Data.ByteString.Char8.unlines $ "Env" : Prelude.map (("\t"++) . (intercalate " = \t")) 
    [ ["pos", showP $ position e]
    , ["more", showP $ _more e]
    , ["rules", showP $ moduleImports e]
    , ["target", showP $ target e]
    , ["externVars", showP $ externVars e]
    , ["moduleData", showP $ moduleData e]
    , ["onlyTags", showP $ onlyTags e]
    , ["onlyIdens", showP $ onlyIdens e]
    , ["atomTable", showP $ atomTable e]
    , ["maxRules", showP $ maxRules e]
    , ["timeout", showP $ timeout e]
    , ["maxStrPerRule", showP $ maxStrPerRule e]
    , ["stackSize", showP $ stackSize e]
    , ["threads", showP $ threads e]
    , ["fastScan", showP $ fastScan e]
    , ["failOnWarnings", showP $ failOnWarnings e]
    , ["compiledRules", showP $ compiledRules e]
    , ["oppositeDay", showP $ oppositeDay e]
    , ["disableWarnings", showP $ disableWarnings e]
    , ["recursivelySearch", showP $ recursivelySearch e]
    , ["printNumMatches", showP $ printNumMatches e]
    , ["printMetadata", showP $ printMetadata e]
    , ["printModule", showP $ printModule e]
    , ["printNamespace", showP $ printNamespace e]
    , ["printStats", showP $ printStats e]
    , ["printStrings", showP $ printStrings e]
    , ["printStrLength", showP $ printStrLength e]
    , ["printTags", showP $ printTags e]
    , ["printVersion", showP $ printVersion e]
    , ["printHelp", showP $ printHelp e]
    ] where showP = pack . show
-}
