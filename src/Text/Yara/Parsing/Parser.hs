{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE Rank2Types #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# OPTIONS_GHC -funbox-strict-fields #-}
{-# OPTIONS_HADDOCK prune #-}
-- |
-- Module      :  Text.Yara.Parsing.Parser
-- Copyright   :  David Heras 2018-2019
-- License     :  GPL-3
--
-- Maintainer  :  dheras@protonmail.com
-- Stability   :  experimental
-- Portability :  unknown
--
-- Fundamental YARA parser/data types and based on the Attoparsec library.
--
module Text.Yara.Parsing.Parser (
    -- Parser types
    YaraParser(..), Result(..), More(..), Failure, Success, Env(..),

    -- Reporting errors using bytestrings (fail <~> fault)
    fault,

    -- Running the parsers
    (<?>), (<!>), parse, parse_, advance, prompt,
    getPos, posMap, getPosByteString
    ) where

import Prelude hiding (FilePath, length, drop, (++), null)
import Control.Applicative hiding (liftA2)
import Control.DeepSeq
import qualified Control.Monad.Fail as Fail
import Control.Monad.Reader
import Control.Monad.State.Strict
import Data.ByteString hiding (pack, map)
import Data.ByteString.Builder (toLazyByteString, intDec)
import Data.ByteString.Char8 hiding (cons, snoc, map)
import Data.ByteString.Internal (ByteString(..))
import qualified Data.ByteString.Lazy as BL (toStrict)
import Data.Default
import Data.String ()
import Data.Typeable
    -----
import qualified Data.List       as List
import qualified Data.Map.Strict as Map
import qualified Data.Sequence   as Seq
    -----
import Text.Yara.Parsing.Buffer
import Text.Yara.Parsing.Types
import Text.Yara.Shared

-- GENERAL TYPE & INSTANCES

-- | A result type for the YaraParser
data Result r
      -- | Parsing failed
    = Fail ByteString [ByteString] ByteString
      -- | Parsing in-progess /and/
      -- expecting more input
    | Partial (ByteString -> Result r)
      -- | Parsing success
    | Done ByteString r

instance Eq r => Eq (Result r) where
  (Done b1 r1) == (Done b2 r2) = b1 == b2 && r1 == r2
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

-- | To annotate
type Failure r = Buffer -> Env -> [ByteString] -> ByteString -> Result r

-- | To annotate
type Success a r = Buffer -> Env -> a -> Result r

-- YARAPARSER TYPE & INSTANCES

-- | Main parser type
--
-- The type of string parsed is always a bytestring (treated as a stream of bytes).
-- This type is an instance of the following classes:
--
-- * 'Functor' and 'Applicative', which follow the usual definitions.
--
-- * 'Monad', where 'fail' throws an exception (i.e. fails) with an
--   error message. We also provide 'fault', which is used in place of
--   'fail' as it accepts bytestrings.
--
-- * 'MonadPlus', where 'mzero' fails (with no error message) and
--   'mplus' executes the right-hand parser if the left-hand one
--   fails.  When the parser on the right executes, the input is reset
--   to the same state as the parser on the left started with. (In
--   other words, attoparsec is a backtracking parser that supports
--   arbitrary lookahead.)
--
-- * 'Alternative', which follows 'MonadPlus'.
--
-- * 'Default', where 'def := pure ()'
--
-- * 'Semigroup', 'Monoid' To annotate.
--
-- * 'MonadReader' and 'MonadState', where our parser deviates significantly from
--   the 'Data.Attoparsec' core parser, upon which this implimentations is derived
--   from. The parser has access to an 'Env' (short for 'Environment') record that
--   tracks the position and if more input is avialable (identical to how
--   Attoparsec uses these parameters) but also provides access to necessary
--   environmental variables such as known imports, name space, global rules,
--   external variables, ect.
--
--   This is a current compromise/test.
--
newtype YaraParser a = YaraParser {
    runParser ::
       forall r. Buffer       -- ^ The bytestring currently being parsed
              -> Env          -- ^ Current enviroment during parsing
              -> Failure r    -- ^ Handles a unsuccessful parsing
              -> Success a r  -- ^ Handles a successful parsing
              -> Result r     -- ^ Outcome of running the parser
    } deriving Typeable

instance Functor YaraParser where
  fmap f par = YaraParser $ \b e l s ->
    runParser par b e l (\b_ e_ a -> s b_ e_ $ f a)
  {-# INLINE fmap #-}

instance Applicative YaraParser where
  pure v = YaraParser $ \b !e _ s -> s b e v
  {-# INLINE pure #-}
  w <*> b = do
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
     where many_p = some_p `mplus` def
           some_p = liftA2 (:) p many_p
  {-# INLINE many #-}
  some v = some_v
     where many_v = some_v <|> def
           some_v = liftA2 (:) v many_v
  {-# INLINE some #-}

instance Monad YaraParser where
  v >>= k = YaraParser $ \b !e l s ->
    runParser v b e l (\t_ e_ a -> runParser (k a) t_ e_ l s)
  {-# INLINE (>>=) #-}
  (>>) = (*>)
  {-# INLINE (>>) #-}
  return = pure
  {-# INLINE return #-}

instance MonadPlus YaraParser where
  mzero = fault "mzero"
  {-# INLINE mzero #-}
  mplus f g = YaraParser $ \b e l s ->
    runParser f b e (\nb _ _ _ -> runParser g nb e l s) s
  {-# INLINE mplus #-}

instance Semigroup a => Semigroup (YaraParser a) where
  (<>) = liftA2 (<>)
  {-# INLINE (<>) #-}

instance Monoid a => Monoid (YaraParser a) where
  mempty  = pure mempty
  {-# INLINE mempty #-}
  mappend = (<>)
  {-# INLINE mappend #-}

-- | Version of 'fail' that uses bytestrings instead
fault :: ByteString -> YaraParser a
fault m = do
  p <- getPosByteString
  YaraParser $ \b !e l _ ->
    l b e [] $ "[" ++ p ++ "] Failed parsing! " ++ m
{-# INLINE fault #-}

instance Fail.MonadFail YaraParser where
  fail = fault . pack
  {-# INLINE fail #-}

instance MonadState Env YaraParser where
  get = YaraParser $ \b !e _ s -> s b e e
  {-# INLINE get #-}
  put e = YaraParser $ \b _ l s -> runParser def b e l s
  {-# INLINE put #-}

instance MonadReader Env YaraParser where
  ask = get
  {-# INLINE ask #-}
  local fun par = YaraParser $ \b !e l s -> runParser par b (fun e) l s
  {-# INLINE local #-}
  reader fun = YaraParser $ \b !e _ s -> s b e (fun e)
  {-# INLINE reader #-}

instance Default a => Default (YaraParser a) where
  def = pure def

--- RUNNING A PARSER

-- | Return current position.
getPos :: YaraParser Int
getPos = reader position
{-# INLINE getPos #-}

-- | Return current target file
getTarget :: YaraParser FilePath
getTarget = reader targetFile
{-# INLINE getTarget #-}

-- | 'Read' current position as a ByteString.
-- Used for returning location in printable format.
getPosByteString :: YaraParser ByteString
getPosByteString = reader (int2bs.position)
  where
    -- @int2bs@ converts an int to a bytestring.
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
{-# INLINE getPosByteString #-}

-- | Name the parser, in the event failure occurs.
infixr 0 <?>
(<?>) :: YaraParser a -> ByteString -> YaraParser a
par <?> msg = YaraParser $ \b e l s ->
   runParser par b e (\b_ e_ s_ m_ -> l b_ e_ (msg:s_) m_) s
{-# INLINE (<?>) #-}

-- | Name the module of the parser, in case failure occurs.
--
-- Testing it out ----> may not use or may remove later.
-- The idea is that imported modules can be given a label at the begining
-- instead of rewriting the module name everytime
infixl 0 <!>
(<!>) :: ByteString -> YaraParser a -> YaraParser a
msg <!> par = YaraParser $ \b e l s ->
   runParser par b e (\b_ e_ s_ m_ -> l b_ e_ s_ (msg ++ m_)) s
{-# INLINE (<!>) #-}

posMap :: (Int -> Int) -> Env -> Env
posMap f e = e { position = p } where p = f $ position e
{-# INLINE posMap #-}

-- | Advance the position pointer. Use very /carefully/ since its unnatural
-- in the wrong situations.
advance :: Int -> YaraParser ()
advance n = YaraParser $ \b e _ s -> s b (posMap (+n) e) ()
{-# INLINE advance #-}

-- | Run a parser.
parse :: YaraParser a  -- ^ Parser to run
      -> Env           -- ^ Env to run with (ie starting state)
      -> ByteString    -- ^ ByteString to parse
      -> Result a
parse p env b =
  runParser p (toBuffer b)
              (env { position = 0, moreInput = Incomplete })
              (\t e -> Fail (bufferUnsafeDrop (position e) t))
              (\t e -> Done (bufferUnsafeDrop (position e) t))
{-# INLINE parse #-}

-- | Parse with default environment settings.
parse_ :: YaraParser a -> ByteString -> Result a
parse_ p = parse p def
{-# INLINE parse_ #-}

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
  , targetFile       :: !FilePath
  , externVars       :: !(Map.Map Label Value)
  , moduleData       :: !(Map.Map Label FilePath)
  , onlyTags         :: !(Seq.Seq Label)
  , onlyIdens        :: !(Seq.Seq Label)
  , atomTable        :: !(Maybe FilePath)
  , maxRules         :: Int
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
  }

instance Show Env where
  show Env{..} =
    List.unlines $ "Env" : List.map (("\t" List.++) . List.intercalate " = \t") [
      ["pos", show position]
    , ["more", show moreInput]
    , ["source files" , show sourceFiles]
    , ["rules", show  moduleImports]
    , ["target", show targetFile]
    , ["externVars", show externVars]
    , ["moduleData", show moduleData]
    , ["onlyTags", show onlyTags]
    , ["onlyIdens", show onlyIdens]
    , ["atomTable", show  atomTable]
    , ["maxRules", show maxRules]
    , ["timeout", show timeout]
    , ["maxStrPerRule", show maxStrPerRule]
    , ["stackSize", show stackSize]
    , ["threads", show threads ]
    , ["fastScan", show fastScan]
    , ["failOnWarnings", show failOnWarnings]
    , ["compiledRules", show compiledRules]
    , ["oppositeDay", show oppositeDay]
    , ["disableWarnings", show disableWarnings]
    , ["recursivelySearch", show recursiveSearch]
    , ["printNumMatches", show printNumMatches ]
    , ["printMetadata", show printMetadata]
    , ["printModule", show printModule]
    , ["printNamespace", show  printNamespace]
    , ["printStats", show printStats]
    , ["printStrings", show printStrings]
    , ["printStrLength", show printStrLength]
    , ["printTags", show printTags]
    , ["printVersion", show printVersion]
    , ["printHelp", show printHelp]
    ]

-- | A default set of environmental variables.
instance Default Env where
  def =  Env {
      position = 0
    , moreInput = Incomplete
    , sourceFiles = Map.empty
    , moduleImports = Map.empty
    , targetFile = ""
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
