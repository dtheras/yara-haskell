{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE Rank2Types #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE CPP#-}
{-# OPTIONS_GHC -funbox-strict-fields #-}
{-# OPTIONS_HADDOCK prune #-}
-- |
-- Module      :  Yara.Parsing.Parser
-- Copyright   :  David Heras 2018-2019
-- License     :  GPL-3
--
-- Maintainer  :  dheras@protonmail.com
-- Stability   :  experimental
-- Portability :  unknown
--
-- Fundamental YARA parser/data types and based on the Attoparsec library.
--
module Yara.Parsing.Parser (
    -- Parser types
    YP(..), Result(..), More(..), Failure, Success, Env(..),

    -- Reporting errors using bytestrings (fail <~> fault)
    fault,

    -- Running the parsers
    (<?>), (<!>), parse, parse_, advance, prompt, posMap,
    forkA,

    getPosByteString, getPos, getStrings, getInscopeRules,
    getFilename, getFiletype

    ) where

import Prelude hiding (FilePath, length, drop, (++), null)
import Control.Applicative hiding (liftA2)
import Control.DeepSeq
import qualified Control.Monad.Fail as Fail
import Control.Monad.Reader
import Control.Monad.State.Strict
import Data.ByteString hiding (pack, map)
import Data.ByteString.Char8 hiding (cons, snoc, map)
import Data.ByteString.Internal (ByteString(..))
import Data.Default
import Data.String () -- Only need typeclass imported
import Data.Typeable
import qualified Data.Map.Strict as Map
import qualified Data.Set        as Set
    -----
import Yara.Parsing.Buffer
import Yara.Parsing.Types
import Yara.Shared

-- GENERAL TYPE & INSTANCES

-- | A result type for the YP
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
      (Fail t stk msg) -> shows "Fail" . toShows t . toShows stk . toShows msg
      (Partial _)      -> shows "Partial _"
      (Done t r)       -> shows "Done" . toShows t . toShows r

instance (NFData r) => NFData (Result r) where
    rnf (Fail t stk msg) = rnf t `seq` rnf stk `seq` rnf msg
    rnf (Partial _)  = ()
    rnf (Done t r)   = rnf t `seq` rnf r
    {-# INLINE rnf #-}

instance Functor Result where
  fmap f (Done b a) = Done b $ f a
  fmap _ r          = r

-- | To annotate
data Env = Env {
     position     :: !Pos
  -- ^ Position in buffer.
  ,  more         :: !More
  -- ^ More input available?
  ,  imports      :: !(Set.Set ByteString)
  -- ^ Set of imported modules
  ,  externalVars :: !(Map.Map ByteString  Value)
  -- ^ Set of externally defined variables
  ,  localStrings :: !(Map.Map ByteString Pattern)
  -- ^ Stored as a follows:
  -- 'ByteString' stores the string name
  -- 'Pattern' stores the string, regex or byte with the set of modifiers
  ,  inscopeRules :: !(Set.Set ByteString)
  ,  filename     :: ByteString
  ,  filetype     :: ByteString
  } deriving (Show, Eq)

defEnv :: Env
defEnv = Env {
    position = 0
  , more = Incomplete
  , imports = Set.empty
  , externalVars = Map.empty
  , localStrings = Map.empty
  , inscopeRules = Set.empty
  , filename = ""
  , filetype = ""
  }

-- | More input avialable?
data More = Complete | Incomplete deriving (Eq, Show)

-- | To annotate
type Failure r = Buffer -> Env -> [ByteString] -> ByteString -> Result r

-- | To annotate
type Success a r = Buffer -> Env -> a -> Result r

-- YP TYPE & INSTANCES

-- | Main parser type
--
-- The type of string parsed is always a bytestring (treated as a stream of bytes).
-- This type is an instance of the following classes:
--
--  o  'Functor' and 'Applicative', which follow the usual definitions.
--
--  o  'Monad', where 'fail' throws an exception (i.e. fails) with an
--     error message. We also provide 'fault', which is used in place of
--     'fail' as it accepts bytestrings.
--
--  o  'MonadPlus', where 'mzero' fails (with no error message) and
--     'mplus' executes the right-hand parser if the left-hand one
--     fails.  When the parser on the right executes, the input is reset
--     to the same state as the parser on the left started with. (In
--     other words, attoparsec is a backtracking parser that supports
--     arbitrary lookahead.)
--
--  o  'Alternative', which follows 'MonadPlus'.
--
--  o  'Default', where 'def := pure ()'
--
--  o  'Semigroup', 'Monoid' To annotate.
--
--  o  'MonadReader' and 'MonadState', where our parser deviates significantly
--     from the 'Data.Attoparsec' core parser, upon which this implimentations
--     is derived from. The parser has access to an 'Env' (short for
--     'Environment') record that tracks the position and if more input is
--     avialable (identical to how Attoparsec uses these parameters) but also
--     provides access to necessary environmental variables such as known
--     imports, name space, global rules, external variables, ect.
--
-- This is a current compromise/test.
--
newtype YP a = YP {
    runParser ::
       forall r. Buffer       -- ^ The bytestring currently being parsed
              -> Env          -- ^ Current enviroment during parsing
              -> Failure r    -- ^ Handles a unsuccessful parsing
              -> Success a r  -- ^ Handles a successful parsing
              -> Result r     -- ^ Outcome of running the parser
    } deriving Typeable

instance Functor YP where
  fmap f par = YP $ \b e l s -> f <$> runParser par b e l s
  {-# INLINE fmap #-}

instance Applicative YP where
  pure v = YP $ \b !e _ s -> s b e v
  {-# INLINE pure #-}
  w <*> b = do
    !f <- w
    f <$> b
  {-# INLINE (<*>) #-}
  m *> k = m >>= \_ -> k
  {-# INLINE (*>) #-}
  x <* y = x >>= \a -> y $> a
  {-# INLINE (<*) #-}

instance Default a => Default (YP a) where
  def = pure def

instance Alternative YP where
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

instance Monad YP where
  v >>= k = YP $ \b !e l s ->
    runParser v b e l (\t_ e_ a -> runParser (k a) t_ e_ l s)
  {-# INLINE (>>=) #-}
  (>>) = (*>)
  {-# INLINE (>>) #-}
  return = pure
  {-# INLINE return #-}

instance MonadPlus YP where
  mzero = fault "mzero"
  {-# INLINE mzero #-}
  mplus f g = YP $ \b e l s ->
    runParser f b e (\nb _ _ _ -> runParser g nb e l s) s
  {-# INLINE mplus #-}

instance Semigroup a => Semigroup (YP a) where
  (<>) = liftA2 (<>)
  {-# INLINE (<>) #-}

instance Monoid a => Monoid (YP a) where
  mempty  = pure mempty
  {-# INLINE mempty #-}
  mappend = (<>)
  {-# INLINE mappend #-}

-- | Version of 'fail' that uses bytestrings instead
-- It also appends the current position to the begining of the message.
fault :: ByteString -> YP a
fault m = do
  p <- getPosByteString
  YP $ \b !e l _ ->
    l b e [] $ "[" ++ p ++ "] Failed parsing! " ++ m
{-# INLINE fault #-}

instance Fail.MonadFail YP where
  fail = fault . pack
  {-# INLINE fail #-}

instance MonadState Env YP where
  get = YP $ \b !e _ s -> s b e e
  {-# INLINE get #-}
  put e = YP $ \b _ l s -> runParser (pure ()) b e l s
  {-# INLINE put #-}

instance MonadReader Env YP where
  ask = get
  {-# INLINE ask #-}
  local fun par = YP $ \b !e l s -> runParser par b (fun e) l s
  {-# INLINE local #-}
  reader fun = YP $ \b !e _ s -> s b e (fun e)
  {-# INLINE reader #-}


--- RUNNING A PARSER

#define GO(n,T,s) n :: YP (T); n = reader s; {-# INLINE n #-}
GO(getPos,Int,position)
GO(getStrings,Map.Map ByteString Pattern,localStrings)
GO(getInscopeRules,Set.Set ByteString,inscopeRules)
GO(getFilename,ByteString,filename)
GO(getFiletype,ByteString,filetype)
-- | 'getPosByteString' return position as a ByteString.
-- Used for printing location within buffer.
GO(getPosByteString,ByteString,(int2bs.position))
#undef GO


-- | Name the parser, in the event failure occurs.
infixr 0 <?>
(<?>) :: YP a -> ByteString -> YP a
par <?> msg = YP $ \b e l s ->
   runParser par b e (\b_ e_ s_ m_ -> l b_ e_ (msg:s_) m_) s
{-# INLINE (<?>) #-}

-- | Name the module of the parser, in case failure occurs.
--
-- Testing it out ----> may not use or may remove later.
-- The idea is that imported modules can be given a label at the begining
-- instead of rewriting the module name everytime
infixl 0 <!>
(<!>) :: ByteString -> YP a -> YP a
msg <!> par = YP $ \b e l s ->
   runParser par b e (\b_ e_ s_ m_ -> l b_ e_ s_ (msg ++ m_)) s
{-# INLINE (<!>) #-}

posMap :: (Int -> Int) -> Env -> Env
posMap f e = e { position = p } where p = f $ position e
{-# INLINE posMap #-}

-- | Advance the position pointer. Use very /carefully/ since its unnatural
-- in the wrong situations.
advance :: Int -> YP ()
advance n = YP $ \b e _ s -> s b (posMap (+n) e) ()
{-# INLINE advance #-}

-- | Run a parser.
parse :: YP a  -- ^ Parser to run
      -> Env           -- ^ Env to run with (ie starting state)
      -> ByteString    -- ^ ByteString to parse
      -> Result a
parse p env b =
  runParser p (toBuffer b)
              (env { position = 0, more = Incomplete })
              (\t e -> Fail (bufferUnsafeDrop (position e) t))
              (\t e -> Done (bufferUnsafeDrop (position e) t))
{-# INLINE parse #-}

-- | Parse with default environment settings.
parse_ :: YP a -> ByteString -> Result a
parse_ p = parse p defEnv
{-# INLINE parse_ #-}

-- | Ask for input.  If we receive any, pass the augmented input to a
-- success continuation, otherwise to a failure continuation.
prompt :: (Buffer -> Env -> Result r)
       -> (Buffer -> Env -> Result r)
       -> Buffer -> Env -> Result r
prompt l s b e = Partial $ \bs -> if null bs
  then l b (e { more = Complete })
  else s (bufferPappend b bs) (e { more = Incomplete })
{-# INLINE prompt #-}

-- | @forkParsing@
-- Basically, written as a monadic if-then-else but with the order reverses
-- since a false case is usually a simple return and a True case is a continue
-- parsing.
--
-- Think of it as "if need byte is this, go left (or done), else go right and
-- continue."
forkA :: Applicative f
      => Bool
      -> f a     -- ^ If False, execute this action
      -> f a     -- ^ If True, execute this action
      -> f a
forkA b u v = if b then v else u
{-# INLINE forkA #-}
{-# SPECIALIZE forkA :: Bool -> YP a -> YP a -> YP a #-}




data ParsingError

failWithError :: ParsingError -> YP a
failWithError = undefined
