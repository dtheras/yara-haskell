{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE Rank2Types #-}
{-# LANGUAGE RecordWildCards #-}
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
    -- * Parsing types
      Yp(..)
    , Result(..)
    , More(..)
    , Failure
    , Success
    , Env(..)

    -- * Flag parsing error
    , fault

    -- * Writing combinators
    , (<?>)
    , (<!>)

    , advance
    , prompt
    , posMap
    , forkA
    , getPosByteString
    , getPos
    , getStrings
    , getInscopeRules
    , getFilename
    , getFiletype

    -- * Running parsers
    , parse
    , parse_

    ) where

import Yara.Prelude hiding (pack)
import Yara.Parsing.Buffer
import Yara.Parsing.Types

import Control.DeepSeq
import Data.ByteString.Char8 hiding (null, cons, snoc, map)
import Data.ByteString.Internal (ByteString(..))
import Data.Default
import Data.String () -- Only need typeclass imported
import Data.Typeable
import qualified Data.Map.Strict as Map
import qualified Data.Set        as Set

data ExceptionCode
   -- Preproccessing-specific error codes
   = UnterminatedInclude
   | FileDoesNotExist
   | ExpectedFilePathMissing
   | UnrecognizedPragma
   | IncorrectlyAlignedPragma
   | UnterminatedStringLiteral
   | UnclosedParenthesis
   | LonelyOpenParen
   | LonelyClosedParen
   | GenericException
   deriving Show

data ParseException = ParseException {
    exp_filepath :: FilePath      -- ^ Filepath of source file being processed
  , exp_message  :: ByteString    -- ^ Reporting message
  , exp_at       :: Pos           -- ^ Location (in source file) exception was thrown
  , exp_code     :: ExceptionCode -- ^ Cde indicating the type of exception thrown
  }

prettyPrintException :: ParseException -> ByteString
prettyPrintException (ParseException f m p c) = stamp ++ prettyShowExceptionCode
  where
    stamp = f ++ "(" ++ int2bs.position p ++ "): "
    showError = concat $ case c of
      UinatedInclude      -> ["unterminated include pragma '", msg, "' found in '", fp, "'"]
      HeaderFileDoesNotExist   -> ["included header file '", msg, "' does not exist"]
      HeaderPathMissing        -> [""]
      UnrecognizedPragma       -> ["unrecognized pragma '", msg]
      IncorrectlyAlignedPragma -> undefined
      GenericException         -> msg

instance Show ParseException where
  show = unpack . prettyShowException

-- | A result type for the YP
data Result r
      -- | Parsing failed
    = Fail ByteString [ByteString] ParseException
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
      (Partial _)      -> shows "Partial _"
      (Done t r)       -> shows "Done" . toShows t . toShows r
      (Fail t stk exp) -> shows "" . toShows t . toShows exp . toShows stk

instance (NFData r) => NFData (Result r) where
    rnf (Fail t stk exp) = rnf t `seq` rnf stk `seq` rnf exp
    rnf (Partial _)  = ()
    rnf (Done t r)   = rnf t `seq` rnf r
    {-# INLINE rnf #-}

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
  -- ^
  ,  filepath     :: ByteString
  -- ^ The filepath of the file being parsed
  ,  filetype     :: ByteString
  -- ^
  } deriving (Show, Eq)

defEnv :: Env
defEnv = Env {
    position = 0
  , more = Incomplete
  , imports = Set.empty
  , externalVars = Map.empty
  , localStrings = Map.empty
  , inscopeRules = Set.empty
  , filepath = ""
  , filetype = ""
  }

-- | More input avialable?
data More = Complete | Incomplete deriving (Eq, Show)

-- | To annotate
type Failure r = Buffer -> Env -> [ByteString] -> ParseException -> Result r

-- | To annotate
type Success a r = Buffer -> Env -> a -> Result r

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
newtype Yp a = YP {
    runParser ::
       forall r. Buffer       -- ^ The bytestring currently being parsed
              -> Env          -- ^ Current enviroment during parsing
              -> Failure r    -- ^ Handles a unsuccessful parsing
              -> Success a r  -- ^ Handles a successful parsing
              -> Result r     -- ^ Outcome of running the parser
    } deriving Typeable

instance Functor Yp where
  fmap f par = YP $ \b e l s ->
    let s_ b_ e_ a_ = s b_ e_ (f a_) in runParser par b e l s_
  {-# INLINE fmap #-}

instance Applicative Yp where
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

instance Default a => Default (Yp a) where
  def = pure def

-- | Version of 'fail' that uses bytestrings instead.
--
-- It fails with exception code 'GenericException.'
--
-- Rule of thumb when throw exceptions:
--
-- a) If it is a general parsing failure, use 'fault'
--
-- b)
--
-- c) Avoid `throwError`
--
fault :: ExceptionCode -> ByteString -> Yp a
fault exp msg = Yp $ \b e l _ ->
   let fp = filepath e
       po = position e
   in l b e [] $ ParseException fp msg po exp
{-# INLINE fault #-}

fault_ :: ByteString -> Yp a
fault_ msg = Yp $ \b e l _ ->
   let fp = filepath e
       po = position e
   in l b e [] $ ParseException fp msg po GenericException
{-# INLINE fault_ #-}

-- | With the way the parser is written, errors cannot be "caught." That is correct
-- since (a) failed parsers always backtrack and (b) generally parsing errors are
-- not something that can be caught .
instance MonadError ExceptionCode Yp where
  throwError ex = fault ex "Error thrown (MonadError)"
  catchError p f = YP $ \b e l s ->
    let res = runParser p b e l s
    in case res of
      (Fail rst qs exp)  -> f exp
      _                  -> res

instance Alternative Yp where
  empty = fault_ "empty (Alternative)"
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

instance Monad Yp where
  v >>= k = YP $ \b !e l s ->
    runParser v b e l (\t_ e_ a -> runParser (k a) t_ e_ l s)
  {-# INLINE (>>=) #-}
  (>>) = (*>)
  {-# INLINE (>>) #-}
  return = pure
  {-# INLINE return #-}

instance MonadPlus Yp where
  mzero = fault_ "mzero"
  {-# INLINE mzero #-}
  mplus f g = YP $ \b e l s ->
    runParser f b e (\nb _ _ _ -> runParser g nb e l s) s
  {-# INLINE mplus #-}

instance Semigroup a => Semigroup (Yp a) where
  (<>) = liftA2 (<>)
  {-# INLINE (<>) #-}

instance Monoid a => Monoid (Yp a) where
  mempty  = pure mempty
  {-# INLINE mempty #-}
  mappend = (<>)
  {-# INLINE mappend #-}

-- -----------------------------------------------------------------------------
-- Exception Throwing


instance MonadState Env Yp where
  get = YP $ \b !e _ s -> s b e e
  {-# INLINE get #-}
  put e = YP $ \b _ l s -> runParser (pure ()) b e l s
  {-# INLINE put #-}

instance MonadReader Env Yp where
  ask = get
  {-# INLINE ask #-}
  local fun par = YP $ \b !e l s -> runParser par b (fun e) l s
  {-# INLINE local #-}
  reader fun = YP $ \b !e _ s -> s b e (fun e)
  {-# INLINE reader #-}

#define GO(n,T,s) n :: Yp (T); n = reader s; {-# INLINE n #-}
GO(getPos,Int,position)
GO(getStrings,Map.Map ByteString Pattern,localStrings)
GO(getInscopeRules,Set.Set ByteString,inscopeRules)
GO(getFilepath,FilePath,filepath)
GO(getFiletype,ByteString,filetype)
#undef GO

-- | Name the parser, in the event failure occurs.
infixr 0 <?>
(<?>) :: Yp a -> ByteString -> Yp a
par <?> msg = YP $ \b e l s ->
   runParser par b e (\b_ e_ s_ m_ -> l b_ e_ (msg:s_) m_) s
{-# INLINE (<?>) #-}

-- | Name the module of the parser, in case failure occurs.
--
-- Testing it out ----> may not use or may remove later.
-- The idea is that imported modules can be given a label at the begining
-- instead of rewriting the module name everytime
infixl 0 <!>
(<!>) :: ByteString -> Yp a -> Yp a
msg <!> par = YP $ \b e l s ->
   runParser par b e (\b_ e_ s_ m_ -> l b_ e_ s_ (msg ++ m_)) s
{-# INLINE (<!>) #-}

posMap :: (Int -> Int) -> Env -> Env
posMap f e = e { position = p } where p = f $ position e
{-# INLINE posMap #-}

-- | Advance the position pointer. Use very /carefully/ since its unnatural
-- in the wrong situations.
advance :: Int -> Yp ()
advance n = YP $ \b e _ s -> s b (posMap (+n) e) ()
{-# INLINE advance #-}

-- | Run a parser.
parse :: Yp a  -- ^ Parser to run
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
parse_ :: Yp a -> ByteString -> Result a
parse_ p = parse p defEnv
{-# INLINE parse_ #-}

-- | Ask for input.  If we receive any, pass the augmented input to a
-- success continuation, otherwise to a failure continuation.
prompt :: (Buffer -> Env -> Result r)
       -> (Buffer -> Env -> Result r)
       -> Buffer -> Env -> Result r
prompt l s b e = Partial $ \bs -> if isEmpty bs
  then l b (e { more = Complete })
  else s (bufferPappend b bs) (e { more = Incomplete })
{-# INLINE prompt #-}

