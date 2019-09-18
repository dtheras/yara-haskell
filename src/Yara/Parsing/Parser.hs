{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE Rank2Types #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# OPTIONS_GHC -funbox-strict-fields #-}
{-# OPTIONS_HADDOCK prune             #-}
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
module Yara.Parsing.Parser where

import Yara.Prelude
import Yara.Parsing.Buffer
import Yara.Parsing.AST

import Data.Map.Strict hiding (take)
import Data.String () -- Only need typeclass instances
import Data.Typeable

data ExceptionCode
   = UnterminatedInclude
   -- ^
   | FileDoesNotExist
   -- ^
   | ExpectedFilePathMissing
   -- ^
   | UnrecognizedPragma
   -- ^
   | IncorrectlyAlignedPragma
   -- ^
   | UnterminatedStringLiteral
   -- ^
   | UnexpectedNewline
   -- ^
   | UnrecognizedEscapeCharacter
   -- ^
   | UnclosedParenthesis
   -- ^
   | LonelyOpenParen
   -- ^
   | LonelyClosedParen
   -- ^
   | EndOfInput
   -- ^
   | NotEnoughInput
   -- ^
   | OpenBlockComment
   -- ^ Unterminated block comment
   | GenericException
   -- ^
   | RemainingBufferToShort
   | TOPLEVELPARSEFAIL
   -- ^
   deriving (Generic, NFData, Show, Eq)
{-static void print_error(
    int error)
{
  switch (error)
  {
    case ERROR_SUCCESS:
      break;
    case ERROR_COULD_NOT_ATTACH_TO_PROCESS:
      fprintf(stderr, "can not attach to process (try running as root)\n");
      break;
    case ERROR_INSUFFICIENT_MEMORY:
      fprintf(stderr, "not enough memory\n");
      break;
    case ERROR_SCAN_TIMEOUT:
      fprintf(stderr, "scanning timed out\n");
      break;
    case ERROR_COULD_NOT_OPEN_FILE:
      fprintf(stderr, "could not open file\n");
      break;
    case ERROR_UNSUPPORTED_FILE_VERSION:
      fprintf(stderr, "rules were compiled with a different version of YARA\n");
      break;
    case ERROR_CORRUPT_FILE:
      fprintf(stderr, "corrupt compiled rules file.\n");
      break;
    case ERROR_EXEC_STACK_OVERFLOW:
      fprintf(stderr, "stack overflow while evaluating condition "
                      "(see --stack-size argument) \n");
      break;
    case ERROR_INVALID_EXTERNAL_VARIABLE_TYPE:
      fprintf(stderr, "invalid type for external variable\n");
      break;
    case ERROR_TOO_MANY_MATCHES:
      fprintf(stderr, "too many matches\n");
      break;
    default:
      fprintf(stderr, "internal error: %d\n", error);
      break;-}
instance Default ExceptionCode where
  -- Unspecified thrown exceptions will get recorded as "GenericException"
  -- May demove later
  def = GenericException

-- | A result type for the YP
data Result r = Fail Env           -- ^ Final Enivronment
                     ByteString    -- ^ Description of fail situation
                     ExceptionCode -- ^ Failure code
              | Done ByteString    -- ^ Remaining input
                     r             -- ^ Parsed value
              deriving (Generic)

deriving instance (NFData r) => NFData (Result r)

instance Eq r => Eq (Result r) where
  (Done b1 r1) == (Done b2 r2) = b1 == b2 && r1 == r2
  _            == _            = False

instance (Show r) => Show (Result r) where
  show res = case res of
    (Done m r)   ->
      let rm = bs2s $ if length m > 20
            then take 20 m ++ "..."
            else m
      in mconcat ["Done{ ", show r, " }: \"", rm,"\""]
    (Fail e m c) -> let
      f = filepath e
      p = position e
      stamp = mconcat [f, "(", int2bs p, "): " ]
      message = mconcat $ case c of
        UnterminatedInclude         -> ["unterminated include pragma '", m, "' found in '", f, "'"]
        FileDoesNotExist            -> ["included header file '", m, "' does not exist"]
        UnrecognizedPragma          -> ["unrecognized pragma '", m]
        IncorrectlyAlignedPragma    -> undefined
        GenericException            -> ["generic exception ",m," ", int2bs $ position e ]
        UnterminatedStringLiteral   -> ["unterminated string literal"]
        UnexpectedNewline           -> ["unexpected newline"]
        TOPLEVELPARSEFAIL           -> ["toplevelparser fail"]
        UnrecognizedEscapeCharacter -> ["Unrecognized escape character ",m]
        _                           -> ["catchallllll"]
     in bs2s $ stamp ++ message




-- | `Env` contains the basic state as well as "read-only" information
data Env = Env {
     filepath      :: ByteString          -- ^ Filepath of the file being parsed
  ,  filetype      :: ByteString                -- ^
  ,  position      :: Pos                       -- ^ Position in buffer.
  ,  parserLabels  :: [ByteString]              -- ^
  ,  imports       :: Map ByteString ByteString -- ^ Set of imported modules
  ,  externalVars  :: Map ByteString Value      -- ^ Externally defined vars
  ,  localStrings  :: Map ByteString Pattern    -- ^ Inscope strings
  ,  inscopeRules  :: Map ByteString RuleType   -- ^ Inscope rules
  } deriving (Show, Generic, NFData)

instance Default Env where
  def = Env { position = 0
            , imports = def
            , parserLabels = def
            , externalVars = def
            , localStrings = def
            , inscopeRules = def
            , filepath = ""
            , filetype = ""
            }

-- | To annotate
type Failure r = Env -> ByteString -> ExceptionCode -> Result r

-- | To annotate
type Success a r = Buffer -> Env -> a -> Result r

-- -----------------------------------------------------------------------------
-- Yara Parser

-- | Main parser type
--
-- The type of string parsed is always a bytestring (treated as a stream of
-- bytes). This type is an instance of the following classes:
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
     forall r. Buffer      -- ^ The bytestring currently being parsed
            -> Env         -- ^ Current enviroment during parsing
            -> Failure r   -- ^ Handles a unsuccessful parsing
            -> Success a r -- ^ Handles a successful parsing
            -> Result r    -- ^ Outcome of running the parser
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
--   (a) If it is a general parsing failure, use 'fault'
--   (b)
--   (c) Avoid `throwError`
--
fault :: ExceptionCode -> ByteString -> Yp a
fault code msg = YP $ \_ e l _ -> l e msg code
{-# INLINE fault #-}

fault_ :: ByteString -> Yp a
fault_ msg = YP $ \_ e l _ -> l e msg GenericException
{-# INLINE fault_ #-}

failure :: ExceptionCode -> ByteString -> Failure r
failure code msg e _ _ = Fail e msg code
{-# INLINE failure #-}

instance MonadError ExceptionCode Yp where
  throwError ex = fault ex "Error thrown (MonadError)"
  catchError p f = YP $ \b e l s ->
    let res = runParser p b e l s
    in case res of
         (Fail ne _ ex) -> runParser (f ex) b ne l s
         _              -> res

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
  -- Avoid, unless value is known at compile time.
  -- Use `throwError` instead for anything runtime.
  --fail = fault_ . s2bs
  --{-# INLINE fail #-}

instance MonadPlus Yp where
  mzero = fault_ "mzero"
  {-# INLINE mzero #-}
  mplus f g = YP $ \b e l s ->
    runParser f b e (\_ _ _ -> runParser g b e l s) s
  {-# INLINE mplus #-}

instance Semigroup a => Semigroup (Yp a) where
  (<>) = liftA2 (<>)
  {-# INLINE (<>) #-}

instance Monoid a => Monoid (Yp a) where
  mempty  = pure mempty
  {-# INLINE mempty #-}
  mappend = (<>)
  {-# INLINE mappend #-}

instance MonadState Env Yp where
  get = YP $ \b !e _ s -> s b e e
  {-# INLINE get #-}
  put e = YP $ \b _ l s -> runParser unit b e l s
  {-# INLINE put #-}

instance MonadReader Env Yp where
  ask = get
  {-# INLINE ask #-}
  local fun par = YP $ \b !e l s -> runParser par b (fun e) l s
  {-# INLINE local #-}
  reader fun = YP $ \b !e _ s -> s b e (fun e)
  {-# INLINE reader #-}

#define GO(n,T,s) n :: Yp (T); n = reader s; {-# INLINE n #-}
GO(getPos, Int, position)
GO(getParserLabels, [ByteString], parserLabels)
GO(getFilepath, FilePath, filepath)
GO(getFiletype, ByteString, filetype)
GO(getImports, Map ByteString ByteString, imports)
GO(getExternalVars, Map ByteString Value, externalVars)
GO(getLocalStrings, Map ByteString Pattern, localStrings)
GO(getInscopeRules, Map ByteString RuleType, inscopeRules)
#undef GO

-- | Name the parser, in the event failure occurs.
infixr 1 <?>
(<?>) :: Yp a -> ByteString -> Yp a
par <?> m = YP $ \b e l s -> let tmp = parserLabels e
  in runParser par b e (\e_ s_ c_ -> l (e_ {parserLabels = m:tmp}) s_ c_) s
{-# INLINE (<?>) #-}

posMap :: (Int -> Int) -> Env -> Env
posMap f e = let pos = position e in e { position = f pos }
{-# INLINE posMap #-}

-- | Checks if there are atleast `n` bytes of buffer string left.
-- Parse always succeeds
atleastBytesLeft :: Int -> Yp Bool
atleastBytesLeft i = YP $ \b e _ s ->
  if position e + i <= bufferLength b
    then s b e True
    else s b e False
{-# INLINE atleastBytesLeft #-}

-- | Advance the position pointer.
-- Returns true if successful, false if not.
--
-- Parser always succeeds.
advance :: Int -> Yp Bool
advance n = ifM (atleastBytesLeft n)
 (YP $ \b e _ s -> s b (posMap (+n) e) True)
 (YP $ \b e _ s -> s b e False)
{-# INLINE advance #-}

-- -----------------------------------------------------------------------------
-- Running parsers

-- | Run a parser.
parse :: Yp a        -- ^ Parser to run
      -> Env         -- ^ Envrionment conditions to parse with
      -> ByteString  -- ^ ByteString to parse
      -> Result a
parse p env bs =
  runParser p
            (toBuffer bs)
            (env { position = 0 })
            (\e s c -> Fail e s c)
            (\b e t -> Done (bufferUnsafeDrop (position e) b) t)
{-# INLINE parse #-}

-- | Parse with default environment settings.
parse_ :: Yp a -> ByteString -> Result a
parse_ p = parse p def
{-# INLINE parse_ #-}




{- TODO: Need to verify compiler core-dumps basically this instance before
         deleting.
instance (NFData r) => NFData (Result r) where
  rnf (Fail m n e) = rnf m `seq` rnf n `seq` rnf e
  rnf (Partial _)      = ()
  rnf (Done t r)       = rnf t `seq` rnf r
  {-# INLINE rnf #-}






instance Functor Result where
  fmap _ (Fail e b c) = Fail e b c
  fmap f (Partial p)  = Partial $ \x -> fmap f $ p x
  fmap f (Done b r)   = Done b $ f r
















newtype ModName = ModName String        -- Module name
 deriving (Show,Eq,Ord,Data,Generic)

newtype PkgName = PkgName String        -- package name
 deriving (Show,Eq,Ord,Data,Generic)
-}
