{-# OPTIONS_HADDOCK prune #-}
-- |
-- Module      :  Yara.Parsing.Parser
-- Copyright   :  David Heras 2019-2020
-- License     :  GPL-3
--
-- Maintainer  :  dheras@protonmail.comk
-- Stability   :  experimental
-- Portability :  unknown
--
-- Fundamental YARA parser/data types and based on the Attoparsec library.
--
module Yara.Parsing.Parser where

import Yara.Prelude
import Yara.Parsing.Buffer
import Yara.Parsing.AST

--import qualified Data.HashMap.Strict as H
--import Data.Map.Strict hiding (take)
import Data.String () -- Only need typeclass instances

-----------------------------------------------------------------------------

-- | @Env@ contains the basic state as well as "read-only" information
data Env = Env {
    filepath     :: !ByteString
  , position     :: !Int
  , parserLabels :: ![ByteString]
  } deriving (Show,Generic,NFData)

instance Default Env where
  def = Env "" 0 []

data Result s r = Fail Env ByteString s ExceptionCode
                | Done ByteString r

instance Eq r => Eq (Result s r) where
  (Done b1 r1) == (Done b2 r2)  = b1 == b2 && r1 == r2
  _            == _             = False

instance (Show s, Show r) => Show (Result s r) where
  show res = case res of
    (Done m r)  -> let
      rm = bs2s $ if length m > 20
        then take 20 m ++ "..."
        else m
      in mconcat ["Done{ ", show r, " }: \"", rm,"\""]
    (Fail (Env fp pos l) msg _ c) -> let
      stamp = mconcat [fp, "(", int2bs pos, "): " ]
      labels = "(" ++ intercalate ", " l ++ ")"
      showerr = case c of
        ExceptionSuccess  -> "exception success. "
        ParseError        -> "parsing error. "
        InternalError     -> "internal error. "
      in bs2s $ stamp ++ showerr ++ msg ++ labels

-- | To annotate.
type Failure s r = Env -> ByteString -> ExceptionCode -> s -> Result s r

-- | To annotate.
type Success s a r = Env -> Buffer -> a -> Result s r

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
newtype Yp s a
  = YP { runParser :: forall r .
            Buffer        -- ^ The bytestring currently being parsed
         -> Env           -- ^ Current enviroment during parsing
         -> s             -- ^ State
         -> Failure s r   -- ^ Handles a unsuccessful parsing
         -> Success s a r -- ^ Handles a successful parsing
         -> Result s r    -- ^ Outcome of running the parser
     } deriving Typeable

instance Functor (Yp s) where
  fmap f par = YP $ \b e st l s ->
    let s_ e_ b_ a_ = s e_ b_ (f a_) in runParser par b e st l s_
  {-# INLINE fmap #-}

instance Applicative (Yp s) where
  pure v = YP $ \b !e _ _ s -> s e b v
  {-# INLINE pure #-}
  w <*> b = do
    !f <- w
    f <$> b
  {-# INLINE (<*>) #-}
  m *> k = m >>= \_ -> k
  {-# INLINE (*>) #-}
  x <* y = x >>= \a -> y $> a
  {-# INLINE (<*) #-}

instance Default a => Default (Yp s a) where
  def = pure def
  {-# INLINE def #-}

instance Semigroup a => Semigroup (Yp s a) where
  (<>) = liftA2 (<>)
  {-# INLINE (<>) #-}

instance Monoid a => Monoid (Yp s a) where
  mempty  = pure mempty
  {-# INLINE mempty #-}
  mappend = (<>)
  {-# INLINE mappend #-}

instance Monad (Yp s) where
  v >>= k = YP $ \b !e st l s ->
    runParser v b e st l (\e_ b_ a -> runParser (k a) b_ e_ st l s)
  {-# INLINE (>>=) #-}
  (>>) = (*>)
  {-# INLINE (>>) #-}
  return = pure
  {-# INLINE return #-}

-- | Throws error with code, for this module only.
-- Use 'parseError' and 'internalError' instead elsewhere.
fault :: ExceptionCode -> ByteString -> Yp s a
fault code msg = YP $ \_ e st l _ -> l e msg code st
{-# INLINE fault #-}

parseError :: ByteString -> Yp s a
parseError = fault ParseError
{-# INLINE parseError #-}

internalError :: ByteString -> Yp s a
internalError = fault InternalError
{-# INLINE internalError #-}

-- | Avoid use of 
instance MonadError ExceptionCode (Yp s) where
  throwError _ = internalError $ "Error thrown (MonadError): unknown reason"
  catchError p f = YP $ \b e st l s -> let
    res = runParser p b e st l s
    in case res of
         (Fail ne _ ns nc) -> runParser (f nc) b ne ns l s
         _                 -> res

instance Alternative (Yp s) where
  empty = internalError "empty (Alternative)"
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

instance MonadPlus (Yp s) where
  mzero = internalError "mzero"
  {-# INLINE mzero #-}
  --mplus f g = ifM (committing <$> getEnv) f (YP $ \b e st l s ->
  mplus f g = YP $ \b e st l s ->
    runParser f b e st (\_ _ _ _ -> runParser g b e st l s) s
  {-# INLINE mplus #-}

instance MonadState s (Yp s) where
  get = YP $ \b !e st _ s -> s e b st
  {-# INLINE get #-}
  put st = YP $ \b e _ l s -> runParser unit b e st l s
  {-# INLINE put #-}

instance MonadReader s (Yp s) where
  ask = YP $ \b !e st _ s -> s e b st
  {-# INLINE ask #-}
  local fun par = YP $ \b !e st l s -> runParser par b e (fun st) l s
  {-# INLINE local #-}
  reader fun = YP $ \b !e st _ s -> s e b (fun st)
  {-# INLINE reader #-}

-- | Infix version of @annotate@ but used after the parser.
infixr 1 <?>
(<?>) :: Yp s a -> ByteString -> Yp s a
(<?>) par m = YP $ \b e st l s -> let
  tmp = parserLabels e
  l_ e_ s_ c_ st_ = l (e_ {parserLabels = m:tmp}) s_ c_ st_
  in runParser par b e st l_ s
{-# INLINE (<?>) #-}

-- | Apply function to the position record
posMap :: (Int -> Int) -> Env -> Env
posMap f e = let pos = position e in e { position = f pos }
{-# INLINE posMap #-}

-- | Checks if there are atleast `n` bytes of buffer string left.
-- Parse always succeeds
atleastBytesLeft :: Int -> Yp s Bool
atleastBytesLeft i = YP $ \b e _ _ s ->
  if position e + i <= bufferLength b
    then s e b True
    else s e b False
{-# INLINE atleastBytesLeft #-}

-- | Advance the position pointer.
-- Returns true if successful, false if not.
--
-- Parser always succeeds.
advance :: Int -> Yp s Bool
advance n = ifM (atleastBytesLeft n)
 (YP $ \b e _ _ s -> s (posMap (+n) e) b True)
 (YP $ \b e _ _ s -> s e b False)
{-# INLINE advance #-}

-- | Return 'Env' in the monad (since MonadState is tied to the local state)
getEnv :: Yp s Env
getEnv = YP $ \b e _ _ s -> s e b e
{-# INLINE getEnv #-}

getPos :: Yp s Int
getPos = YP $ \b e _ _ s -> s e b $ position e
{-# INLINE getPos #-}

-- -----------------------------------------------------------------------------
-- Running parsers

-- | Run a parser.
parse :: Yp s a      -- ^ Parser to run
      -> Env         -- ^ Envrionment conditions to parse with
      -> s
      -> ByteString  -- ^ ByteString to parse
      -> Result s a
parse p env st bs =
  runParser p
            (toBuffer bs)
            (env { position = 0 })
            st
            (\e b c ns -> Fail e b ns c)
            (\e b t -> Done (bufferUnsafeDrop (position e) b) t)
{-# INLINE parse #-}

-- | Parse without state settings.
parse_ :: Yp () a -> ByteString -> Result () a
parse_ p = parse p def ()
{-# INLINE parse_ #-}
