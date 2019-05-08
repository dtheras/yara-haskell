{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE Rank2Types #-}
{-# LANGUAGE CPP #-}

#ifdef HLINT
{-# ANN module "HLint: ignore Eta reduce" #-}
#endif

module Combinators
  ( (<?>)
  , (<^>)
  , pair
  , parse
  , advance
  , atEnd
  , endOfInput
  , getPos
  , getPosByteString
  , getPosByteStringP1

  -- Parser Predicates
  , isAlpha
  , isDigit
  , isAlphaNum
  , isSpace
  , isEndOfLine
  , isHorizontalSpace

  -- Fundamental Parsers
  , peekWord8
  , satisfy
  , anyWord8
  , takeTill
  , takeWhile
  , space1
  , spaces
  , word8

  -- Specific character parsers
  , openCurl
  , closeCurl
  , openParen
  , closeParen
  , bSlash
  , fSlash
  , tab
  , vertBar
  , dash
  , colon
  , equal
  , at
  , quote
  , option
  , many
  , many1
  , sepBy
  , sepBy1
  , manyTill
  , skipMany
  , skipMany1
  , count
  , decimal
  -- ByteString parsers
  , string
  , strings
  , stringIgnoreCase
  , bool
  , scan
  ) where

import Prelude hiding (map, null, drop, takeWhile, length, (++),
                       concat, reverse)
import Control.Monad.Reader
import Control.Applicative hiding (liftA2)
import Data.Bits
import Data.ByteString hiding (count, elem, empty, foldr, append, takeWhile)
import qualified Data.ByteString as BS (takeWhile)
import Data.ByteString.Builder (toLazyByteString, intDec)
import qualified Data.ByteString.Char8 as C8
import Data.ByteString.Internal (ByteString(..))
import qualified Data.ByteString.Lazy as L (toStrict)
import Data.ByteString.Unsafe
--import Data.Functor
import Data.String (IsString(..))
import GHC.Word
import Foreign hiding (void)
import qualified Data.Sequence as Seq

import Types
import Buffer
import Utilities

infix 0 <?>
infixr 2 <^>

instance (a ~ ByteString) => IsString (YaraParser a) where
    fromString = string . C8.pack


--- RUNNING A PARSER

parse :: YaraParser a -> Env -> ByteString -> Result a
parse m e s = runParser m e (toBuffer s) (Pos 0) Incomplete failK successK
  where successK t (Pos pos) _more = Done (bufferUnsafeDrop pos t)
        failK t (Pos pos) _more = Fail (bufferUnsafeDrop pos t)
{-# INLINE parse #-}

parse_ :: YaraParser a -> ByteString -> Result a
parse_ par bs = parse par defaultEnv bs
{-# INLINE parse_ #-}


advance :: Int -> YaraParser ()
advance n = YaraParser $ \_ t pos more _lose suc ->
  suc t (pos + Pos n) more ()
{-# INLINE advance #-}

-- | Return current position.
getPos :: YaraParser Int
getPos = YaraParser $ \_ b !p m _ s -> s b p m $ fromPos p
{-# INLINE getPos #-}

-- | Convert int to a bytestring.
-- Not exported.
-- Fairly ugly and uses the really slow 'toStrict', but even if parsing a 100,00
-- word novel, at over-estimate of 7 characters a word, leaves us
-- converting a number less than 850,000 into a bytestring, max. That is utterly
-- dwarfed by the actual loading into the buffer "War & Peace."
int2bs :: Int -> ByteString
int2bs =  L.toStrict . toLazyByteString . intDec
{-# INLINE int2bs #-}

-- | Return current position as a ByteString.
--
-- Used for returning location in printable format.
getPosByteString :: YaraParser ByteString
getPosByteString = int2bs <$> getPos
{-# INLINE getPosByteString #-}

-- | Return current position plus 1 as a ByteString.
-- Specifically written to be used in combination with matching cases on
-- 'peekWord8'. So when reporting a parsing issue on that peeked word, reporting
-- refelects an accurate position
getPosByteStringP1 :: YaraParser ByteString
getPosByteStringP1 = int2bs . (+1) <$> getPos
{-# INLINE getPosByteStringP1 #-}

-- | This parser always succeeds.  It returns 'True' if the end
-- of all input has been reached, and 'False' if any input is available
atEnd :: YaraParser Bool
atEnd = YaraParser $ \_ t pos more _lose suc ->
  if | pos < (Pos $ bufferLength t) -> suc t pos more False
     | more == Complete    -> suc t pos more True
     | otherwise -> let lose' t' pos' more' = suc t' pos' more' True
                        suc' t' pos' more'  = suc t' pos' more' False
                    in prompt t pos more lose' suc'
{-# INLINE atEnd #-}

-- | Match only if all input has been consumed.
endOfInput :: YaraParser ()
endOfInput = YaraParser $ \e t pos more lose suc ->
  if | pos < (Pos $ bufferLength t) -> lose t pos more [] "endOfInput"
     | more == Complete -> suc t pos more ()
     | otherwise ->  let lose' t' pos' more' _ctx _msg = suc t' pos' more' ()
                         suc' t' pos' more' _a = lose t' pos' more' [] "endOfInput"
                     in  runParser demandInput e t pos more lose' suc'
{-# INLINE endOfInput #-}




--- UTILITY PARSERS

pair :: YaraParser a -> YaraParser b -> YaraParser (a,b)
pair u v = do
  x <- u
  !y <- v
  pure (x,y)
{-# INLINE pair #-}

-- | /(<^>)/ combines two parsers and returns the combination of the results, in order.
-- Both must be successfull for the combo to be successfull.
(<^>) :: (Semigroup a) => YaraParser a -> YaraParser a -> YaraParser a
(<^>) u v = do
  x <- u
  !y <- v
  return $ x <> y
{-# INLINE (<^>) #-}

untuple :: Applicative f => (f a, f b) -> f (a,b)
untuple (b,c) = do
  y <- b
  !x <- c
  pure (y,x)
{-# INLINE untuple #-}
{-# SPECIALIZE untuple :: (YaraParser a, YaraParser b) -> YaraParser (a,b) #-}

-- | Name the parser, in case failure occurs.
(<?>) :: YaraParser a -> ByteString -> YaraParser a
par <?> msg0 = YaraParser $ \e t p m l s ->
   let l' t' p' m' strs = l t' p' m' (msg0:strs)
   in runParser par e t p m l' s
{-# INLINE (<?>) #-}

option :: a -> YaraParser a -> YaraParser a
option x p = p <|> pure x
{-# INLINE option #-}

many1 :: YaraParser a -> YaraParser [a]
many1 p = liftA2 (:) p (many p)
{-# INLINE many1 #-}

sepBy :: YaraParser a -> YaraParser s -> YaraParser [a]
sepBy p s = liftA2 (:) p ((s *> sepBy1 p s) <|> pure []) <|> pure []
{-# INLINE sepBy #-}

sepBy1 :: YaraParser a -> YaraParser s -> YaraParser [a]
sepBy1 p s = scan
    where scan = liftA2 (:) p ((s *> scan) <|> pure [])
{-# INLINE sepBy1 #-}

manyTill :: YaraParser a -> YaraParser b -> YaraParser [a]
manyTill p end = scan
    where scan = (end $> []) <|> liftA2 (:) p scan
{-# INLINE manyTill #-}

-- | Skip zero or more instances of an action.
skipMany :: YaraParser a -> YaraParser ()
skipMany p = scan
    where scan = (p *> scan) <|> pure ()
{-# INLINE skipMany #-}

-- | Skip one or more instances of an action.
skipMany1 :: YaraParser a -> YaraParser ()
skipMany1 p = p *> skipMany p
{-# INLINE skipMany1 #-}

-- | Apply the given action repeatedly, returning every result.
count :: Int -> YaraParser a -> YaraParser [a]
count = replicateM
{-# INLINE count #-}



-- SPECIFIC WORD8 PARSERS

openCurl :: YaraParser Word8
openCurl = word8 123
{-# INLINE openCurl  #-}

closeCurl :: YaraParser Word8
closeCurl = word8 125
{-# INLINE closeCurl  #-}

openParen :: YaraParser Word8
openParen = word8 40
{-# INLINE openParen #-}

closeParen :: YaraParser Word8
closeParen = word8 41
{-# INLINE closeParen #-}

sqBra :: YaraParser Word8
sqBra  = word8 91
{-# INLINE sqBra #-}

sqKet :: YaraParser Word8
sqKet  = word8 93
{-# INLINE sqKet #-}

bSlash :: YaraParser Word8
bSlash = word8 92
{-# INLINE bSlash #-}

fSlash :: YaraParser Word8
fSlash = word8 47
{-# INLINE fSlash #-}

tab :: YaraParser Word8
tab = word8 09
{-# INLINE tab #-}

vertBar :: YaraParser Word8
vertBar = word8 124
{-# INLINE vertBar #-}

dash :: YaraParser Word8
dash = word8 45
{-# INLINE dash #-}

colon :: YaraParser Word8
colon = word8 58
{-# INLINE colon #-}

equal :: YaraParser Word8
equal = word8 61
{-# INLINE equal #-}

lt :: YaraParser Word8
lt     = word8 60
{-# INLINE lt #-}

gt :: YaraParser Word8
gt     = word8 62
{-# INLINE gt #-}
at :: YaraParser Word8
at     = word8 64
{-# INLINE at #-}

quote :: YaraParser Word8
quote = word8 34
{-# INLINE quote #-}



-- FAST PREDICATES

isAlpha :: Word8 -> Bool
isAlpha w = w - 65 <= 26 || w - 97 <= 26
{-# INLINE isAlpha #-}

-- | A fast digit predicate.
isDigit :: Word8 -> Bool
isDigit w = w - 48 <= 9
{-# INLINE isDigit #-}

isAlphaNum :: Word8 -> Bool
isAlphaNum = isDigit <> isAlpha
{-# INLINE isAlphaNum #-}

isSpace :: Word8 -> Bool
isSpace w = w == 32 || w - 9 <= 4
{-# INLINE isSpace #-}

-- | A predicate that matches either a carriage return @\'\\r\'@ or
-- newline @\'\\n\'@ character.
isEndOfLine :: Word8 -> Bool
isEndOfLine w = w == 13 || w == 10
{-# INLINE isEndOfLine #-}

-- | A predicate that matches either a space @\' \'@ or horizontal tab
-- @\'\\t\'@ character.
isHorizontalSpace :: Word8 -> Bool
isHorizontalSpace w = w == 32 || w == 9
{-# INLINE isHorizontalSpace #-}



--- FAST PREDICATE PARSERS

-- | Peek at next word8. Doesn't fail unless at end of input.
peekWord8 :: YaraParser Word8
peekWord8 = YaraParser $ \e t pos more lose suc ->
    if bufferLengthAtLeast pos 1 t
    then suc t pos more (bufferUnsafeIndex t (fromPos pos))
    else let suc' t' pos' more' bs' = suc t' pos' more' $! unsafeHead bs'
         in ensureSuspended e 1 t pos more lose suc'
{-# INLINE peekWord8 #-}

satisfy :: (Word8 -> Bool) -> YaraParser Word8
satisfy p = do
  h <- peekWord8
  if p h
    then advance 1 >> return h
    else fail "satisfy"
{-# INLINE satisfy #-}

-- | Match a specific byte.
word8 :: Word8 -> YaraParser Word8
word8 c = satisfy (== c) <?> singleton c
{-# INLINE word8 #-}

anyWord8 :: YaraParser Word8
anyWord8 = satisfy $ const True
{-# INLINE anyWord8 #-}

-- | Match either a single newline character @\'\\n\'@, or a carriage
-- return followed by a newline character @\"\\r\\n\"@.
endOfLine :: YaraParser ()
endOfLine = void (word8 10) <|> void (string "\r\n")

-- | Match any byte except the given one.
notWord8 :: Word8 -> YaraParser Word8
notWord8 c = satisfy (/= c) <?> "not '" +> c ++ "'"
{-# INLINE notWord8 #-}

alphaNum :: YaraParser Word8
alphaNum = satisfy isAlphaNum  <?> "alphaNum"
{-# INLINE alphaNum #-}

space :: YaraParser Word8
space = satisfy isSpace <?> "space"
{-# INLINE space #-}

spaces :: YaraParser ByteString
spaces = takeWhile isSpace <?> "spaces"
{-# INLINE spaces #-}

space1 :: YaraParser ByteString
space1 = takeWhile1 isSpace <?> "space1"
{-# INLINE space1 #-}

horizontalSpace :: YaraParser Word8
horizontalSpace = satisfy isHorizontalSpace <?> "horizontalSpace"
{-# INLINE horizontalSpace #-}



--- | PARSER COMBINATORS

-- | The parser @skip p@ succeeds for any byte for which the predicate
-- @p@ returns 'True'.
--
-- >skipDigit = skip isDigit
-- >    where isDigit w = w >= 48 && w <= 57
skip :: (Word8 -> Bool) -> YaraParser ()
skip p = do
  h <- peekWord8
  if p h
    then advance 1
    else fail "skip"

-- | skipTo
-- Gobbles up horizontal space then applies parser
skipTo :: YaraParser a -> YaraParser a
skipTo p = takeWhile isHorizontalSpace *> p
{-# INLINE skipTo #-}

-- | skipTo1
-- same as skipTo but requires the occurance of atleast 1 horizonal space
skipTo1 :: YaraParser a -> YaraParser a
skipTo1 p = takeWhile1 isHorizontalSpace *> p
{-# INLINE skipTo1 #-}

-- | skipToLn
-- gobbles up all whitespace, including newlines, then applyies parser
skipToLn :: YaraParser a -> YaraParser a
skipToLn p = takeWhile isSpace *> p
{-# INLINE skipToLn #-}

-- | skipToLn1
-- | sames as skipToLn but requiring atleast one whitespace occurance
skipToLn1 :: YaraParser a -> YaraParser a
skipToLn1 p = takeWhile1 isSpace *> p
{-# INLINE skipToLn1 #-}

hexadecimal :: (Integral a, Bits a) => YaraParser a
hexadecimal = foldl' step 0 `fmap` takeWhile1 isHexDigit
  where
    isHexDigit :: Word8 -> Bool
    isHexDigit w = (w >= 48 && w <= 57) ||
                   (w >= 97 && w <= 102) ||
                   (w >= 65 && w <= 70)
    step a w | w >= 48 && w <= 57  = (a `shiftL` 4) .|. fromIntegral (w - 48)
             | w >= 97             = (a `shiftL` 4) .|. fromIntegral (w - 87)
             | otherwise           = (a `shiftL` 4) .|. fromIntegral (w - 55)
{-# SPECIALISE hexadecimal :: YaraParser Int #-}
{-# SPECIALISE hexadecimal :: YaraParser Integer #-}
{-# SPECIALISE hexadecimal :: YaraParser Word #-}

decimal :: Integral a => YaraParser a
decimal = foldl' step 0 `fmap` takeWhile1 isDigit
  where step a w = a * 10 + fromIntegral (w - 48)
{-# SPECIALISE decimal :: YaraParser Int #-}
{-# SPECIALISE decimal :: YaraParser Integer #-}
{-# SPECIALISE decimal :: YaraParser Word #-}

-- | Skip past input for as long as the predicate returns 'True'.
skipWhile :: (Word8 -> Bool) -> YaraParser ()
skipWhile p = go
 where
  go = do
    t <- BS.takeWhile p <$> getBuff
    continue <- atleastBytesLeft (length t)
    when continue go
{-# INLINE skipWhile #-}

takeTill :: (Word8 -> Bool) -> YaraParser ByteString
takeTill p = takeWhile (not . p)
{-# INLINE takeTill #-}

takeWhile :: (Word8 -> Bool) -> YaraParser ByteString
takeWhile p = do
    s <- BS.takeWhile p <$> getBuff
    continue <- atleastBytesLeft (length s)
    if continue
      then takeWhileAcc p [s]
      else return s
{-# INLINE takeWhile #-}

takeWhile1 :: (Word8 -> Bool) -> YaraParser ByteString
takeWhile1 p = do
  (`when` demandInput) =<< endOfBuffer
  s <- BS.takeWhile p <$> getBuff
  let len = length s
  if len == 0
    then fail "takeWhile1"
    else do
      advance len
      eoc <- endOfBuffer
      if eoc
        then takeWhileAcc p [s]
        else return s
{-# INLINE takeWhile1 #-}

takeWhileAcc :: (Word8 -> Bool) -> [ByteString] -> YaraParser ByteString
takeWhileAcc p = go
 where
  go acc = do
    s <- BS.takeWhile p <$> getBuff
    continue <- atleastBytesLeft (length s)
    if continue
      then go (s:acc)
      else return $ concatReverse (s:acc)
{-# INLINE takeWhileAcc #-}

between :: YaraParser o
        -- ^ opening parser
        -> YaraParser c
        -- ^ closing parser
        -> YaraParser a
        -- ^ parser to satisfy inbetween
        -> YaraParser a
between op cp p = op *> skipTo p <* skipTo cp
{-# INLINE between #-}

flank :: YaraParser b -> YaraParser a -> YaraParser a
flank del par = between del del par
{-# INLINE flank #-}

-- | A generic "grouping" parser that take any parser. So,
--      /parse (grouping alphaNums) "(abc|def|ghi|jkl)"
--                                = Done "fromList[abc,def,ghi,jkl]" ""/
-- Note: ignores extraneous whitespaces between instances of parser and seperators.
-- Note: the parser must succeed atleast once (so "(p)" will pass but not "()").
grouping :: YaraParser a -> YaraParser [a]
grouping p = between openParen closeParen $ interleaved vertBar p
  where interleaved s par = sepBy1 par (skipTo s <* spaces)
{-# INLINE grouping #-}

-- | litString parses a literal string
-- Strings can contain the following escape bytes \" \\ \t \n \r and handle
-- string line breaks.
-- Returns the content of the string without the quotation bytes.
litString :: YaraParser ByteString
litString = quote *> (go "") <* quote <?> "litString"
  where
    go acc = do
      -- Take till a quote, newline, or backslash
      bs <- takeTill $ \q -> elem q [92, 34, 10]
      let acc_ = acc ++ bs
      peekWord8 >>= \case
        -- If unescaped quote, we've reached the end of the string.
        -- The accumulation is stored in reverse until returned
        34 -> return acc_
        -- If new line, fault since string was not closed.
        10 -> fault "string was not closed"
        -- If backslash, check next byte.
        92 -> do
          r <- anyWord8
          s <- anyWord8
             -- If next is a slash of quote, then we append.
             -- NOTE: the appending in reverse. 
          if | s == 34 || s == 92 -> go $ acc_ +> r +> s
             -- When there is a space after a slash, may have
             -- a string break among multiple lines, but a few empty
             -- spaces follow
             | isHorizontalSpace s -> do
                 takeWhile isHorizontalSpace
                 endOfLine
                 takeWhile isHorizontalSpace
                 n <- satisfy notSpace
                 go $ acc_ +> n
             -- Handles the case that there is a newline immediately after
             -- the escape slash.
             | 10 == s -> do
                 takeWhile isHorizontalSpace
                 n <- satisfy notSpace
                 go $ acc_ +> n
             -- Anyother is not supported.
             | otherwise -> fault $ "Unrecognized escape char: " +> s
        -- Shuts up incomplete-patterns
        _  -> fault "How did you get here?"
    notSpace = not . isSpace

-- MATCH STRINGS

stringWithMorph :: (ByteString -> ByteString)
                -> ByteString
                -> YaraParser ByteString
stringWithMorph f s = string_ (stringSuspended f) f s
{-# INLINE stringWithMorph #-}

string_ :: (forall r. Env -> ByteString -> ByteString -> Buffer -> Pos -> More
            -> Failure r -> Success ByteString r -> Result r)
        -> (ByteString -> ByteString)
        -> ByteString -> YaraParser ByteString
string_ suspended f s0 = YaraParser $ \e t pos more lose suc ->
  let n = length s
      s = f s0
  in if bufferLengthAtLeast pos n t
     then let t' = substring pos (Pos n) t
          in if s == f t'
             then suc t (pos + Pos n) more t'
             else lose t pos more [] "string"
     else let t' = bufferUnsafeDrop (fromPos pos) t
          in if f t' `isPrefixOf` s
             then suspended e s (drop (length t') s) t pos more lose suc
             else lose t pos more [] "string"
{-# INLINE string_ #-}

stringSuspended :: (ByteString -> ByteString)
                -> Env -> ByteString -> ByteString -> Buffer -> Pos -> More
                -> Failure r
                -> Success ByteString r
                -> Result r
stringSuspended f e s0 s t pos more lose suc =
    runParser (demandInput_ >>= go) e t pos more lose suc
  where go s'0   = YaraParser $ \env t' pos' more' lose' suc' ->
          let m  = length s
              s' = f s'0
              n  = length s'
          in if n >= m
             then if unsafeTake m s' == s
                  then let o = Pos (length s0)
                       in suc' t' (pos' + o) more'
                          (substring pos' o t')
                  else lose' t' pos' more' [] "string"
             else if s' == unsafeTake n s
                  then stringSuspended f env s0 (unsafeDrop n s)
                       t' pos' more' lose' suc'
                  else lose' t' pos' more' [] "string"
{-# INLINE stringSuspended #-}

-- | Immediately demand more input via a 'Partial' continuation
-- result.
demandInput :: YaraParser ()
demandInput = YaraParser $ \_ t pos more lose suc ->
  case more of
    Complete -> lose t pos more [] "not enough input"
    _ -> let lose' _ pos' more' = lose t pos' more' [] "not enough input"
             suc' t' pos' more' = suc t' pos' more' ()
         in prompt t pos more lose' suc'
{-# INLINE demandInput #-}

-- | Immediately demand more input via a 'Partial' continuation
-- result.  Return the new input.
demandInput_ :: YaraParser ByteString
demandInput_ = YaraParser $ \_ t pos more lose suc ->
  case more of
    Complete -> lose t pos more [] "not enough input"
    _ -> Partial $ \s ->
         if null s
         then lose t pos Complete [] "not enough input"
         else suc (bufferPappend t s) pos more s
{-# INLINE demandInput_ #-}

-- | Ask for input.  If we receive any, pass the augmented input to a
-- success continuation, otherwise to a failure continuation.
prompt :: Buffer -> Pos -> More
       -> (Buffer -> Pos -> More -> Result r)
       -> (Buffer -> Pos -> More -> Result r)
       -> Result r
prompt t pos _more lose suc = Partial $ \s ->
  if null s
  then lose t pos Complete
  else suc (bufferPappend t s) pos Incomplete
{-# INLINE prompt #-}

atleastBytesLeft :: Int -> YaraParser Bool
atleastBytesLeft i = YaraParser $ \_ t pos_ more _lose suc ->
  let pos = pos_ + Pos i
  in if fromPos pos < bufferLength t || more == Complete
     then suc t pos more False
     else let lose' t' pos' more' = suc t' pos' more' False
              suc'  t' pos' more' = suc t' pos' more' True
          in prompt t pos more lose' suc'
{-# INLINE atleastBytesLeft #-}

ensureSuspended :: Env -> Int -> Buffer -> Pos -> More
                -> Failure r
                -> Success ByteString r
                -> Result r
ensureSuspended env n t pos more lose suc =
    runParser (demandInput >> go) env t pos more lose suc
  where go = YaraParser $ \e t' pos' more' lose' suc' ->
          if bufferLengthAtLeast pos' n t'
          then suc' t' pos' more' (substring pos (Pos n) t')
          else runParser (demandInput >> go) e t' pos' more' lose' suc'
{-# INLINE ensureSuspended #-}

-- | If at least @n@ elements of input are available, return the
-- current input, otherwise fail.
ensure :: Int -> YaraParser ByteString
ensure n = YaraParser $ \e t pos more lose suc ->
    if bufferLengthAtLeast pos n t
    then suc t pos more (substring pos (Pos n) t)
    -- The uncommon case is kept out-of-line to reduce code size:
    else ensureSuspended e n t pos more lose suc
{-# INLINE ensure #-}

-- | Match a specific string.
string :: ByteString -> YaraParser ByteString
string = stringWithMorph id
{-# INLINE string #-}

-- | Match on of a specific list of strings
strings :: Foldable f => f ByteString -> YaraParser ByteString
strings = foldMap string
{-# INLINE strings #-}
{-# SPECIALIZE strings :: Seq.Seq ByteString -> YaraParser ByteString #-}
{-# SPECIALIZE strings :: [ByteString] -> YaraParser ByteString #-}

-- | Satisfy a literal string, ignoring case.
-- ASCII-specific but fast, oh yes.
stringIgnoreCase :: ByteString -> YaraParser ByteString
stringIgnoreCase = stringWithMorph (map toLower)
  where toLower w | w >= 65 && w <= 90 = w + 32
                  | otherwise          = w
{-# INLINE stringIgnoreCase #-}

bool :: YaraParser Bool
bool = peekWord8 >>= \case
  102 -> string "false" $> False
  116 -> string "true" $> True
  _   -> fail "bool"
  <?> "bool"
{-# INLINE bool #-}

data T s = T {-# UNPACK #-} !Int s

scan_ :: (s -> [ByteString] -> YaraParser a) -> s -> (s -> Word8 -> Maybe s)
         -> YaraParser a
scan_ f s0 p = go [] s0
 where
  go acc s1 = do
    let scanner (PS fp off len) =
          withForeignPtr fp $ \ptr0 -> do
            let start = ptr0 `plusPtr` off
                end   = start `plusPtr` len
                inner ptr !s
                  | ptr < end = do
                    w <- peek ptr
                    case p s w of
                      Just s' -> inner (ptr `plusPtr` 1) s'
                      _       -> done (ptr `minusPtr` start) s
                  | otherwise = done (ptr `minusPtr` start) s
                done !i !s = return (T i s)
            inner start s1
    bs <- getBuff
    let T i s' = inlinePerformIO $ scanner bs
        !h = unsafeTake i bs
    continue <- atleastBytesLeft i
    if continue
      then go (h:acc) s'
      else f s' (h:acc)
{-# INLINE scan_ #-}

-- | A stateful scanner.  The predicate consumes and transforms a
-- state argument, and each transformed state is passed to successive
-- invocations of the predicate on each byte of the input until one
-- returns 'Nothing' or the input ends.
--
-- This parser does not fail.  It will return an empty string if the
-- predicate returns 'Nothing' on the first byte of input.
--
-- /Note/: Because this parser does not fail, do not use it with
-- combinators such as 'Control.Applicative.many', because such
-- parsers loop until a failure occurs.  Careless use will thus result
-- in an infinite loop.
scan :: s -> (s -> Word8 -> Maybe s) -> YaraParser ByteString
scan = scan_ $ \_ chunks -> return $! concatReverse chunks
{-# INLINE scan #-}







-- ? between (str "\"") (str "\"")  many $ choice [alphaNum, escapeseq,
                                                     --  doublequote, whitespace]
--escQuot :: Parser Word8
--escQuot = bSlash *> quot


--- | Parse one or more occurances of 'a' perated by a delinator 'sep'

--intersperse :: Foldable f => Parser sep -> f (Parser a) -> Parser (f a)
--intersperse may not need


{-
-- | Consume input until either:
-- 1) the predicate fails
-- /or/
-- 2) n-bytes are consumed. If the immediately following byte (n+1th) satisfies
-- pred, then the parser fails.
--
-- Must consume atleast /one/ eventhough the parser name is not followed by a '1'.
takeNWhile :: Int -> (Word8 -> Bool) -> YaraParser ByteString
takeNWhile n p = do
  (`when` demandInput) =<< endOfBuffer
  s <- BS.takeWhile p <$> getBuff
  continue <- inputSpansChunks (length s)
  if continue
    then takeWhileAcc p [s]
    else return s
{-# INLINE takeNWhile #-}

inputSpansChunks :: Int -> YaraParser Bool
inputSpansChunks i = YaraParser $ \_ t pos_ more _lose suc ->
  -- take position and find end of chunk
  let pos = pos_ + Pos i
  -- if the new position doesnt reach end of buffer or out of feed
  in if fromPos pos < bufferLength t || more == Complete
     -- false
     then suc t pos more False
     -- else it much reach past, so prompt for input or success
     else let lose' t' pos' more' = suc t' pos' more' False
              suc' t' pos' more' = suc t' pos' more' True
          in prompt t pos more lose' suc'
{-# INLINE inputSpansChunks #-}
-}
