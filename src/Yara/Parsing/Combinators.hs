{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE Rank2Types #-}
{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE BlockArguments #-}
{-# LANGUAGE TupleSections #-}
#ifdef hlint
{-# ANN module "HLint: ignore Eta reduce" #-}
#endif
-- |
-- Module      :  Yara.Parsing.Combinators
-- Copyright   :  David Heras 2018-2019
-- License     :  GPL-3
--
-- Maintainer  :  dheras@protonmail.com
-- Stability   :  experimental
-- Portability :  unknown
--
-- A library of useful, general parser combinators.
--
module Yara.Parsing.Combinators (

  -- Parser combinators
  pair, parse, atEnd, endOfBuffer, endOfInput, decimal, hexadecimal,

  -- Parser Predicates
  isAlpha, isDigit, isAlphaNum, isSpace, isEndOfLine, isHorizontalSpace, isDot,

  -- Fundamental Parsers
  peekByte, satisfy, anyByte, skipWhile, takeTill, takeWhile, takeWhile1,
  space, space1, spaces, byte,

  -- Specific character parsers
  openCurl, closeCurl, openParen, closeParen, bSlash, fSlash, tab, vertBar,
  dash, colon, equal, at, lt, gt, quote, dot, doubleEqual, ellipsis,

  option, perhaps, many, many1, manyTill, skipTo, skipMany, skipMany1, count,

   -- String parsers
  string, strings, stringIgnoreCase, scan, atleastBytesLeft,
  {-quotedString, quotedStringWith,-}

  -- `sepBy` Parsers
  sepBy,  sepBySet,  sepBySeq,  sepByMap,
  sepBy1, sepBy1Set, sepBy1Seq, sepBy1Map

  ) where

import Prelude hiding (map, null, drop, takeWhile, length, (++),
                       concat, reverse)
import Control.Monad.Reader
import Control.Exception
import Control.Applicative hiding (liftA2)
import Data.Bits
import Data.ByteString hiding (count, elem, empty, foldr, append, takeWhile)
import qualified Data.ByteString       as BS (takeWhile)
import qualified Data.ByteString.Char8 as C8
import Data.ByteString.Internal
import Data.ByteString.Unsafe
import Data.Default
import Data.Int
import Data.String
import Foreign hiding (void)
import Data.Sequence ((<|))
    -----
import qualified Data.Map.Strict as Map
import qualified Data.Sequence   as Seq
import qualified Data.Set        as Set
    -----
import Yara.Parsing.Buffer
import Yara.Parsing.Parser
import Yara.Shared

instance (a ~ ByteString) => IsString (YaraParser a) where
    fromString = string . C8.pack

-- | Return remaining buffer as a bytestring
getBuff :: YaraParser ByteString
getBuff = YaraParser $ \b e _ s -> s b e (bufferUnsafeDrop (position e) b)
{-# INLINE getBuff #-}

-- | Return 'True' if buffer is empty
endOfBuffer :: YaraParser Bool
endOfBuffer = liftA2 (==) getPos (YaraParser $ \b@(Buf _ _ l _ _) e _ s ->
                                    let p = position e
                                    in s b e $ assert (p >= 0 && p <= l) (l-p))
{-# INLINE endOfBuffer #-}

-- | This parser always succeeds.  It returns 'True' if the end
-- of all input has been reached, and 'False' if any input is available
atEnd :: YaraParser Bool
atEnd = YaraParser $ \b e _ s ->
  if | position e < bufferLength b  -> s b e True
     | more e == Complete           -> s b e False
     | otherwise                    -> prompt (\b_ e_ -> s b_ e_ False)
                                              (\b_ e_ -> s b_ e_ True)
                                              b e
{-# INLINE atEnd #-}

-- | Match only if all input has been consumed.
endOfInput :: YaraParser ()
endOfInput = YaraParser $ \b e l s ->
  if | position e < bufferLength b  -> l b e [] "endOfInput"
     | more e == Complete           -> s b e ()
     | otherwise        -> runParser demandInput b e
                                     (\b_ e_ _ _ -> l b_ e_ [] "endOfInput")
                                     (\b_ e_ _   -> s b_ e_ ())
{-# INLINE endOfInput #-}

--- UTILITY PARSERS

-- | Run two parsers and return the pair of their results,
-- while running a possible seperator parser
pair :: YaraParser a -> Maybe (YaraParser s) -> YaraParser b -> YaraParser (a,b)
pair u p v = liftA2 (,) (u <* maybe def void p) v <?> "pair"
{-# INLINE pair #-}

option :: a -> YaraParser a -> YaraParser a
option x p = p <|> pure x <?> "option"
{-# INLINE option #-}

-- | @perhaps@ returns `Just` results if parser succeeds, otherwise
-- returns nothing. Doesn't fail.
--
-- >>> parse_ (perhaps colon) ":yara"
-- Done "yara" (Just 58)
--
-- >>> parse_ (perhaps alphaNum) ":yara"
-- Done ":yara" Nothing
--
perhaps :: YaraParser a -> YaraParser (Maybe a)
perhaps v = (Just <$> v) <|> def <?> "perhaps"
{-# INLINE perhaps #-}

-- | @many1@ parses one or more occurances of a parser.
--
-- >>> parse_ (many1 colon) ":::yara"
-- Done "yara" [58, 58, 58]
--
many1 :: YaraParser a -> YaraParser [a]
many1 p = liftA2 (:) p (many p) <?> "many1"
{-# INLINE many1 #-}

sepBy :: YaraParser a -> YaraParser s -> YaraParser [a]
sepBy p s = liftA2 (:) p ((s *> sepBy1 p s) <|> def) <|> def <?> "sepBy"
{-# INLINE sepBy #-}

sepBySet :: Ord a => YaraParser a -> YaraParser s -> YaraParser (Set.Set a)
sepBySet p s = liftA2 Set.insert p ((s *> sepBy1Set p s) <|> def) <|> def
{-# INLINE sepBySet #-}

sepByMap :: Ord k => YaraParser (k,a)
                  -> YaraParser s
                  -> YaraParser (Map.Map k a)
sepByMap p s =
  liftA2 (uncurry Map.insert) p ((s *> sepBy1Map p s) <|> def) <|> def
{-# INLINE sepByMap #-}

sepBySeq :: YaraParser a -> YaraParser s -> YaraParser (Seq.Seq a)
sepBySeq p s = liftA2 (<|) p ((s *> sepBy1Seq p s) <|> def) <|> def
{-# INLINE sepBySeq #-}

sepBy1 :: YaraParser a -> YaraParser s -> YaraParser [a]
sepBy1 p s = let go = liftA2 (:) p ((s *> go) `mplus` def) in go
{-# INLINE sepBy1 #-}

sepBy1Set :: Ord a => YaraParser a -> YaraParser s -> YaraParser (Set.Set a)
sepBy1Set p s = let go = liftA2 Set.insert p ((s *> go) `mplus` def) in go
{-# INLINE sepBy1Set #-}

sepBy1Map :: Ord k => YaraParser (k,a)
                          -> YaraParser s -> YaraParser (Map.Map k a)
sepBy1Map p s =
  let go = liftA2 (uncurry Map.insert) p ((s *> go) `mplus` def) in go
{-# INLINE sepBy1Map #-}

sepBy1Seq :: YaraParser a -> YaraParser s -> YaraParser (Seq.Seq a)
sepBy1Seq p s = let go = liftA2 (<|) p ((s *> go) `mplus` def) in go
{-# INLINE sepBy1Seq #-}

manyTill :: YaraParser a -> YaraParser b -> YaraParser [a]
manyTill p end = (end $> []) <|> liftA2 (:) p (manyTill p end)
{-# INLINE manyTill #-}

-- | Skip zero or more instances of an action.
skipMany :: YaraParser a -> YaraParser ()
skipMany p = (p *> skipMany p) <|> def
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

openCurl :: YaraParser Byte
openCurl = byte 123
{-# INLINE openCurl #-}

closeCurl :: YaraParser Byte
closeCurl = byte 125
{-# INLINE closeCurl #-}

openParen :: YaraParser Byte
openParen = byte 40
{-# INLINE openParen #-}

closeParen :: YaraParser Byte
closeParen = byte 41
{-# INLINE closeParen #-}

sqBra :: YaraParser Byte
sqBra  = byte 91
{-# INLINE sqBra #-}

sqKet :: YaraParser Byte
sqKet  = byte 93
{-# INLINE sqKet #-}

bSlash :: YaraParser Byte
bSlash = byte 92
{-# INLINE bSlash #-}

fSlash :: YaraParser Byte
fSlash = byte 47
{-# INLINE fSlash #-}

tab :: YaraParser Byte
tab = byte 09
{-# INLINE tab #-}

vertBar :: YaraParser Byte
vertBar = byte 124
{-# INLINE vertBar #-}

dash :: YaraParser Byte
dash = byte 45
{-# INLINE dash #-}

colon :: YaraParser Byte
colon = byte 58
{-# INLINE colon #-}

equal :: YaraParser Byte
equal = byte 61
{-# INLINE equal #-}

doubleEqual :: YaraParser Byte
doubleEqual = byte 61 *> byte 61
{-# INLINE doubleEqual #-}

lt :: YaraParser Byte
lt = byte 60
{-# INLINE lt #-}

gt :: YaraParser Byte
gt = byte 62
{-# INLINE gt #-}

at :: YaraParser Byte
at = byte 64
{-# INLINE at #-}

quote :: YaraParser Byte
quote = byte 34
{-# INLINE quote #-}

dot :: YaraParser Byte
dot = byte 46
{-# INLINE dot #-}

ellipsis :: YaraParser ()
ellipsis = void $ dot *> dot
{-# INLINE ellipsis #-}

-- FAST PREDICATES

isDot :: Byte -> Bool
isDot = (==46)
{-# INLINE isDot #-}

isAlpha :: Byte -> Bool

isAlpha b = b - 65 < 26 || b - 97 < 26
{-# INLINE isAlpha #-}

-- | A fast digit predicate.
isDigit :: Byte -> Bool
isDigit b = b - 48 <= 9
{-# INLINE isDigit #-}

isAlphaNum :: Byte -> Bool
isAlphaNum = isDigit <> isAlpha
{-# INLINE isAlphaNum #-}

isSpace :: Byte -> Bool
isSpace b = b == 32 || b - 9 <= 4
{-# INLINE isSpace #-}

-- | A predicate that matches either a carriage return @\'\\r\'@ or
-- newline @\'\\n\'@ character.
isEndOfLine :: Byte -> Bool
isEndOfLine = (== 13) <> (== 10)
{-# INLINE isEndOfLine #-}

-- | A predicate that matches either a space @\' \'@ or horizontal tab
-- @\'\\t\'@ character.
isHorizontalSpace :: Byte -> Bool
isHorizontalSpace = (== 32) <> (== 9)
{-# INLINE isHorizontalSpace #-}



--- FAST PREDICATE PARSERS

-- | Peek at next byte.
--
-- Note: Doesn't fail unless at the end of input.
peekByte :: YaraParser Byte
peekByte = YaraParser $ \b e l s ->
  let pos = position e in
  if bufferLengthAtLeast pos 1 b
     then s b e (bufferUnsafeIndex b pos)
     else ensureSuspended 1 b e l (\b_ e_ bs_ -> s b_ e_ $! unsafeHead bs_)
{-# INLINE peekByte #-}

satisfy :: (Byte -> Bool) -> YaraParser Byte
satisfy p = do
  h <- peekByte
  when_ (p h) "satisfy" (advance 1 >> pure h)
{-# INLINE satisfy #-}

-- | Match a specific byte.
byte :: Byte -> YaraParser Byte
byte c = satisfy (== c) <?> singleton c
{-# INLINE byte #-}

anyByte :: YaraParser Byte
anyByte = satisfy $ const True
{-# INLINE anyByte #-}

-- | Match either a single newline character @\'\\n\'@, or a carriage
-- return followed by a newline character @\"\\r\\n\"@.
endOfLine :: YaraParser ()
endOfLine = void (byte 10) <|> void (string "\r\n")

-- | Match any byte except the given one.
notByte :: Byte -> YaraParser Byte
notByte c = satisfy (/= c) <?> "not '" +> c ++ "'"
{-# INLINE notByte #-}


alphaNum :: YaraParser Byte
alphaNum = satisfy isAlphaNum  <?> "alphaNum"
{-# INLINE alphaNum #-}

space :: YaraParser Byte
space = satisfy isSpace <?> "space"
{-# INLINE space #-}

spaces :: YaraParser ByteString
spaces = takeWhile isSpace <?> "spaces"
{-# INLINE spaces #-}

space1 :: YaraParser ByteString
space1 = takeWhile1 isSpace <?> "space1"
{-# INLINE space1 #-}

horizontalSpace :: YaraParser Byte
horizontalSpace = satisfy isHorizontalSpace <?> "horizontalSpace"
{-# INLINE horizontalSpace #-}

--- | PARSER COMBINATORS

-- | @hexadecimal@
--
-- Parser expects a leading @\"0x\"@ or @\"0X\"@ string.
hexadecimal :: (Integral a, Bits a) => YaraParser a
hexadecimal = do
  byte 48               -- '0'
  byte 88 <|> byte 120  -- 'X' or 'x'
  foldl' step 0 `fmap` takeWhile1 isHexByte
  where
    isHexByte :: Byte -> Bool
    isHexByte b = (b >= 48 && b <= 57) || (b >= 97 && b <= 102) ||
                                                    (b >= 65 && b <= 70)
    step a w | w >= 48 && w <= 57  = (a `shiftL` 4) .|. fromIntegral (w - 48)
             | w >= 97             = (a `shiftL` 4) .|. fromIntegral (w - 87)
             | otherwise           = (a `shiftL` 4) .|. fromIntegral (w - 55)
{-# SPECIALISE hexadecimal :: YaraParser Int #-}
{-# SPECIALIZE hexadecimal :: YaraParser Int64 #-}
{-# SPECIALISE hexadecimal :: YaraParser Integer #-}
{-# SPECIALISE hexadecimal :: YaraParser Word #-}
{-# INLINE hexadecimal #-}

decimal :: Integral a => YaraParser a
decimal = foldl' step 0 `fmap` takeWhile1 isDigit
  where step a b = a * 10 + fromIntegral (b - 48)
{-# SPECIALISE decimal :: YaraParser Int #-}
{-# SPECIALISE decimal :: YaraParser Int64 #-}
{-# SPECIALISE decimal :: YaraParser Integer #-}
{-# SPECIALISE decimal :: YaraParser Word #-}
{-# INLINE decimal #-}

-- | The parser @skip p@ succeeds for any byte for which the predicate
-- @p@ returns 'True'.
--
-- >skipDigit = skip isDigit
-- >    where isDigit w = w >= 48 && w <= 57
skip :: (Byte -> Bool) -> YaraParser ()
skip p = do
  h <- peekByte
  forkA (p h) (pure ()) $
    advance 1

-- | skipTo
-- Gobbles up horizontal space then applies parser
skipTo :: YaraParser a -> YaraParser a
skipTo p = skip isSpace *> p
{-# INLINE skipTo #-}

-- | skipTo1
-- same as skipTo but requires the occurance of atleast 1 horizonal space
skipToHz1 :: YaraParser a -> YaraParser a
skipToHz1 p = takeWhile1 isHorizontalSpace *> p
{-# INLINE skipToHz1 #-}

-- | skipToLn1
-- | sames as skipToLn but requiring atleast one whitespace occurance
skipTo1 :: YaraParser a -> YaraParser a
skipTo1 p = takeWhile1 isSpace *> p
{-# INLINE skipTo1 #-}

-- | Skip past input for as long as the predicate returns 'True'.
skipWhile :: (Byte -> Bool) -> YaraParser ()
skipWhile p = go
 where
  go = do
    t <- BS.takeWhile p <$> getBuff
    continue <- atleastBytesLeft (length t)
    when continue go
{-# INLINE skipWhile #-}

takeTill :: (Byte -> Bool) -> YaraParser ByteString
takeTill p = takeWhile (not . p)
{-# INLINE takeTill #-}

-- | @followedBy p@ only succeeds when parser @p@ succeeds.
--
-- Note: does not consume any input. It tests if the parser would succeed.
-- When parsing keywords or name spaces, we usually want
-- to make ensure such is followed by a whitespace.
--
-- Note: /Backtracking is expensive/. The combinators is mostly to be used
-- on single byte parsing predicates.
--
-- Why the type @YaraParser a -> YaraParser ()@, instead of say
-- @(Word8 -> Bool) -> YaraParser ()@ if its used primarily for matching on
-- single bytes? Occasionally we do need to match on a pair of bytes.
--
--
-- End lines are sometimes not just a byte but a pair of bytes "\r\n" so
-- we can pass in any parser ('void'-ing out result type if needed).
followedBy :: YaraParser a -> YaraParser ()
followedBy p = YaraParser $ \b e l s ->
  case parse (void p) e (bufferUnsafeDrop (position e) b) of
    Fail{}    -> l b e [] "followedBy"
    Done{}    -> s b e ()
    Partial{} -> prompt (\b_ e_ -> s b_ e_ ())
                        (\b_ e_ -> l b_ e_ ["followedBy"] "followedBy")
                        b e


takeWhile :: (Byte -> Bool) -> YaraParser ByteString
takeWhile p = do
    s <- BS.takeWhile p <$> getBuff
    continue <- atleastBytesLeft (length s)
    forkA continue (pure s) $ takeWhileAcc p s

{-# INLINE takeWhile #-}

takeWhile1 :: (Byte -> Bool) -> YaraParser ByteString
takeWhile1 p = do
  (`when` void demandInput) =<< endOfBuffer
  s <- BS.takeWhile p <$> getBuff
  let len = length s
  when_ (len /= 0) "takeWhile1" $ do
      advance len
      eoc <- endOfBuffer
      if eoc
        then takeWhileAcc p s
        else pure s
{-# INLINE takeWhile1 #-}

takeWhileAcc :: (Byte -> Bool) -> ByteString -> YaraParser ByteString
takeWhileAcc p = go
  where go acc = do
          s <- BS.takeWhile p <$> getBuff
          continue <- atleastBytesLeft (length s)
          if continue
           then go $ acc ++ s
           else pure $ acc ++ s
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

-- A generic "grouping" parser that take any parser. So,
--      /parse (grouping alphaNums) "(abc|def|ghi|jkl)"
--                                = Done "fromList[abc,def,ghi,jkl]" ""/
--
-- Note: ignores extraneous whitespaces between instances of parser and
--       seperators.
--
-- Note: the parser must succeed atleast once (so "(p)" will pass but not "()").


grouping :: YaraParser a -> YaraParser s -> YaraParser (Seq.Seq a)
grouping p v = between openParen closeParen $ interleaved v p
  where interleaved s par = sepBy1 par (skipTo s <* spaces)




{-
-- | `quotedString` parses a string literal
-- Strings can contain the following escape bytes \" \\ \t \n \r and handle
-- string line breaks.
-- Returns the content of the string without the quotation bytes.
-- Careful as Haskell style strings differ from C style string literals
-- THESE parse as C style
quotedString :: YaraParser ByteString
quotedString = quotedStringWith (const True)

data ScanStatus =
    SeekingNewLine
  | SS

-- | `quotedStringWith` parses a string literal, but only if all the bytes
-- satisfy the predicate
--
-- Todo: need to be able to return the status of exit as well to handle exit
--       error reporting.
quotedStringWith :: (Word8 -> Bool) -> YaraParser ByteString
quotedStringWith f = quote *> scan False go <* quote <?> "litString"
  where
    -- s - stores previous char
    go s w = if
        -- If unescaped quote mark, the string is closed
        | (s /= 92 && w == 34)  -> Nothing
        -- If byte doesn't satisfy predicate

        -- Quote, preceeded by backslash is cool.
        | s == 92 && w == 34   -> if p w
                then Just w
                else Nothing
        | s == 92 && (isSpace w || w == 10 || w == 13)  -> Just s
-}
-- | Match a specific string.
string :: ByteString -> YaraParser ByteString
string bs = stringWithMorph id bs
{-# INLINE string #-}

-- | Satisfy a literal string, ignoring case.
-- ASCII-specific but fast, oh yes.
stringIgnoreCase :: ByteString -> YaraParser ByteString
stringIgnoreCase = stringWithMorph (map toLower)
  where toLower b | b >= 65 && b <= 90 = b + 32
                  | otherwise          = b
{-# INLINE stringIgnoreCase #-}

-- | To annotate
stringWithMorph :: (ByteString -> ByteString)
                -> ByteString -> YaraParser ByteString
stringWithMorph fn sn = string_ (stringSuspend fn) fn sn where

  string_ :: (forall r. ByteString -> ByteString -> Buffer -> Env
          -> Failure r -> Success ByteString r -> Result r)
          -> (ByteString -> ByteString) -> ByteString -> YaraParser ByteString
  string_ suspended f s0 = YaraParser $ \b e l s ->
    let bs = f s0
        n = length bs
        pos = position e
        b_ = bufferSubstring pos n b
        t_ = bufferUnsafeDrop pos b
    in if
      | bufferLengthAtLeast pos n b && (bs == f b_)  -> s b (posMap (+n) e) b_
      | f t_ `isPrefixOf` bs   -> suspended bs (drop (length t_) bs) b e l s
      | otherwise              -> l b e [] "string"

  stringSuspend :: (ByteString -> ByteString)
                -> ByteString -> ByteString -> Buffer -> Env
                -> Failure r -> Success ByteString r -> Result r
  stringSuspend f s0 s1 = runParser (demandInput >>= go) where
    m = length s1
    go str = YaraParser $ \b e l s -> let n = length (f str) in
      if | n >= m && unsafeTake m (f str) == s1 ->
               let o = length s0
               in s b (posMap (+o) e) (bufferSubstring (position e) o b)
         | str == unsafeTake n s1 ->
               stringSuspend f s0 (unsafeDrop n s1) b e l s
         | otherwise              -> l b e [] "string"
{-# INLINE stringWithMorph #-}

-- | Checks if there are atleast `n` bytes of buffer string left.
-- Parse always succeeds
atleastBytesLeft :: Int -> YaraParser Bool
atleastBytesLeft i = YaraParser $ \b e _ s ->
  let pos = position e + i in
  if pos < bufferLength b || more e == Complete
    then s b (e { position = pos}) False
    else prompt (\b_ e_ -> s b_ e_ False)
                (\b_ e_ -> s b_ e_ True)
                b
                (e {position = pos})
{-# INLINE atleastBytesLeft #-}

ensureSuspended :: Int -> Buffer -> Env
                -> Failure r
                -> Success ByteString r
                -> Result r
ensureSuspended n = runParser (demandInput >> go)
  where go = YaraParser $ \b e l s ->
          let pos = position e in
          if bufferLengthAtLeast pos n b
            then s b e (bufferSubstring pos n b)
            else runParser (demandInput >> go) b e l s
{-# INLINE ensureSuspended #-}

-- | Immedidately demand more input via a 'Partial' continuation
-- result.
demandInput :: YaraParser ByteString
demandInput = YaraParser $ \b e l s ->
  case more e of
    Complete -> l b e [] "not enough input"
    _        -> Partial $ \bs -> if null bs
      then l b (e { more = Complete }) [] "not enough input"
      else s (bufferPappend b bs) (e { more = Incomplete }) bs
{-# INLINE demandInput #-}

-- | Match on of a specific list of strings
strings :: Foldable f => f ByteString -> YaraParser ByteString
strings = foldMap string
{-# INLINE strings #-}
{-# SPECIALIZE strings :: Seq.Seq ByteString -> YaraParser ByteString #-}
{-# SPECIALIZE strings :: [ByteString] -> YaraParser ByteString #-}

data T s = T {-# UNPACK #-} !Int s

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
scan :: s -> (s -> Byte -> Maybe s) -> YaraParser ByteString
scan s0 p = scanWith s0 p id <?> "scan"
{-# INLINE scan #-}


-- |
--   'scan s p = scanWith s p id'
--
-- ghci$ pred s w = if w > 73 then Nothing else Just False
-- ghci$ parse_ (scan_ False toLower pred) "ABCDEFGHIJKLMNOP"
-- "Done" "JKLMNOP" "abcdefghi"
--
scanWith :: s
      -- ^ Initial state
      -> (s -> Byte -> Maybe s)
      -- ^ State Transformation
      -> (Byte -> Byte)
      -- ^ Byte shift
      -> YaraParser ByteString
scanWith s0 p f = go "" s0 <?> "scan"
  where
    go acc s1 = do
      let scanner (PS fp off len) =
            withForeignPtr fp $ \ptr0 -> do
              let done !i !s = pure $! T i s
                  start = ptr0 `plusPtr` off
                  inner ptr !s
                    | ptr < (start `plusPtr` len) = do
                        w <- peek ptr
                        case p s w of
                          Just s' -> do
                            pokeByteOff ptr 0 (f w)
                            inner (ptr `plusPtr` 1) s'
                          _       -> done (ptr `minusPtr` start) s
                    | otherwise = done (ptr `minusPtr` start) s
              inner start s1
      bs <- getBuff
      let T i u = accursedUnutterablePerformIO $ scanner bs
          !h = unsafeTake i bs
      continue <- atleastBytesLeft i
      if continue
        then go (acc ++ h) u
        else pure $! acc ++ h
{-# INLINE scanWith #-}





{- THE SALAVAGE YARD
Everything saved just in case. 



{-
-- | If at least @n@ elements of input are available, return the
-- current input, otherwise fail.
ensure :: Int -> YaraParser ByteString
ensure n = (YaraParser $ \b e l s ->
    let pos = position e in
    if bufferLengthAtLeast pos n b
      then s b e (substring pos n b)
      -- The uncommon case is kept out-of-line to reduce code size:
      else ensureSuspended n b e l s
    ) <?> "ensure"
{-# INLINE ensure #-}
-}


--sepByByte :: Semigroup a
--             => Byte -> YaraParser a -> YaraParser b -> YaraParser (a,b)
--sepByByte b q p = pair (q <* space1 <* byte b <* space1) p


untuple :: (YaraParser a, YaraParser b) -> YaraParser (a,b)
untuple (u,v) = pair u Nothing v <?> "untuples"
{-# INLINE untuple #-}



sepByw :: Default (f a)
      => (a -> f a -> f a)
      -> YaraParser a
      -> YaraParser s
      -> YaraParser (f a)
sepByw f p s = liftA2 f p ((s *> sepByw1 f p s) <|> def) <|> def
{-# INLINE sepByw #-}

sepByw1 :: Default (f a)
        => (a -> f a -> f a)
        -> YaraParser a
        -> YaraParser s
        -> YaraParser (f a)
sepByw1 f p s = let go = liftA2 f p ((s *> go) `mplus` def) in go
{-# SPECIALIZE sepByw1 :: (a -> Set.Set a -> Set.Set a) -> YaraParser a
                                  -> YaraParser s -> YaraParser (Set.Set a) #-}
{-# INLINE sepByw1 #-}





-- | litString parses a literal string
-- Strings can contain the following escape bytes \" \\ \t \n \r and handle
-- string line breaks.
-- Returns the content of the string without the quotation bytes.
litString :: YaraParser ByteString
litString = quote *> (go "") <* quote <?> "litString"
  where
    -- s - stores previous char
    go s w
      -- If quote, not preceeded by backslash, the string is closed.
      | s /= 92 && w == 34   = Nothing
      -- Quote, preceeded by backslash is cool. 
      | s == 92 && w == 34   = Just w

      | s == 92 && (isSpace w || isNewline w)  = Just ~~tricky


{-
    go acc = do
      -- Take till a quote, newline, or backslash
      bs <- takeTill $ \q -> q `elem` [92, 34, 10]
      let acc_ = acc ++ bs
          gotoNextChar = do
            takeWhile isHorizontalSpace
            go =<< (acc_ +>) <$> satisfy notSpace
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
                 gotoNextChar
             -- Handles the case that there is a newline immediately after
             -- the escape slash.
             | 10 == s -> gotoNextChar
             -- Anyother is not supported.
             | otherwise -> fault $ "Unrecognized escape char: " +> s
        -- Shuts up incomplete-patterns
        _  -> fault "How did you get here?"
    notSpace = not . isSpace
-}
-- MATCH STRINGS
    go acc = do
      -- Take till a quote, newline, or backslash
      bs <- takeTill $ \q -> q `elem` [92, 34, 10]
      let acc_ = acc ++ bs
          gotoNextChar = do
            takeWhile isHorizontalSpace
            go =<< (acc_ +>) <$> satisfy notSpace
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
                 gotoNextChar
             -- Handles the case that there is a newline immediately after
             -- the escape slash.
             | 10 == s -> gotoNextChar
             -- Anyother is not supported.
             | otherwise -> fault $ "Unrecognized escape char: " +> s
        -- Shuts up incomplete-patterns
        _  -> fault "How did you get here?"
    notSpace = not . isSpace




-}


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
  continue <- inptSpansChunks (length s)
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






-- Is point-free style ever slower or faster
-- or does ghc optimize it all equivalently?
-- option = (flip (<|>)) . pure
-- perhaps = (option Nothing) . (Just <$>)
option :: a -> YaraParser a -> YaraParser a
option x p = p <|> pure x <?> "option"
{-# INLINE option #-}

-}


