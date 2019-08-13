{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE Rank2Types #-}
{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE BlockArguments #-}
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
module Yara.Parsing.Combinators where

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



--- GHC.IO.Buffer



instance (a ~ ByteString) => IsString (YP a) where
    fromString = string . C8.pack

-- | Return remaining buffer as a bytestring
getBuff :: YP ByteString
getBuff = YP $ \b e _ s -> s b e (bufferUnsafeDrop (position e) b)
{-# INLINE getBuff #-}

-- | Get next byte.
nextByte :: YP Byte
nextByte = satisfy $ const True
{-# INLINE nextByte #-}

-- | Return 'True' if buffer is empty
endOfBuffer :: YP Bool
endOfBuffer = liftA2 (==) getPos (YP $ \b@(Buf _ _ l _ _) e _ s ->
                                    let p = position e
                                    in s b e $ assert (p >= 0 && p <= l) (l-p))
{-# INLINE endOfBuffer #-}

-- | This parser always succeeds.  It returns 'True' if the end
-- of all input has been reached, and 'False' if any input is available
atEnd :: YP Bool
atEnd = YP $ \b e _ s ->
  if | position e < bufferLength b  -> s b e True
     | more e == Complete           -> s b e False
     | otherwise                    -> prompt (\b_ e_ -> s b_ e_ False)
                                              (\b_ e_ -> s b_ e_ True)
                                              b e
{-# INLINE atEnd #-}

-- | Match only if all input has been consumed.
endOfInput :: YP ()
endOfInput = YP $ \b e l s ->
  if | position e < bufferLength b  -> l b e [] "endOfInput"
     | more e == Complete           -> s b e ()
     | otherwise        -> runParser demandInput b e
                                     (\b_ e_ _ _ -> l b_ e_ [] "endOfInput")
                                     (\b_ e_ _   -> s b_ e_ ())
{-# INLINE endOfInput #-}

--- UTILITY PARSERS

-- | Run two parsers and return the pair of their results,
-- while running a possible seperator parser
pair :: YP a -> Maybe (YP s) -> YP b -> YP (a,b)
pair u p v = liftA2 (,) (u <* maybe unit void p) v <?> "pair"
{-# INLINE pair #-}

option :: a -> YP a -> YP a
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
perhaps :: YP a -> YP (Maybe a)
perhaps v = (Just <$> v) <|> pure Nothing <?> "perhaps"
{-# INLINE perhaps #-}

-- | @many1@ parses one or more occurances of a parser.
--
-- >>> parse_ (many1 colon) ":::yara"
-- Done "yara" [58, 58, 58]
--
many1 :: YP a -> YP [a]
many1 p = liftA2 (:) p (many p) <?> "many1"
{-# INLINE many1 #-}

sepBy :: YP a -> YP s -> YP [a]
sepBy p s = liftA2 (:) p ((s *> sepBy1 p s) <|> def) <|> def <?> "sepBy"
{-# INLINE sepBy #-}

sepBySet :: Ord a => YP a -> YP s -> YP (Set.Set a)
sepBySet p s = liftA2 Set.insert p ((s *> sepBy1Set p s) <|> def) <|> def
{-# INLINE sepBySet #-}

sepByMap :: Ord k => YP (k,a)
                  -> YP s
                  -> YP (Map.Map k a)
sepByMap p s =
  liftA2 (uncurry Map.insert) p ((s *> sepBy1Map p s) <|> def) <|> def
{-# INLINE sepByMap #-}

sepBySeq :: YP a -> YP s -> YP (Seq.Seq a)
sepBySeq p s = liftA2 (<|) p ((s *> sepBy1Seq p s) <|> def) <|> def
{-# INLINE sepBySeq #-}

sepBy1 :: YP a -> YP s -> YP [a]
sepBy1 p s = let go = liftA2 (:) p ((s *> go) `mplus` def) in go
{-# INLINE sepBy1 #-}

sepBy1Set :: Ord a => YP a -> YP s -> YP (Set.Set a)
sepBy1Set p s = let go = liftA2 Set.insert p ((s *> go) `mplus` def) in go
{-# INLINE sepBy1Set #-}

sepBy1Map :: Ord k => YP (k,a)
                          -> YP s -> YP (Map.Map k a)
sepBy1Map p s =
  let go = liftA2 (uncurry Map.insert) p ((s *> go) `mplus` def) in go
{-# INLINE sepBy1Map #-}

sepBy1Seq :: YP a -> YP s -> YP (Seq.Seq a)
sepBy1Seq p s = let go = liftA2 (<|) p ((s *> go) `mplus` def) in go
{-# INLINE sepBy1Seq #-}

manyTill :: YP a -> YP b -> YP [a]
manyTill p end = (end $> []) <|> liftA2 (:) p (manyTill p end)
{-# INLINE manyTill #-}

-- | Skip zero or more instances of an action.
skipMany :: YP a -> YP ()
skipMany p = (p *> skipMany p) <|> unit
{-# INLINE skipMany #-}

-- | Skip one or more instances of an action.
skipMany1 :: YP a -> YP ()
skipMany1 p = p *> skipMany p
{-# INLINE skipMany1 #-}

-- | Apply the iven action repeatedly, returning every result.
count :: Int -> YP a -> YP [a]
count = replicateM
{-# INLINE count #-}

-- FIXED BYTE PARSERS
#define CP(n,v) n :: YP Byte; n = byte v; {-# INLINE n #-}
CP(tab,9)
CP(quote,34)
CP(dollarSign,36)
CP(oParen,40)
CP(cParen,41)
CP(dash,45)
CP(dot,46)
CP(fSlash,47)
CP(colon,58)
CP(lt,60)
CP(eq,61)
CP(gt,62)
CP(at,64)
CP(sqBra,91)
CP(bSlash,92)
CP(sqKet,93)
CP(oCurly,123)
CP(vertBar,124)
CP(cCurly,125)
#undef CP

-- Ensure that a '<' or '>'  token is followed by any byte
-- except '=' (otherwise token is '<=' or '>=' token)
notFollowedByEq :: YP ()
notFollowedByEq = do
  b <- peekByte
  if isEqual b
    then fault "YARA spec doesn't permit the use of operators '<=' and '>=' "
    else pure () -- otherwise
{-# INLINE notFollowedByEq #-}

#define DP(name,p1,p2,val) name = p1 *> p2 $> val; {-# INLINE name #-}
DP(lessthan,lt,notFollowedByEq,LT)
DP(eqeq,eq,eq,EQ)
DP(greaterthan,gt,notFollowedByEq,GT)
DP(ellipsis,dot,dot,())
#undef DP

ordering :: YP Ordering
ordering = lessthan <|> eqeq <|> greaterthan <?> "ordering"
{-# INLINE ordering #-}

-- FAST PREDICATES
-- Yes - I am that lazy.
#define PD(func,pred) func :: Byte -> Bool; func = pred; {-# INLINE func #-}
PD(isDot,(==46))
PD(isEqual, (==61))
PD(isAlpha,\b -> b - 65 < 26 || b - 97 < 26)
-- | A fast digit predicate.
PD(isDigit,\b -> b - 48 <= 9)
PD(isAlphaNum, isDigit <> isAlpha)
PD(isSpace, \b -> b == 32 || b - 9 <= 4)
-- | A predicate that matches either a carriage return @\'\\r\'@ or
-- newline @\'\\n\'@ character.
PD(isEndOfLine, (== 13) <> (== 10))
-- | A predicate that matches either a space @\' \'@ or horizontal tab
-- @\'\\t\'@ character.
PD(isHorizontalSpace, (== 32) <> (== 9))
-- | Following three are for YARA strings.
PD(isUnderscore,(== 95))
PD(isLeadingByte,isAlpha <> isUnderscore)
PD(isIdByte,isAlphaNum <> isUnderscore)
#undef PD

--- FAST PREDICATE PARSERS

-- | Peek at next byte.
--
-- Note: Doesn't fail unless at the end of input.
peekByte :: YP Byte
peekByte = YP $ \b e l s ->
  let pos = position e in
  if bufferLengthAtLeast pos 1 b
    then s b e (bufferUnsafeIndex b pos)
    else ensureSuspended 1 b e l (\b_ e_ bs_ -> s b_ e_ $! unsafeHead bs_)
{-# INLINE peekByte #-}

-- | Peek at the next 'N' number of bytes
peekNBytes :: Word -> YP ByteString
peekNBytes n = YP $ \b e l s ->
  let pos = position e in
  if bufferLengthAtLeast pos n b
   then s b e (bufferSubstring p n b)
   else ensureSuspended 1 b e l (\b_ e_ bs_ -> s b_ e_ $! unsafeHead bs_)


satisfy :: (Byte -> Bool) -> YP Byte
satisfy p = do
  h <- peekByte
  if p h
    then advance 1 >> pure h
    else fault "satisfy"
{-# INLINE satisfy #-}

-- | Match a specific byte.
byte :: Byte -> YP Byte
byte c = satisfy (== c)
         <?> sig c
{-# INLINE byte #-}

-- | Match any byte except the given one.
notByte :: Byte -> YP Byte
notByte c = satisfy (/= c)
            <?> "not '" +> c ++ "'"
{-# INLINE notByte #-}

-- Yes, I am that lazy.
#define GO(label,comb,pred) label = comb (pred) <?> "label"  ; {-# INLINE label #-}
GO(anyByte,satisfy,const True)
GO(endOfLine,void,string "\n" <|> string "\r\n")
GO(alphaNum,satisfy,isAlphaNum)
GO(space,satisfy,isSpace)
GO(spaces,takeWhile,isSpace)
GO(space1,takeWhile1,isSpace)
GO(horizontalSpace,satisfy,isHorizontalSpace)
GO(horizontalSpaces,takeWhile,isHorizontalSpace)
GO(horizontalSpace1,takeWhile1,isHorizontalSpace)
#undef GO

--- | PARSER COMBINATORS

isHexByte :: Byte -> Bool
isHexByte b = (b>=48 && b<=57) || (b>=97 && b<=102) || (b>=65 && b<=70)
{-# INLINE isHexByte #-}

isOctByte :: Byte -> Bool
isOctByte b = b>=48 && b>=55
{-# INLINE isOctByte #-}

-- | @hexadecimal@
--
-- Parser expects a leading @\"0x\"@ or @\"0X\"@ string.
hexadecimal :: (Integral a, Bits a) => YP a
hexadecimal = do
  byte 48               -- '0'
  byte 88 <|> byte 120  -- 'X' or 'x'
  foldl' step 0 `fmap` takeWhile1 isHexByte
  where
    step a w | w >= 48 && w <= 57  = (a `shiftL` 4) .|. fromIntegral (w - 48)
             | w >= 97             = (a `shiftL` 4) .|. fromIntegral (w - 87)
             | otherwise           = (a `shiftL` 4) .|. fromIntegral (w - 55)
{-# SPECIALISE hexadecimal :: YP Int #-}
{-# SPECIALIZE hexadecimal :: YP Int64 #-}
{-# SPECIALISE hexadecimal :: YP Integer #-}
{-# SPECIALISE hexadecimal :: YP Word #-}
{-# INLINE hexadecimal #-}

decimal :: Integral a => YP a
decimal = foldl' step 0 `fmap` takeWhile1 isDigit
  where step a b = a * 10 + fromIntegral (b - 48)
{-# SPECIALISE decimal :: YP Int #-}
{-# SPECIALISE decimal :: YP Int64 #-}
{-# SPECIALISE decimal :: YP Integer #-}
{-# SPECIALISE decimal :: YP Word #-}
{-# INLINE decimal #-}

-- | The parser @skip p@ succeeds for any byte for which the predicate
-- @p@ returns 'True'.

-- >skipDigit = skip isDigit
-- >    where isDigit w = w >= 48 && w <= 57
skip :: (Byte -> Bool) -> YP ()
skip p = do
  h <- peekByte
  forkA (p h) (pure ()) $
    advance 1
  <?> "skip"
{-# INLINE skip #-}

-- | skipTo
-- Gobbles up horizontal space then applies parser
skipTo :: YP a -> YP a
skipTo p = skip isSpace *> p
{-# INLINE skipTo #-}

-- | skipTo1
-- same as skipTo but requires the occurance of atleast 1 horizonal space
skipToHz1 :: YP a -> YP a
skipToHz1 p = takeWhile1 isHorizontalSpace *> p
{-# INLINE skipToHz1 #-}

-- | skipToLn1
-- | sames as skipToLn but requiring atleast one whitespace occurance
skipTo1 :: YP a -> YP a
skipTo1 p = takeWhile1 isSpace *> p
{-# INLINE skipTo1 #-}

-- | Skip past input for as long as the predicate returns 'True'.
skipWhile :: (Byte -> Bool) -> YP ()
skipWhile p = go
 where
  go = do
    t <- BS.takeWhile p <$> getBuff
    continue <- atleastBytesLeft (length t)
    when continue go
{-# INLINE skipWhile #-}

takeTill :: (Byte -> Bool) -> YP ByteString
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
-- Why the type @YP a -> YP ()@, instead of say
-- @(Word8 -> Bool) -> YP ()@ if its used primarily for matching on
-- single bytes? Occasionally we do need to match on a pair of bytes.
--
--
-- End lines are sometimes not just a byte but a pair of bytes "\r\n" so
-- we can pass in any parser ('void'-ing out result type if needed).
followedBy :: YP a -> YP ()
followedBy p = YP $ \b e l s ->
  case parse (void p) e (bufferUnsafeDrop (position e) b) of
    Fail{}    -> l b e [] "followedBy"
    Done{}    -> s b e ()
    Partial{} -> prompt (\b_ e_ -> s b_ e_ ())
                        (\b_ e_ -> l b_ e_ ["followedBy"] "followedBy")
                        b e

takeWhile :: (Byte -> Bool) -> YP ByteString
takeWhile p = do
    s <- BS.takeWhile p <$> getBuff
    continue <- atleastBytesLeft (length s)
    forkA continue (pure s) $ takeWhileAcc p s
{-# INLINE takeWhile #-}

takeWhile1 :: (Byte -> Bool) -> YP ByteString
takeWhile1 p = do
  (`when` void demandInput) =<< endOfBuffer
  s <- BS.takeWhile p <$> getBuff
  let len = length s
  if len /= 0
    then do
      advance len
      eoc <- endOfBuffer
      if eoc
        then takeWhileAcc p s
        else pure s
    else fault "takeWhile1"
{-# INLINE takeWhile1 #-}

takeWhileAcc :: (Byte -> Bool) -> ByteString -> YP ByteString
takeWhileAcc p = go
  where go acc = do
          s <- BS.takeWhile p <$> getBuff
          continue <- atleastBytesLeft (length s)
          if continue
           then go $ acc ++ s
           else pure $ acc ++ s
{-# INLINE takeWhileAcc #-}

between :: YP o
        -- ^ opening parser
        -> YP c
        -- ^ closing parser
        -> YP a
        -- ^ parser to satisfy inbetween
        -> YP a
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
grouping :: YP a -> YP s -> YP (Seq.Seq a)
grouping p v = between oParen cParen $ interleaved v p
  where interleaved s par = sepBy1Seq par (skipTo s <* spaces)

-- | Match a specific string.
string :: ByteString -> YP ByteString
string bs = stringWithMorph id bs
{-# INLINE string #-}

-- | Match one of the following strings, first one to match is successfull.
--
-- Note: not efficent since it backtracks after every failure.
-- Note: it matches in-order of list.
oneOfStrings :: [ByteString] -> YP ByteString
oneOfStrings [] = fault "oneOfStrings: passed empty list"
oneOfStrings ls = Prelude.foldl1 (<|>) (fmap string ls)
{-# INLINE oneOfStrings #-}

-- | Satisfy a literal string, ignoring case.
-- ASCII-specific but fast, oh yes.
stringIgnoreCase :: ByteString -> YP ByteString
stringIgnoreCase = stringWithMorph toLower
{-# INLINE stringIgnoreCase #-}

-- | To annotate
stringWithMorph :: (ByteString -> ByteString)
                -> ByteString -> YP ByteString
stringWithMorph fn sn = string_ (stringSuspend fn) fn sn where

  string_ :: (forall r. ByteString -> ByteString -> Buffer -> Env
          -> Failure r -> Success ByteString r -> Result r)
          -> (ByteString -> ByteString) -> ByteString -> YP ByteString
  string_ suspended f s0 = YP $ \b e l s ->
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
    go str = YP $ \b e l s -> let n = length (f str) in
      if | n >= m && unsafeTake m (f str) == s1 ->
               let o = length s0
               in s b (posMap (+o) e) (bufferSubstring (position e) o b)
         | str == unsafeTake n s1 ->
               stringSuspend f s0 (unsafeDrop n s1) b e l s
         | otherwise              -> l b e [] "string"
{-# INLINE stringWithMorph #-}

-- | Checks if there are atleast `n` bytes of buffer string left.
-- Parse always succeeds
atleastBytesLeft :: Int -> YP Bool
atleastBytesLeft i = YP $ \b e _ s ->
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
  where go = YP $ \b e l s ->
          let pos = position e in
          if bufferLengthAtLeast pos n b
            then s b e (bufferSubstring pos n b)
            else runParser (demandInput >> go) b e l s
{-# INLINE ensureSuspended #-}

-- | Immedidately demand more input via a 'Partial' continuation
-- result.
demandInput :: YP ByteString
demandInput = YP $ \b e l s ->
  case more e of
    Complete -> l b e [] "not enough input"
    _        -> Partial $ \bs -> if null bs
      then l b (e { more = Complete }) [] "not enough input"
      else s (bufferPappend b bs) (e { more = Incomplete }) bs
{-# INLINE demandInput #-}

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
scan :: s -> (s -> Byte -> Maybe s) -> YP ByteString
scan s0 p = scan_ id (\_ y -> pure y) p s0 <?> "scan"
{-# INLINE scan #-}

scanSt :: s -> (s -> Byte -> Maybe s) -> YP (s, ByteString)
scanSt s0 p = scan_ id (curry pure) p s0 <?> "scanSt"
{-# INLINE scanSt #-}

-- |
--   'scan s p = scanWith s p id'
--
-- ghci$ pred s w = if w > 73 then Nothing else Just False
-- ghci$ parse_ (scan_ False toLower pred) "ABCDEFGHIJKLMNOP"
-- "Done" "JKLMNOP" "abcdefghi"
--
scan_ :: (Byte -> Byte)
      -- ^ How to transform byte as scanning?
      -> (s -> ByteString -> YP r)
      -- ^ Do what with the final state and parsed bytestring?
      -> (s -> Byte -> Maybe s)
      -- ^ State Transformation
      -> s
      -- ^ Initial state value
      -> YP r
scan_ sft ret rho s0 = go "" s0 <?> "scan"
  where
    go acc s1 = do
      let scanner (PS fp off len) =
            withForeignPtr fp $ \ptr0 -> do
              let done !i !s = pure $! T i s
                  start = ptr0 `plusPtr` off
                  inner ptr !s
                    | ptr < (start `plusPtr` len) = do
                        w <- peek ptr
                        case rho s w of
                          Just s' -> do
                            pokeByteOff ptr 0 (sft w)
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
        else ret u $! acc ++ h
{-# INLINE scan_ #-}

-- | @SLToken@
-- Use only for tracking parsing tokens of a string literal.
data SLToken = EverythingOk
             | Finished
             | SeekingNewLine
             | NewLine
             | Escaping
             | OctalNumber
             | Hexadecimal
             | ErrorMsg ByteString
               deriving (Show, Eq)

-- | `quotedString` parses a string literal
-- Strings can contain the following escape bytes \" \\ \t \n \r and handle
-- string line breaks.
-- Returns the content of the string without the quotation bytes.
-- Careful as Haskell style strings differ from C style string literals
-- THESE parse as C style
stringLiteral :: YP ByteString
stringLiteral = do
  quote
  (s,b) <- getStringLiteralLines "" EverythingOk
  case s of
      Finished      -> b <$ quote
      ErrorMsg msg  -> fault msg
      _             -> fault $ "ERROR! The parser 'quotedStringWith' failed with uncaught final state: '" ++ C8.pack (show s) ++ "'"
  <?> "string literal"
  where
    -- YARA spec says matches 'getStringLiteralLines'
    getStringLiteralLines :: ByteString -> SLToken -> YP (SLToken, ByteString)
    getStringLiteralLines acc EverythingOk = do
       (st,bs) <- scanSt EverythingOk rho
       let acc_ = acc ++ bs
       case st of
         -- It gets a bit tricky, since newline bytes need to be parsed
         -- and ignored since a multi-line string literal will be handled as
         -- as single line after parsing. So. We are setting a rule that
         -- the only way to have "Escaping" returned as a state
         Escaping -> do
           endOfLine
           getStringLiteralLines acc_ EverythingOk

    isEscapableByte :: SLToken -> Byte -> Bool
    isEscapableByte OctalNumber = isOctByte --abefnrtv\'"?
    isEscapableByte Hexadecimal = isHexByte
    isEscapableByte _           = flip elem [97,98,101,102]

    rho :: SLToken -> Byte -> Maybe SLToken
    rho (ErrorMsg bs) _ = Nothing
    rho s b             = if
      ---if new line and escaping return nothing
      --if quote then return Nothing
      
        | b == 10 && s /= Escaping -> Just NewLine
        -- Escaped whitespace
        | s == Escaping && isHorizontalSpace b ->
                             Just (ErrorMsg "Unknowed escape sequence '\\ ' ")
        | s == Escaping && isEndOfLine b -> Just NewLine

        --  s == PassedNewLine && b is backslash -> Escaping
        | s == NewLine && not (isEndOfLine b) -> undefined

        -- Quote, preceeded by backslash is cool.
       --  | s == 92 && b == 34    -> if p b then Just b else Nothing
        --  | s == 92 && (isSpace b || b == 10 || b == 13)  -> Just s
         -- If unescaped quote mark => the string is closed => done scanning
        | b == 34 && s /= Escaping -> Nothing
{-# INLINE stringLiteral #-}




{- THE SALAVAGE YARD
Everything saved just in case.



{-
-- | If at least @n@ elements of input are available, return the
-- current input, otherwise fail.
ensure :: Int -> YP ByteString
ensure n = (YP $ \b e l s ->
    let pos = position e in
    if bufferLengthAtLeast pos n b
      then s b e (substring pos n b)
      -- The uncommon case is kept out-of-line to reduce code size:
      else ensureSuspended n b e l s
    ) <?> "ensure"
{-# INLINE ensure #-}
-}


---- | Match on of a specific list of strings
--strings :: Foldable f => f ByteString -> YP ByteString
--strings = foldMap string
--{-# INLINE strings #-}
--{-# SPECIALIZE strings :: Seq.Seq ByteString -> YP ByteString #-}
--{-# SPECIALIZE strings :: [ByteString] -> YP ByteString #-}



--sepByByte :: Semigroup a
--             => Byte -> YP a -> YP b -> YP (a,b)
--sepByByte b q p = pair (q <* space1 <* byte b <* space1) p


untuple :: (YP a, YP b) -> YP (a,b)
untuple (u,v) = pair u Nothing v <?> "untuples"
{-# INLINE untuple #-}



sepByw :: Default (f a)
      => (a -> f a -> f a)
      -> YP a
      -> YP s
      -> YP (f a)
sepByw f p s = liftA2 f p ((s *> sepByw1 f p s) <|> def) <|> def
{-# INLINE sepByw #-}

sepByw1 :: Default (f a)
        => (a -> f a -> f a)
        -> YP a
        -> YP s
        -> YP (f a)
sepByw1 f p s = let go = liftA2 f p ((s *> go) `mplus` def) in go
{-# SPECIALIZE sepByw1 :: (a -> Set.Set a -> Set.Set a) -> YP a
                                  -> YP s -> YP (Set.Set a) #-}
{-# INLINE sepByw1 #-}





-- | litString parses a literal string
-- Strings can contain the following escape bytes \" \\ \t \n \r and handle
-- string line breaks.
-- Returns the content of the string without the quotation bytes.
litString :: YP ByteString
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
takeNWhile :: Int -> (Word8 -> Bool) -> YP ByteString
takeNWhile n p = do
  (`when` demandInput) =<< endOfBuffer
  s <- BS.takeWhile p <$> getBuff
  continue <- inptSpansChunks (length s)
  if continue
    then takeWhileAcc p [s]
    else return s
{-# INLINE takeNWhile #-}

inputSpansChunks :: Int -> YP Bool
inputSpansChunks i = YP $ \_ t pos_ more _lose suc ->
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
option :: a -> YP a -> YP a
option x p = p <|> pure x <?> "option"
{-# INLINE option #-}




-- | Match either a single newline character @\'\\n\'@, or a carriage
-- return followed by a newline character @\"\\r\\n\"@.
endOfLine :: YP ()
endOfLine = void (byte 10) <|> void (string "\r\n")



alphaNum :: YP Byte
alphaNum = satisfy isAlphaNum  <?> "alphaNum"
{-# INLINE alphaNum #-}

space :: YP Byte
space = satisfy isSpace <?> "space"
{-# INLINE space #-}

spaces :: YP ByteString
spaces = takeWhile isSpace <?> "spaces"
{-# INLINE spaces #-}

space1 :: YP ByteString
space1 = takeWhile1 isSpace <?> "space1"
{-# INLINE space1 #-}


horizontalSpace :: YP Byte
horizontalSpace = satisfy isHorizontalSpace <?> "horizontalSpace"
{-# INLINE horizontalSpace #-}
-}
