{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE BlockArguments #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE Rank2Types #-}
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
module Yara.Parsing.Combinators where

import Yara.Prelude
import Yara.Parsing.AST
import Yara.Parsing.Buffer
import Yara.Parsing.Parser

import Data.Bits
import qualified Data.ByteString       as BS (takeWhile, foldl')
import qualified Data.ByteString.Char8 as C8
import Data.ByteString.Internal
import Data.ByteString.Unsafe
import Data.Default
import Data.Int
import Data.Sequence ((<|))
import Data.String
import Foreign hiding (void)

import qualified Data.Map.Strict as Map
import qualified Data.Sequence   as Seq
import qualified Data.Set        as Set
--- GHC.IO.Buffer


-- -----------------------------------------------------------------------------
-- Fundamental Parsers


instance (a ~ ByteString) => IsString (Yp a) where
    fromString = string . C8.pack

-- | Return remaining buffer as a bytestring
getBuff :: Yp ByteString
getBuff = YP $ \b e _ s -> s b e (bufferUnsafeDrop (position e) b)
{-# INLINE getBuff #-}

-- | Peek at next byte.
--
-- Note: Doesn't fail unless at the end of input.
peekByte :: Yp Byte
peekByte = YP $ \b e l s ->
  let pos = position e in
  if bufferLengthAtLeast pos 1 b
    then s b e (bufferUnsafeIndex b pos)
    else ensureSuspended 1 b e l (\b_ e_ bs_ -> (s b_ e_ $! unsafeHead bs_))
{-# INLINE peekByte #-}

satisfy :: (Byte -> Bool) -> Yp Byte
satisfy p = do
  h <- peekByte
  if p h
    then advance 1 $> h
    else fault_ "satisfy"
{-# INLINE satisfy #-}

-- | Match a specific byte.
byte :: Byte -> Yp Byte
byte c = satisfy (== c)
         <?> sig c
{-# INLINE byte #-}

-- | Match any byte except the given one.
notByte :: Byte -> Yp Byte
notByte c = satisfy (/= c)
            <?> "not '" +> c ++ "'"
{-# INLINE notByte #-}

-- | Get next byte.
nextByte :: Yp Byte
nextByte = satisfy $ const True
{-# INLINE nextByte #-}

-- | Return 'True' if buffer is empty
endOfBuffer :: Yp Bool
endOfBuffer = liftA2 (==) getPos retBufLength
  where retBufLength = YP $ \b@(Buf _ _ l _ _) e _ s ->
          let p = position e
          in s b e $ assert (p >= 0 && p <= l) (l-p)
{-# INLINE endOfBuffer #-}
 {-YP $ \b@(Buf _ _ l _ _) e _ s ->
  let p = position e
  in


  liftA2 (==) do
   p <- getPos
   l <- retBufLength
   pure 
  where retBufLength = YP $ \b@(Buf _ _ l _ _) e _ s ->
          let p = position e
          in s b e $ assert (p >= 0 && p <= l) (l-p)-}


#define GO(func,pred) func :: Byte -> Bool; func = pred; {-# INLINE func #-}
GO(isDot,(==46))
GO(isEqual, (==61))
GO(isAlpha,\b -> b - 65 < 26 || b - 97 < 26)
-- | A fast digit predicate.
GO(isDigit,\b -> b - 48 <= 9)
GO(isAlphaNum, isDigit <> isAlpha)
GO(isSpace, \b -> b == 32 || b - 9 <= 4)
-- | A predicate that matches either a carriage return @\'\\r\'@ or
-- newline @\'\\n\'@ character.
GO(isEndOfLine, (== 13) <> (== 10))
-- | A predicate that matches either a space @\' \'@ or horizontal tab
-- @\'\\t\'@ character.
GO(isHorizontalSpace, (== 32) <> (== 9))
#undef GO


-- | This parser always succeeds.  It returns 'True' if the end
-- of all input has been reached, and 'False' if any input is available
atEnd :: Yp Bool
atEnd = YP $ \b e _ s ->
  if | position e < bufferLength b  -> s b e True
     | more e == False              -> s b e False
     | otherwise                    -> prompt (\b_ e_ -> s b_ e_ False)
                                              (\b_ e_ -> s b_ e_ True)
                                              b e
{-# INLINE atEnd #-}

-- | Match only if all input has been consumed.
endOfInput :: Yp ()
endOfInput = YP $ \b e l s ->
  if | position e < bufferLength b  -> l b e "end-of-input" EndOfInput
     | more e == False              -> s b e ()
     | otherwise  -> runParser demandInput b e (failure EndOfInput "endOfInput")
                                               (\b_ e_ _   -> s b_ e_ ())
{-# INLINE endOfInput #-}

--- UTILITY PARSERS

-- | Run two parsers and return the pair of their results,
-- while running a possible seperator parser
pair :: Yp a -> Maybe (Yp s) -> Yp b -> Yp (a,b)
pair u p v = liftA2 (,) (u <* maybe unit void p) v <?> "pair"
{-# INLINE pair #-}

option :: a -> Yp a -> Yp a
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
perhaps :: Yp a -> Yp (Maybe a)
perhaps v = (Just <$> v) <|> pure Nothing <?> "perhaps"
{-# INLINE perhaps #-}

-- | @many1@ parses one or more occurances of a parser.
--
-- >>> parse_ (many1 colon) ":::yara"
-- Done "yara" [58, 58, 58]
--
many1 :: Yp a -> Yp [a]
many1 p = liftA2 (:) p (many p) <?> "many1"
{-# INLINE many1 #-}

sepBy :: Yp a -> Yp s -> Yp [a]
sepBy p s = liftA2 (:) p ((s *> sepBy1 p s) <|> def) <|> def <?> "sepBy"
{-# INLINE sepBy #-}

sepBySet :: Ord a => Yp a -> Yp s -> Yp (Set.Set a)
sepBySet p s = liftA2 Set.insert p ((s *> sepBy1Set p s) <|> def) <|> def
{-# INLINE sepBySet #-}

sepByMap :: Ord k => Yp (k,a)
                  -> Yp s
                  -> Yp (Map.Map k a)
sepByMap p s =
  liftA2 (uncurry Map.insert) p ((s *> sepBy1Map p s) <|> def) <|> def
{-# INLINE sepByMap #-}

sepBySeq :: Yp a -> Yp s -> Yp (Seq.Seq a)
sepBySeq p s = liftA2 (<|) p ((s *> sepBy1Seq p s) <|> def) <|> def
{-# INLINE sepBySeq #-}

sepBy1 :: Yp a -> Yp s -> Yp [a]
sepBy1 p s = let go = liftA2 (:) p ((s *> go) `mplus` def) in go
{-# INLINE sepBy1 #-}

sepBy1Set :: Ord a => Yp a -> Yp s -> Yp (Set.Set a)
sepBy1Set p s = let go = liftA2 Set.insert p ((s *> go) `mplus` def) in go
{-# INLINE sepBy1Set #-}

sepBy1Map :: Ord k => Yp (k,a)
                          -> Yp s -> Yp (Map.Map k a)
sepBy1Map p s =
  let go = liftA2 (uncurry Map.insert) p ((s *> go) `mplus` def) in go
{-# INLINE sepBy1Map #-}

sepBy1Seq :: Yp a -> Yp s -> Yp (Seq.Seq a)
sepBy1Seq p s = let go = liftA2 (<|) p ((s *> go) `mplus` def) in go
{-# INLINE sepBy1Seq #-}

manyTill :: Yp a -> Yp b -> Yp [a]
manyTill p end = (end $> []) <|> liftA2 (:) p (manyTill p end)
{-# INLINE manyTill #-}

-- | Skip zero or more instances of an action.
skipMany :: Yp a -> Yp ()
skipMany p = (p *> skipMany p) <|> unit
{-# INLINE skipMany #-}

-- | Skip one or more instances of an action.
skipMany1 :: Yp a -> Yp ()
skipMany1 p = p *> skipMany p
{-# INLINE skipMany1 #-}

-- | Apply the iven action repeatedly, returning every result.
count :: Int -> Yp a -> Yp [a]
count = replicateM
{-# INLINE count #-}

-- FIXED BYTE PARSERS
#define CP(n,v) n :: Yp Byte; n = byte v; {-# INLINE n #-}
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

ordering :: Yp LinearOrder
ordering = do
  (b1,b2) <- peekBytes2
  case (b1,b2) of
    (61,61) -> ret 2 Equal
    (60,61) -> ret 2 LessThanOrEqual
    (62,61) -> ret 2 GreaterThanOrEqual
    (60,_)  -> ret 1 LessThan
    (61,_)  -> ret 1 GreaterThan
    _       -> fault_ "ordering"
  <?> "ordering"
  where
    ret a b = advance a $> b
    -- Peek at the next 2 bytes in the buffer. Does not consume input.
    peekBytes2 :: Yp (Byte,Byte)
    peekBytes2 =  YP $ \b e l s ->
      let pos = position e
      in if bufferLengthAtLeast pos 2 b
       then s b e (bufferUnsafeIndex b pos, bufferUnsafeIndex b (pos+1))
       else ensureSuspended 2 b e l (\b_ e_ bs_ -> s b_ e_ $! unsafeHead2 bs_)
    -- unsafe-head the first two bytes of a bytestring and return them
    -- as a pair.
    unsafeHead2 :: ByteString -> (Byte, Byte)
    unsafeHead2 (PS x s l) = assert (l > 1) $
      accursedUnutterablePerformIO $ withForeignPtr x $ \p ->
                            liftA2 (,) (peekByteOff p s) (peekByteOff p (s+1))
{-# INLINE ordering #-}

ellipsis :: Yp ()
ellipsis = void $ dot *> dot
{-# INLINE ellipsis #-}

--- FAST PREDICATE PARSERS

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
hexadecimal :: (Integral a, Bits a) => Yp a
hexadecimal = do
  byte 48               -- '0'
  byte 88 <|> byte 120  -- 'X' or 'x'
  BS.foldl' step 0 `fmap` takeWhile1 isHexByte
  where
    step a w | w >= 48 && w <= 57  = (a `shiftL` 4) .|. fromIntegral (w - 48)
             | w >= 97             = (a `shiftL` 4) .|. fromIntegral (w - 87)
             | otherwise           = (a `shiftL` 4) .|. fromIntegral (w - 55)
{-# SPECIALISE hexadecimal :: Yp Int #-}
{-# SPECIALIZE hexadecimal :: Yp Int64 #-}
{-# SPECIALISE hexadecimal :: Yp Integer #-}
{-# SPECIALISE hexadecimal :: Yp Word #-}
{-# INLINE hexadecimal #-}

decimal :: Integral a => Yp a
decimal = BS.foldl' step 0 `fmap` takeWhile1 isDigit
  where step a b = a * 10 + fromIntegral (b - 48)
{-# SPECIALISE decimal :: Yp Int #-}
{-# SPECIALISE decimal :: Yp Int64 #-}
{-# SPECIALISE decimal :: Yp Integer #-}
{-# SPECIALISE decimal :: Yp Word #-}
{-# INLINE decimal #-}

-- | skipTo
-- Gobbles up whitespace then applies parser
skipTo :: Yp a -> Yp a
skipTo = (*>) spaces
{-# INLINE skipTo #-}


-- | skipToHz
-- Gobbles up horizontal space then applies parser
skipToHz :: Yp a -> Yp a
skipToHz = (*>) horizontalSpaces
{-# INLINE skipToHz #-}

-- | skipToHz1
-- same as skipTo but requires the occurance of atleast 1 horizonal space
skipToHz1 :: Yp a -> Yp a
skipToHz1 = (*>) horizontalSpace1
{-# INLINE skipToHz1 #-}


-- | Skip past input for as long as the predicate returns 'True'.
skipWhile :: (Byte -> Bool) -> Yp ()
skipWhile p = go
 where
  go = do
    t <- BS.takeWhile p <$> getBuff
    continue <- atleastBytesLeft $ length t
    when continue go
{-# INLINE skipWhile #-}

takeTill :: (Byte -> Bool) -> Yp ByteString
takeTill p = takeWhile (not . p)
{-# INLINE takeTill #-}

takeWhile :: (Byte -> Bool) -> Yp ByteString
takeWhile p = do
    s <- BS.takeWhile p <$> getBuff
    continue <- atleastBytesLeft (length s)
    if continue
      then takeWhileAcc p s
      else pure s
{-# INLINE takeWhile #-}

takeWhile1 :: (Byte -> Bool) -> Yp ByteString
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
    else fault_ "takeWhile1"
{-# INLINE takeWhile1 #-}

takeWhileAcc :: (Byte -> Bool) -> ByteString -> Yp ByteString
takeWhileAcc p = go
  where go acc = do
          s <- BS.takeWhile p <$> getBuff
          continue <- atleastBytesLeft (length s)
          if continue
           then go $ acc ++ s
           else pure $ acc ++ s
{-# INLINE takeWhileAcc #-}

between :: Yp o
        -- ^ opening parser
        -> Yp c
        -- ^ closing parser
        -> Yp a
        -- ^ parser to satisfy inbetween
        -> Yp a
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
grouping :: Yp a -> Yp s -> Yp (Seq.Seq a)
grouping p v = between oParen cParen $ interleaved v p
  where interleaved s par = sepBy1Seq par (skipTo s <* spaces)

-- | Match a specific string.
string :: ByteString -> Yp ByteString
string bs = stringWithMorph id bs
{-# INLINE string #-}

-- | Match one of the following strings, first one to match is successfull.
--
-- Note: not efficent since it backtracks after every failure.
-- Note: it matches in-order of list.
oneOfStrings :: [ByteString] -> Yp ByteString
oneOfStrings [] = fault_ "oneOfStrings: passed empty list"
oneOfStrings ls = foldl1 (<|>) (fmap string ls)
{-# INLINE oneOfStrings #-}

-- | Satisfy a literal string, ignoring case.
-- ASCII-specific but fast, oh yes.
stringIgnoreCase :: ByteString -> Yp ByteString
stringIgnoreCase = stringWithMorph toLower
{-# INLINE stringIgnoreCase #-}

-- | To annotate
stringWithMorph :: (ByteString -> ByteString)
                -> ByteString -> Yp ByteString
stringWithMorph fn sn = string_ (stringSuspend fn) fn sn
  where
    string_ :: (forall r. ByteString -> ByteString -> Buffer -> Env
            -> Failure r -> Success ByteString r -> Result r)
            -> (ByteString -> ByteString) -> ByteString -> Yp ByteString
    string_ suspended f s0 = YP $ \b e l s ->
      let bs  = f s0
          n   = length bs
          pos = position e
          b_  = bufferSubstring pos n b
          t_  = bufferUnsafeDrop pos b
      in if
        | bufferLengthAtLeast pos n b && (bs == f b_)  -> s b (posMap (+n) e) b_
        | f t_ `isPrefixOf` bs   -> suspended bs (drop (length t_) bs) b e l s
        | otherwise              -> failure "stringWithMorph" GenericException

    stringSuspend :: (ByteString -> ByteString)
                  -> ByteString -> ByteString -> Buffer -> Env
                  -> Failure r -> Success ByteString r -> Result r
    stringSuspend f s0 s1 = runParser (demandInput >>= go) where
      m = length s1
      go str = YP $ \b e l s ->
        let n = length (f str)
            pos = position e
            fp = filepath e
        in 
        if | n >= m && unsafeTake m (f str) == s1 ->
               let o = length s0
               in s b (posMap (+o) e) (bufferSubstring pos o b)
           | str == unsafeTake n s1 ->
               stringSuspend f s0 (unsafeDrop n s1) b e l s
           | otherwise              -> fault_ "string "-- l b e [] "string"
{-# INLINE stringWithMorph #-}

-- | Checks if there are atleast `n` bytes of buffer string left.
-- Parse always succeeds
atleastBytesLeft :: Int -> Yp Bool
atleastBytesLeft i = YP $ \b e _ s ->
  let pos = position e + i in
  if pos < bufferLength b || more e == False
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
demandInput :: Yp ByteString
demandInput = YP $ \b e l s ->
  let nei = ParseException (filepath e) "demandInput" (position e) NotEnoughInput
  in case more e of
    False -> l b e [] nei
    _     -> Partial $ \bs -> if isEmpty bs
      then l b (e { more = False }) [] nei
      else s (bufferPappend b bs) (e { more = True }) bs
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
scan :: s -> (s -> Byte -> Maybe s) -> Yp ByteString
scan s0 p = scan_ id (\_ y -> pure y) p s0 <?> "scan"
{-# INLINE scan #-}

scanSt :: s -> (s -> Byte -> Maybe s) -> Yp (s, ByteString)
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
      -> (s -> ByteString -> Yp r)
      -- ^ Do what with the final state and parsed bytestring?
      -> (s -> Byte -> Maybe s)
      -- ^ State Transformation
      -> s
      -- ^ Initial state value
      -> Yp r
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



-- -----------------------------------------------------------------------------
-- Specialty Parsers


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
stringLiteral :: Yp ByteString
stringLiteral = do
  quote
  (s,b) <- getStringLiteralLines "" EverythingOk
  case s of
      Finished      -> b <$ quote
      ErrorMsg msg  -> fault_ msg
      _             -> fault_ $ "ERROR! The parser 'quotedStringWith' failed with uncaught final state: '" ++ C8.pack (show s) ++ "'"
  <?> "string literal"
  where
    -- YARA spec says matches 'getStringLiteralLines'
    getStringLiteralLines :: ByteString -> SLToken -> Yp (SLToken, ByteString)
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

-- | 'lineSeperated' is a parser that allows a compact way of consuming white
-- space but ensuring atleast 1 newline character is parsed. It continues to parse
-- any further whitespace (including more newlines).
lineSeperated :: Yp ()
lineSeperated = do
  horizontalSpace  -- Parse remainder of any of current lines whitespace
  endOfLine        -- Parse atleast one newline token
  void $ spaces    -- Eatup any further whitespace

-- | 'seekOnNewLine' applies a 'lineSeperated'
seekOnNewLine :: Yp a -> Yp a
seekOnNewLine = (*>) lineSeperated


-- | Following three are for YARA strings.
#define PD(func,pred) func :: Byte -> Bool; func = pred; {-# INLINE func #-}
PD(isUnderscore,(== 95))
PD(isLeadingByte,isAlpha <> isUnderscore)
PD(isIdByte,isAlphaNum <> isUnderscore)
#undef PD


{- THE COMBINATOR GRAVE/SALAVAGE YARD
Everything saved just in case.



{-
-- | If at least @n@ elements of input are available, return the
-- current input, otherwise fail.
ensure :: Int -> Yp ByteString
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
--strings :: Foldable f => f ByteString -> Yp ByteString
--strings = foldMap string
--{-# INLINE strings #-}
--{-# SPECIALIZE strings :: Seq.Seq ByteString -> YP ByteString #-}
--{-# SPECIALIZE strings :: [ByteString] -> Yp ByteString #-}



--sepByByte :: Semigroup a
--             => Byte -> Yp a -> Yp b -> Yp (a,b)
--sepByByte b q p = pair (q <* space1 <* byte b <* space1) p


untuple :: (Yp a, Yp b) -> Yp (a,b)
untuple (u,v) = pair u Nothing v <?> "untuples"
{-# INLINE untuple #-}



sepByw :: Default (f a)
      => (a -> f a -> f a)
      -> Yp a
      -> Yp s
      -> Yp (f a)
sepByw f p s = liftA2 f p ((s *> sepByw1 f p s) <|> def) <|> def
{-# INLINE sepByw #-}

sepByw1 :: Default (f a)
        => (a -> f a -> f a)
        -> Yp a
        -> Yp s
        -> Yp (f a)
sepByw1 f p s = let go = liftA2 f p ((s *> go) `mplus` def) in go
{-# SPECIALIZE sepByw1 :: (a -> Set.Set a -> Set.Set a) -> Yp a
                                  -> Yp s -> Yp (Set.Set a) #-}
{-# INLINE sepByw1 #-}





-- | litString parses a literal string
-- Strings can contain the following escape bytes \" \\ \t \n \r and handle
-- string line breaks.
-- Returns the content of the string without the quotation bytes.
litString :: Yp ByteString
litString = quote *> (go "") <* quote <?> "litString"
  where
    -- s - stores previous char
    go s w
      -- If quote, not preceeded by backslash, the string is closed.
      | s /= 92 && w == 34   = Nothing
      -- Quote, preceeded by backslash is cool.
      | s == 92 && w == 34   = Just w

o      | s == 92 && (isSpace w || isNewline w)  = Just ~~tricky



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

-- ? between (str "\"") (str "\"")  many $ choice [alphaNum, escapeseq,
                                                     --  doublequote, whitespace]
--escQuot :: Parser Word8
--escQuot = bSlash *> quot

--- | Parse one or more occurances of 'a' perated by a delinator 'sep'

--intersperse :: Foldable f => Parser sep -> f (Parser a) -> Parser (f a)
--intersperse may not need

-- | Consume input until either:
-- 1) the predicate fails
-- /or/
-- 2) n-bytes are consumed. If the immediately following byte (n+1th) satisfies
-- pred, then the parser fails.
--
-- Must consume atleast /one/ eventhough the parser name is not followed by a '1'.
takeNWhile :: Int -> (Word8 -> Bool) -> Yp ByteString
takeNWhile n p = do
  (`when` demandInput) =<< endOfBuffer
  s <- BS.takeWhile p <$> getBuff
  continue <- inptSpansChunks (length s)
  if continue
    then takeWhileAcc p [s]
    else return s
{-# INLINE takeNWhile #-}

inputSpansChunks :: Int -> Yp Bool
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
option :: a -> Yp a -> Yp a
option x p = p <|> pure x <?> "option"
{-# INLINE option #-}

alphaNum :: Yp Byte
alphaNum = satisfy isAlphaNum  <?> "alphaNum"
{-# INLINE alphaNum #-}

space :: Yp Byte
space = satisfy isSpace <?> "space"
{-# INLINE space #-}

spaces :: Yp ByteString
spaces = takeWhile isSpace <?> "spaces"
{-# INLINE spaces #-}

space1 :: Yp ByteString
space1 = takeWhile1 isSpace <?> "space1"
{-# INLINE space1 #-}


horizontalSpace :: Yp Byte
horizontalSpace = satisfy isHorizontalSpace <?> "horizontalSpace"
{-# INLINE horizontalSpace #-}

-- | Peek at the next 'N' number of bytes
peekNBytes :: Word -> Yp ByteString
peekNBytes n = YP $ \b e l s ->
  let pos = position e
  in if bufferLengthAtLeast pos n b
       then s b e (bufferSubstring (fromIntegral pos) n b)
       else ensureSuspended 1 b e l (\b_ e_ bs_ -> s b_ e_ $! unsafeHead bs_)
{-# INLINE peekNBytes #-}

-- | @followedBy p@ only succeeds when parser @p@ succeeds.
--
-- Note: does not consume any input. It tests if the parser would succeed.
-- When parsing keywords or name spaces, we usually want
-- to make ensure such is followed by a whitespace.
--
-- Note: /Backtracking is expensive/. The combinators is mostly to be used
-- on single byte parsing predicates.
--
-- Why the type @Yp a -> Yp ()@, instead of say
-- @(Word8 -> Bool) -> Yp ()@ if its used primarily for matching on
-- single bytes? Occasionally we do need to match on a pair of bytes.
--
--
-- End lines are sometimes not just a byte but a pair of bytes "\r\n" so
-- we can pass in any parser ('void'-ing out result type if needed).
followedBy :: Yp a -> Yp ()
followedBy p = YP $ \b e l s ->
  case parse (void p) e (bufferUnsafeDrop (position e) b) of
    Fail{}    -> l b e [] "followedBy"
    Done{}    -> s b e ()
    Partial{} -> prompt (\b_ e_ -> s b_ e_ ())
                        (\b_ e_ -> l b_ e_ ["followedBy"] "followedBy")
                        b e
-}
