{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE BlockArguments #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternGuards #-}
{-# LANGUAGE Rank2Types #-}
{-# LANGUAGE UnboxedTuples #-}
#ifdef hlint
{-# ANN module "HLint: ignore Eta reduce" #-}
#endif
-- |
-- Module      :  Yara.Parsing.Combinators
-- Copyright   :  David Heras 2019
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
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import Data.Int
import qualified Data.HashSet as HS
import Data.Scientific
import Data.String

-- -----------------------------------------------------------------------------
-- Fundamental Parsers

instance (a ~ ByteString) => IsString (Yp s a) where
    fromString = string . C8.pack

-- | Return remaining buffer as a bytestring
getBuff :: Yp s ByteString
getBuff = YP $ \b e _ _ s -> s e b (bufferUnsafeDrop (position e) b)
{-# INLINE getBuff #-}

-- | Return remaining buffer as a bytestring, adjust to set
-- offset at '0'.
getNormalizedBuff :: Yp s ByteString
getNormalizedBuff = YP $ \b e _ _ s ->
  let (PS ptr off len) = bufferUnsafeDrop (position e) b
  in  s e b $ PS (plusForeignPtr ptr off) 0 len
{-# INLINE getNormalizedBuff #-}

-- | Peek at next byte.
--
-- Note: Doesn't fail unless at the end of input.
peekByte :: Yp s Byte
peekByte = YP (\b e st l s ->
  let pos = position e in
  if bufferLengthAtLeast pos 1 b
    then s e b (bufferUnsafeIndex b pos)
    else l e "peekByte expected 1 byte" RemainingBufferToShort st
  ) <?> "peekByte"
{-# INLINE peekByte #-}

satisfy :: (Byte -> Bool) -> Yp s Byte
satisfy p = do
  h <- peekByte
  if p h
    then advance 1 $> h
    else fault InternalError "satisfy"
{-# INLINE satisfy #-}

-- | Match a specific byte.
byte :: Byte -> Yp s Byte
byte c = satisfy (== c) <?> sig c
{-# INLINE byte #-}

-- | Get next byte.
nextByte :: Yp s Byte
nextByte = satisfy $ const True
{-# INLINE nextByte #-}

-- | Return 'True' if buffer is empty
endOfBuffer :: Yp s Bool
endOfBuffer = liftA2 (==) getPos retBufLength
  where retBufLength = YP $ \b@(Buf _ _ l _ _) e _ _ s ->
          let p = position e
          in s e b $ assert (p >= 0 && p <= l) (l-p)
{-# INLINE endOfBuffer #-}

--- UTILITY PARSERS

-- | Run two parsers and return the pair of their results,
-- while running a possible seperator parser
pair :: Yp s a -> Yp s b -> Yp s (a,b)
pair u v = liftA2 (,) u v <?> "pair"
{-# INLINE pair #-}

-- | @many1@ parses one or more occurances of a parser.
many1 :: Yp s a -> Yp s [a]
many1 p = liftA2 (:) p (many p) <?> "many1"
{-# INLINE many1 #-}

-- | 'sepBy1Acc' fits into the category of seperated-parser combinators, but
-- it uses the `def` as the accumulator.
sepBy1Acc :: Default m => Yp s (m -> m) -> Yp s () -> Yp s m
sepBy1Acc p s = go def where go an = (do f <- p; s *> go (f an)) <|> def

sepByAcc :: Default m => Yp s (m -> m) -> Yp s () -> Yp s m
sepByAcc p s = (do v <- p; (s *> _sepBy1Acc (v def) p s) <|> def) <|> def
 where
   _sepBy1Acc _m _p _s = go _m where go an = (do f <- p; s *> go (f an)) <|> def
{-
sepBy1HashSet :: (Eq a, Hashable a) => Yp s a -> Yp s sep -> Yp s (HS.HashSet a)
sepBy1HashSet p s = fix $ \go -> liftA2 HS.insert p ((s *> go) <|> def)
{-# INLINE sepBy1HashSet #-}

sepByHashSet :: (Eq a, Hashable a) => Yp s a -> Yp s sep -> Yp s (HS.HashSet a)
sepByHashSet p s = liftA2 HS.insert p ((s *> sepBy1HashSet p s) <|> def) <|> def
{-# INLINE sepByHashSet #-}
-}
-- | Skip one or more instances of an action.
skipMany1 :: Yp s a -> Yp s ()
skipMany1 p = p *> skipMany p
{-# INLINE skipMany1 #-}

-- | @between@ also eats up any white space between the three
-- parsers.
between :: Yp s o
        -- ^ opening parser
        -> Yp s c
        -- ^ closing parser
        -> Yp s a
        -- ^ parser to satisfy inbetween
        -> Yp s a
between op cp p = op *> seek p <* seek cp
{-# INLINE between #-}

-- | Synonym for 'between oParen cParen'
delimited :: Yp s a -> Yp s a
delimited = between oParen cParen
{-# INLINE delimited #-}

-- | Parses a tuple. Eats in-between white space.
tuple :: Yp s a -> Yp s (T2 a a)
tuple p = liftA2 T2 (oParen *> seek p <* seek comma) (seek p <* seek cParen)
{-# INLINE tuple #-}

-- | Parses a range. Eats in-between white spacing.
range :: Yp s a -> Yp s (T2 a a)
range p = liftA2 T2 (sqBra *> seek p <* seek dash) (seek p <* seek sqKet)
{-# INLINE range #-}

-- |
grouped :: Yp s sep -> Yp s a -> Yp s [a]
grouped sep p = delimited $ sepBy1 (seek p) (seek sep)

--------------------------------------------------------------------------------
-- FIXED BYTE PARSERS

#define CP(n,v) n :: Yp s Byte; n = byte v; {-# INLINE n #-}
CP(tab,9)
CP(quote,34)
CP(dollar,36)
CP(oParen,40)
CP(cParen,41)
CP(asterick,42)
CP(plus,43)
CP(comma,44)
CP(dash,45)
CP(dot,46)
CP(fSlash,47)
CP(colon,58)
CP(lt,60)
CP(equal,61)
CP(gt,62)
CP(at,64)
CP(sqBra,91)
CP(bSlash,92)
CP(sqKet,93)
CP(oCurly,123)
CP(vertBar,124)
CP(cCurly,125)
#undef CP

ofTwo :: Yp s a -> Yp s b -> Yp s (Either a b)
ofTwo p q = (Left <$> p) <|> (Right <$> q)

ellipsis :: Yp s ()
ellipsis = void $ dot *> dot
{-# INLINE ellipsis #-}

------------------------------------------------------------------------
--- FAST PREDICATE PARSERS

-- Yes, I am that lazy.
#define GO(label,comb,pred) label = comb (pred) <?> "label"; {-# INLINE label #-}
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

------------------------------------------------------------------------
-- Numberical Combinators

hexStep :: (Bits b, Integral a, Num b) => b -> a -> b
hexStep a w
  | w >= 48 && w <= 57  = (a `shiftL` 4) .|. fromIntegral (w - 48)
  | w >= 97             = (a `shiftL` 4) .|. fromIntegral (w - 87)
  | otherwise           = (a `shiftL` 4) .|. fromIntegral (w - 55)

-- | @hexadecimal@
--
-- Parser expects a leading @\"0x\"@ or @\"0X\"@ string.
hexadecimal :: (Integral a, Bits a) => Yp s a
hexadecimal = do
  byte 48               -- '0'
  byte 88 <|> byte 120  -- 'X' or 'x'
  BS.foldl' hexStep 0 `fmap` takeWhile1 isHexByte
{-# SPECIALISE hexadecimal :: Yp s Int #-}
{-# SPECIALIZE hexadecimal :: Yp s Int64 #-}
{-# SPECIALISE hexadecimal :: Yp s Integer #-}
{-# SPECIALISE hexadecimal :: Yp s Word #-}
{-# INLINE hexadecimal #-}

decimal :: Integral a => Yp s a
decimal = BS.foldl' step 0 `fmap` takeWhile1 isDigit
  where step a b = a * 10 + fromIntegral (b - 48)
{-# SPECIALISE decimal :: Yp s Int #-}
{-# SPECIALISE decimal :: Yp s Int64 #-}
{-# SPECIALISE decimal :: Yp s Integer #-}
{-# SPECIALISE decimal :: Yp s Word #-}
{-# SPECIALISE decimal :: Yp s Word8 #-}
{-# SPECIALISE decimal :: Yp s Word64 #-}
{-# INLINE decimal #-}

-- A strict pair
data SP = SP {-# UNPACK #-} !Integer {-# UNPACK #-} !Int

scientifically :: (Scientific -> a) -> Yp s a
scientifically h = do

  let minus = 45
      plus  = 43
  sign <- peekByte
  let !positive = sign == plus || sign /= minus
  when (sign == plus || sign == minus) (void $ anyByte)

  n <- decimal

  let f fracDigits = SP (BS.foldl' step n fracDigits)
                        (negate $ BS.length fracDigits)
      step a w = a * 10 + fromIntegral (w - 48)

  dotty <- optional peekByte
  -- '.' -> asii 46
  SP c e <- case dotty of
              Just 46 -> anyByte *> (f <$> takeWhile isDigit)
              _       -> pure (SP n 0)

  let !signedCoeff | positive  =  c
                   | otherwise = -c

  let littleE = 101
      bigE    = 69
  (satisfy (\ex -> ex == littleE || ex == bigE) *>
      fmap (h . scientific signedCoeff . (e +)) (signed decimal)) <|>
      pure (h $ scientific signedCoeff    e)
{-# INLINE scientifically #-}


double :: Yp s Double
double = scientifically toRealFloat
{-# INLINABLE double #-}

-- | Parse a number with an optional leading @\'+\'@ or @\'-\'@ sign
-- character.
signed :: Num a => Yp s a -> Yp s a
signed p = (negate <$> (dash *> p))
       <|> (plus *> p)
       <|> p
{-# SPECIALISE signed :: Yp s Double -> Yp s Double #-}
{-# SPECIALISE signed :: Yp s Float -> Yp s Float #-}
{-# SPECIALISE signed :: Yp s Int -> Yp s Int #-}
{-# SPECIALISE signed :: Yp s Int8 -> Yp s Int8 #-}
{-# SPECIALISE signed :: Yp s Int16 -> Yp s Int16 #-}
{-# SPECIALISE signed :: Yp s Int32 -> Yp s Int32 #-}
{-# SPECIALISE signed :: Yp s Int64 -> Yp s Int64 #-}
{-# SPECIALISE signed :: Yp s Integer -> Yp s Integer #-}

------------------------------------------------------------------------

-- | skipToHz
-- Gobbles up horizontal space then applies parser
skipToHz :: Yp s a -> Yp s a
skipToHz = (*>) horizontalSpaces
{-# INLINE skipToHz #-}

-- | skipToHz1
-- same as skipTo but requires the occurance of atleast 1 horizonal space
skipToHz1 :: Yp s a -> Yp s a
skipToHz1 = (*>) horizontalSpace1
{-# INLINE skipToHz1 #-}

takeTill :: (Byte -> Bool) -> Yp s ByteString
takeTill p = takeWhile (not . p)
{-# INLINE takeTill #-}

takeWhile :: (Byte -> Bool) -> Yp s ByteString
takeWhile p = do
  s <- BS.takeWhile p <$> getBuff
  advance $ length s
  pure s
{-# INLINE takeWhile #-}

takeWhile1 :: (Byte -> Bool) -> Yp s ByteString
takeWhile1 p = do
  s <- BS.takeWhile p <$> getBuff
  let len = length s
  if len /= 0
    then do
      b <- advance len
      pure s
    else fault InternalError "takeWhile1"
{-# INLINE takeWhile1 #-}

-- -----------------------------------------------------------------------------
-- Specialty Parsers

-- | 'lineSeperated' is a parser that allows a compact way of consuming white
-- space but ensuring atleast 1 newline character is parsed. It continues to parse
-- any further whitespace (including more newlines).
lineSeperated :: Yp s ()
lineSeperated = do
  horizontalSpace  -- Parse remainder of any of current lines whitespace
  endOfLine        -- Parse atleast one newline token
  void spaces      -- Eatup any further whitespace

-- | 'seekOnNewLine' applies a 'lineSeperated'
seekOnNewLine :: Yp s a -> Yp s a
seekOnNewLine = (*>) lineSeperated
{-# INLINE seekOnNewLine #-}

-- | 'seek' gobbles upwhite space before a parser. Only slightly
-- neater than constaly type "spaces *>" its roughly the only solution
-- unless we could selectively override ">>=".
seek :: Yp s a -> Yp s a
seek = (*>) spaces
{-# INLINE seek #-}

-- | Match a specific string.
string :: ByteString -> Yp s ByteString
string bs = stringWithMorph id bs <?> "string"
{-# INLINE string #-}

-- | To annotate
stringWithMorph :: (ByteString -> ByteString)
                -> ByteString -> Yp s ByteString
stringWithMorph f s0 = YP $ \b e st l s ->
  let bs  = f s0
      n   = length bs
      pos = position e
      b_  = bufferSubstring pos n b
  in if
    | bufferLengthAtLeast pos n b && (s0 == f b_)  -> s (posMap (+n) e) b b_
    | otherwise                                    -> l e "stringWithMorph" InternalError st
{-# INLINE stringWithMorph #-}

-- | 'notFollowedBy'
--
-- When parsing keywords or name spaces, often need ensure a whitespace
-- (or other) follows. Tests if the peeked byte matches predicate.
-- If so, parser fails; else success. Does not consume any input.
notFollowedBy :: (Byte -> Bool) -> Yp s ()
notFollowedBy p = do
  b <- peekByte
  if p b
    then fault InternalError $ "predicate failed: found a '" ++ sig b ++ "'"
    else unit
  <?> "notFollowedBy"

-- | 'token' parses the bytestrings and returns the associated value
token :: ByteString -> a -> Yp s a
token bs v = string bs $> v <?> "token"
{-# INLINE token #-}

-- | 'tokens'
-- A very useful combinator that takes a list of pairs of
-- bytestrings (to match) and values (to return) and attempts to
-- parse them in order.
tokens :: [T2 ByteString a] -> Yp s a
tokens ls = asumMap (\(T2 s v) -> token s v) ls <?> "tokens"
{-# INLINE tokens #-}

relOp :: Ord a => Yp s (a -> a -> Bool)
relOp = tokens [
    T2 "<"  (<)
  , T2 "<=" (<=)
  , T2 ">"  (>)
  , T2 ">=" (>=)
  , T2 "==" (==)
  , T2 "!=" (/=)
  ] <|> fault InternalError "ordering"
  <?> "relOp"
{-# INLINE relOp #-}
{-# SPECIALIZE relOp :: Yp s (Int64 -> Int64 -> Bool) #-}
{-# SPECIALIZE relOp :: Yp s (Integer -> Integer -> Bool) #-}
{-# SPECIALIZE relOp :: Yp s (Int -> Int -> Bool) #-}
{-# SPECIALIZE relOp :: Yp s (Word -> Word -> Bool) #-}
{-# SPECIALIZE relOp :: Integral a => Yp s (a -> a -> Bool) #-}


-- | 'isSucc' runs a parser and returns True\False if it is successful\failed,
-- discards the results (although any "stateful" effects will occur -- hence
-- usually used when in cases that have no effec)
isSucc :: Yp s a -> Yp s Bool
isSucc p = (p $> True) <|> pure False







{-

{- import GHC.Exts (IsList(..))
consIsList :: (IsList l1, IsList l2, Item l1 ~ Item l2) => Item l2 -> l2 -> l1
consIsList x y = fromList $ x : toList y
{-# INLINABLE consIsList #-}
{-# SPECIALIZE consIsList :: Item a -> [a] -> [a] #-}
{-# SPECIALIZE consIsList :: (Eq a, Hashable a)
o                          => Item a
                          -> HS.HashSet a
                          -> [a]                    #-}


defIsList :: IsList f => f a
defIsList = fromList []

sepBy1 :: (IsList f) => Yp s a -> Yp s sep -> Yp s (f a)
sepBy1 p s = fix $ \go -> liftA2 consIsList p ((s *> go) `mplus` def)
{-# INLINE sepBy1 #-}

sepBy :: (IsList f) => Yp s a -> Yp s sep -> Yp s (f a)
sepBy p s = liftA2 consIsList p ((s *> sepBy1 p s) <|> def) <|> def
{-# INLINE sepBy #-}
-}



odd !_ !_ = ()
{-# INLINE odd #-}

oddSepBy1 :: Yp s a -> Yp s sep -> Yp s ()
oddSepBy1 p s = fix $ \go -> liftA2 odd p ((s *> go) `mplus` def)
{-# INLINE oddSepBy1 #-}

oddSepBy :: Yp s a -> Yp s sep -> Yp s ()
oddSepBy p s = liftA2 odd p ((s *> oddSepBy1 p s) <|> def) <|> def
{-# INLINE oddSepBy #-}

-}
