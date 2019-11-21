{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE BlockArguments #-}
{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ViewPatterns #-}
{-# OPTIONS_GHC -funbox-strict-fields #-}
-- |
-- Module      :  Yara.Parsing.ByteStrings
-- Copyright   :  David Heras 2018-2019
-- License     :  GPL-3
--
-- Maintainer  :  dheras@protonmail.com
-- Stability   :  experimental
-- Portability :  unknown
--
-- To annotate.
--
module Yara.Parsing.ByteStrings where

import Yara.Prelude
import Yara.Parsing.Combinators
import Yara.Parsing.Constants
import Yara.Parsing.Parser

import Foreign
import Data.ByteString.Unsafe
import qualified Data.HashMap.Strict as H

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

scan_ :: (Byte -> Byte)
       -- ^ How to transform byte as scanning?
       -> (s -> ByteString -> Yp r)
       -- ^ Do what with the final state and parsed bytestring?
       -> (s -> Byte -> Maybe s)
       -- ^ State Transformation
       -> s
       -- ^ Initial state value
       -> Yp r
scan_ shift !ret !rho !s0 = do
  bs@(PS fp off len) <- getBuff
  let T2 i u = accursedUnutterablePerformIO $
        withForeignPtr fp $ \ptr0 -> do
          let done !i !s = pure $! T2 i s
              start = ptr0 ~+ off
              inner ptr !s
                | ptr < (start ~+ len) = do
                    w <- peek ptr
                    case rho s w of
                      Just s' -> do
                        pokeByteOff ptr 0 (shift w)
                        inner (ptr ~+ 1) s'
                      _       -> done (ptr ~- start) s
                | otherwise = done (ptr ~- start) s
          inner start s0
  advance i
  ret u $! unsafeTake i bs
  <?> "scan_"
{-# INLINE scan_ #-}

------------------
-- Text Strings

hexPairToByte :: Byte -> Byte -> Byte
hexPairToByte b1 b2 =
  assert (isHexByte b1) $!   -- Do these two bool checks add a lot of
    assert (isHexByte b2) $! -- time or should they be left?
      0 `hexStep` b1 `hexStep` b2
{-# INLINE hexPairToByte #-}

data TSTok = TSNorm
           | TSEscp
           | TSHexEscp
           | TSHex1 Byte
           | TSHex2 Byte
           --
           | TSBadNewLn
           | TSBadByte Byte
           | TSUnrecEsc Byte
           | TSUnrecHex Byte
           --
           | TSClosed
           | TSFin Int

modifyByte :: Byte -> TSTok -> TSTok -> Byte
modifyByte 110 TSEscp     TSNorm     = 10
modifyByte 116 TSEscp     TSNorm     = 9
modifyByte _   (TSHex1 _) (TSHex2 w) = w
modifyByte b   _          _          = b
{-# INLINE modifyByte #-}

updateState :: (Byte -> Bool) -> Byte -> TSTok -> TSTok
updateState pred b TSNorm
  | b == 34        = TSClosed
  | b == 92        = TSEscp
  | isEndOfLine b  = TSBadNewLn
  | pred b         = TSNorm
  | otherwise      = TSBadByte b
updateState pred b (TSHex1 p)
  | isHexByte b = let w = hexPairToByte b p in
          if pred w then TSHex2 w else TSBadByte w
  | otherwise   = TSUnrecHex b
updateState pred b (TSHex2 _) = updateState pred b TSNorm
updateState _ b TSEscp
  | b `elem` ([34,92,110,116] ::[Byte])= TSNorm
  | b `elem` ([88,120]::[Byte])    = TSHexEscp
  | otherwise                = TSUnrecEsc b
updateState _ b TSHexEscp
  | isHexByte b = TSHex1 b
  | otherwise   = TSUnrecHex b
updateState _ b s@(TSUnrecEsc v)
  | isHorizontalSpace v && isEndOfLine b       = TSNorm
  | isHorizontalSpace v && isHorizontalSpace b = s
  | otherwise = s
updateState _ _ TSBadNewLn       = TSBadNewLn
updateState _ _ TSClosed         = TSClosed
updateState _ _ s@(TSBadByte _)  = s
updateState _ _ s@(TSUnrecHex _) = s
updateState _ _ s@(TSFin _)      = s
{-# INLINE updateState #-}

-- [*] The inner loop @atomic@ below is identical
-- to 'removeComments' from "Yara.Parser.Preprocess." See
-- that for documentation.
-- | @textString@ parses a string literal.
--
-- Text strings can contain the following
-- subset of the escape sequences available
-- in the C language:
--   \"     Double quote
--   \\     Backslash
--   \t     Horizontal tab
--   \n     New line
--   \xdd   Any byte in hexadecimal notation
--
textStringWith :: (Byte -> Bool) -> Yp ByteString
textStringWith pred = do
  bs <- quote *> getNormalizedBuff
  let atomic :: TSTok -> Ptr Byte -> Int -> Int -> IO (Int, TSTok)
      atomic TSClosed         _ t h = pure (t,TSFin h)
      atomic s@TSBadNewLn     _ _ h = pure (h,s)
      atomic s@(TSUnrecEsc _) _ _ h = pure (h,s)
      atomic s@(TSUnrecHex _) _ _ h = pure (h,s)
      atomic !s !ptr !tort !hare
        | hare >= (length bs) = pure (tort,s)
        | otherwise           = do
           b <- peekByteOff ptr hare
           let st = updateState pred b s
               w  = modifyByte b s st
           t <- if
             | TSNorm   <- st -> pokeByteOff ptr tort w $> tort+1
             | TSHex2 g <- st -> pokeByteOff ptr tort g $> tort+1
             | otherwise      -> pure tort
           atomic st ptr t (hare+1)
      {-# INLINE atomic #-}
      (b,s) = atomicModification atomic TSNorm bs
  case s of
    TSFin n      -> advance n $> b
    TSBadNewLn   -> fault UnexpectedNewline "unexpected new line found"
    TSUnrecHex v -> fault UnrecognizedEscapeCharacter $
                     "expecting a hexadecimal character but found '" +> v +> 39
    TSUnrecEsc v -> fault UnrecognizedEscapeCharacter $
                     39 <+ v <+ "' not a permitted escape character"
    TSBadByte v  -> fault UnrecognizedEscapeCharacter $
                     39 <+ v <+ "' failed the predicate"
    _            -> fault_ "here"
  <?> "stringLiteral"
{-# INLINABLE textStringWith #-}

textString :: Yp ByteString
textString = textStringWith $ \_ -> True
{-# INLINE textString #-}


----------------------------
-- Identifiers

-- possiby temporary. does the parsing of an identifier
-- but doesnt check if imported. very helpful.
_identifier :: Yp ByteString
_identifier = do
  r <- scan 0 rho
  let i = head r
  b <- peekByte
  if -- If the following byte is an id byte then identifier is illegal
     | isIdByte b -> do
         rest <- takeWhile isIdByte
         fault_ $ "Illegal identifier (must be <128 bytes): " ++ r ++ rest
     -- Keywords are not acceptable
     | isKeyword r -> fault_ $ "Identifier cannot be a keyword: '" ++ r ++ "'"
     -- Simply an underscore or digit is not an acceptable identifier
     | length r <= 1 -> fault_ $ "Unacceptable identifier: " ++ r
     -- Otherwise, we have an acceptable identifier
     | otherwise   -> pure r
  <?> "_identifier"
  where
    rho :: Int -> Byte -> Maybe Int
    rho n b
      -- Must lead with underscore or letter
      | n==0 && isLeadingByte b = Just 1
      -- Read only upto 128 bytes
      | n<0 || 128<=n           = Nothing
      | isIdByte b              = Just $ n+1
      | otherwise               = Nothing
{-# INLINE _identifier #-}

-- | Parses an identifier.
--
-- Identifiers must follow the same lexical conventions of C identifiers:
-- > They can contain any alphanumeric character and the underscore character
-- > But the first character can not be a digit.
-- > Rule identifiers are case sensitive.
-- > Identifiers cannot exceed 128 characters.
--
-- The yara keywords are reserved and cannot be used as an identifier; see
-- @yaraKeywords@ for a list.
--
-- We additionally imposed that identifiers cannot be a single number or
-- just an underscore for the time being, due to parsing issues.
identifier :: Yp ByteString
identifier = do
  i <- _identifier
  -- If the next byte is a dot, may be trying to import a module.
  -- Parse another identifier and check if it was imported
  ifM (isDot <$> peekByte)
      (do m <- getImports
          if H.member i m
            then dot *> _identifier
            else badModule i )
      (pure i)
  <?> "identifier"
  where badModule = undefined
{-# INLINE identifier #-}

-- | Parse an identifier that isn't "imported," ie. is not module name
-- trailed by a '.' trailed by an identifier
identifierNoImport :: Yp ByteString
identifierNoImport = do
  l <- _identifier
  --s <- getStrings
  pure l
{-}  if l `Map.member` s
    then pure l
    else fault $ "String not in scope: " ++ l-}
{-# INLINE identifierNoImport #-}

-- | Parse an identifier preceeded by a '$'
-- Returns only the identifier.
label :: Yp ByteString
label = liftA2 seq dollarSign identifierNoImport
{-# INLINE label #-}
