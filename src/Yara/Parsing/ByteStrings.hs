{-# LANGUAGE OverloadedLists #-}
-- |
-- Module      :  Yara.Parsing.ByteStrings
-- Copyright   :  David Heras 2019
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
import Yara.Parsing.AST
import Yara.Parsing.Combinators
import Yara.Parsing.Parser

import qualified Data.HashMap.Strict as HM
import qualified Data.HashSet as HS

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
scan :: st -> (st -> Byte -> Maybe st) -> Yp s ByteString
scan s0 p = scan_ id (\_ y -> pure y) p s0 <?> "scan"
{-# INLINE scan #-}

scanSt :: st -> (st -> Byte -> Maybe st) -> Yp s (st, ByteString)
scanSt s0 p = scan_ id (curry pure) p s0 <?> "scanSt"
{-# INLINE scanSt #-}

scan_ :: (Byte -> Byte)
      -- ^ How to transform byte as scanning?
      -> (st -> ByteString -> Yp s r)
      -- ^ Do what with the final state and parsed bytestring?
      -> (st -> Byte -> Maybe st)
      -- ^ State Transformation
      -> st
      -- ^ Initial state value
      -> Yp s r
scan_ mo !ret !rho !s0 = do
  bs@(PS fp off len) <- getBuff
  let T2 i u = accursedUnutterablePerformIO $
        withForeignPtr fp $ \ptr0 -> do
          let done !j !s = pure $! T2 j s
              start = ptr0 ~+ off
              inner ptr !s
                | ptr < (start ~+ len) = do
                    w <- peek ptr
                    case rho s w of
                      Just s' -> do
                        pokeByteOff ptr 0 (mo w)
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
-- Parser fails if the predicate fails.
textStringWith :: (Byte -> Bool) -> Yp s ByteString
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
      --
  let (b,s) = atomicModification atomic TSNorm bs

  case s of
    TSFin n      -> advance n $> b
    TSBadNewLn   -> parseError "encountered unexpected new line"
    TSUnrecHex v -> parseError $ mconcat [
        "Unrecognized escape character: expecting a "
      , "hexadecimal character but found '" +> v +> 39
      ]
    TSUnrecEsc v -> parseError $ mconcat [
        "Bad escape character: "++sig 39++sig v
      , "' not a permitted escape character"
      ]
    TSBadByte v  -> parseError $
      "Bad escape character: "++sig 39++sig v++"' failed the predicate"
    _            -> internalError
      "Nirvana reached, that is to say you shouldn't be able to reach this point"
  <?> "stringLiteral"
{-# INLINABLE textStringWith #-}

-- [* atomicModification] The core loop logic for @atomic@ is
-- identical to 'removeComments' from "Yara.Parser.Preprocess."
-- See that for documentation.
textString :: Yp s ByteString
textString = textStringWith $ \_ -> True
{-# INLINE textString #-}

----------------------------
-- Identifiers

-- possiby temporary. does the parsing of an identifier
-- but doesnt check if imported. very helpful.
_identifier :: Yp s ByteString
_identifier = do
  r <- scan 0 rho
  --let i = head r
  b <- peekByte

     -- If the following byte is an id byte then identifier is illegal
  if | isIdByte b -> do
         rest <- takeWhile isIdByte
         parseError $ "Bad identifier: must be <=128 bytes " ++ r ++ rest

     -- Keywords are not acceptable
     | isKeyword r ->
         parseError $ "Bad identifier: cannot be a keyword (" ++ r ++ ")"

     -- Simply an underscore or digit is not an acceptable identifier
     | length r <= 1 ->
         parseError $ "Bad identifier: unaccepted identifier of '" ++ r++ "'"

     -- Otherwise, we have an acceptable identifier
     | otherwise   ->
         pure r
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

-- | Parse an identifier that isn't "imported," ie. is not module name
-- trailed by a '.' trailed by an identifier
identifierNoImport :: Yp s ByteString
identifierNoImport = _identifier
  <?> "identifierNoImport"
{-# INLINE identifierNoImport #-}

-- | Parse an identifier preceeded by a '$'
-- Returns only the identifier.
label :: Yp s ByteString
label = liftA2 seq dollar identifierNoImport
{-# INLINE label #-}

getImports :: HasImports s => Yp s (HM.HashMap ByteString ByteString)
getImports = imports <$> get
{-# INLINE getImports #-}

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
identifier :: HasImports s => Yp s ByteString
identifier = do
  i <- _identifier
  -- If the next byte is a dot, may be trying to import a module.
  -- Parse another identifier and check if it was imported
  ifM (isDot <$> peekByte)
      (ifM (HM.member i <$> getImports)
           (dot *> _identifier)
           $ badModule i)
      (pure i)
  <?> "identifier"
  where badModule = undefined
{-# INLINE identifier #-}

isKeyword :: ByteString -> Bool
isKeyword = flip HS.member [
   "all"       , "and"       , "any"      , "ascii"      ,
   "at"        , "condition" , "contains" , "entrypoint" ,
   "false"     , "filesize"  , "for"      , "fullword"   ,
   "global"    , "import"    , "in"       , "include"    ,
   "int16"     , "int16be"   , "int32"    , "int32be"    ,
   "int8"      , "int8be"    , "matches"  , "meta"       ,
   "nocase"    , "not"       , "of"       , "or"         ,
   "private"   , "rule"      , "strings"  , "them"       ,
   "true"      , "uint16"    , "uint16be" , "uint32"     ,
   "uint32be"  , "uint8"     , "uint8be"  , "wide"       ]
