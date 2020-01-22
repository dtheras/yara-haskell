{-# LANGUAGE NegativeLiterals #-}
-- |
-- Module      :  Yara.Parsing.Conditions
-- Copyright   :  David Heras 2019-2020
-- License     :  GPL-3
--
-- Maintainer  :  dheras@protonmail.com
-- Stability   :  experimental
-- Portability :  unknown
--
-- To annotate.
--
module Yara.Parsing.Conditions where

import Yara.Parsing.AST
import Yara.Parsing.ByteStrings
import Yara.Parsing.Patterns
import Yara.Parsing.Combinators
import Yara.Parsing.Parser
import Yara.Prelude

import qualified Data.HashMap.Strict as HM
import qualified Data.HashSet        as HS

-- To-Do list for implimenting conditions:
-- [X] 2.3.1  Counting strings
-- [X] 2.3.2  String offsets or virtual addresses
-- [X] 2.3.3  Match length
-- [X] 2.3.4  Filesize
-- [X] 2.3.5  Executable entry point
-- [X] 2.3.6  Accessing data at a given position
-- [ ] 2.3.7  Sets of strings
-- [ ] 2.3.8  Applying the same condition to many strings
-- [ ] 2.3.9  Using anonymous strings with of and for..of
-- [ ] 2.3.10 Iterating over string occurrences
-- [X] 2.3.11

-------------------------------------------------------------------------
-- Condition AST & primitive AST parsers

-- | 'ConExp' is a conditional expression that can be evaluated true or false
-- while scanning a document. Structurally, its nearly identical to the boolean
-- bnf; it has a several more value constructors for each condition type (as
-- required).
data ConExp = ConExp ConOr

data ConOr = ConOr ConAnd [ConAnd]

data ConAnd = ConAnd ConVal [ConVal]

data ConVal
  = ConNeg ConVal
  | ConGrp ConOr
  | ConBool Bool
  | ConStrCount ByteString (Word64 -> Bool)
  | ConStrAt Integer ByteString
  | ConStrIn Integer Integer ByteString
  | ConStrInFilesize OffsetPrim ByteString
  | ConRuleRef ByteString
  | ConFilesize (Integer -> Bool)
  | ConAccess Sign IntType AccessOffset
  | ConMatchLength MatchLengthPrim
  | ConOffset OffsetPrim

data MatchLengthPrim
  = MatchLength Count ByteString
  | MatchLengthVal Count Integer

data OffsetPrim
  = OffsetVal Integer
  -- ^ Offset value of just an integer
  | OffsetIthOcc Integer ByteString
  -- ^ Offset determined by the ith occurrence of a string

type Sign = Bool -- Is a integer value signed or unsigned?

data IntType = Int8 | Int16 | Int32 | Int8BE | Int16BE | Int32BE

data AccessOffset
  = AccessExp IntType AccessOffset
  | AccessPrim OffsetPrim

data ConState = ConState {
    ruleLabel :: ByteString
  , imports  :: ()
  , inscopeRules  :: HS.HashSet ByteString
  , localPatterns :: Patterns
  }

-------------------------------------------------------------------------
-- General conditions parser combinators

-- | `isPatternInscope`
isPatternInscope :: ByteString -> Yp ConState ()
isPatternInscope bs = do
  rule <- reader ruleLabel
  pats <- reader localPatterns
  unless (hasPattern bs pats)
    (parseError $ "The string '" ++ bs ++ "' is not inscope for rule" ++ rule)
  <?> "isPatternInscope"
{-# INLINABLE isPatternInscope #-}

-- | Parses a pattern "$a" and returns the pattern. Errors if pattern is
-- not within scope.
patternIden :: Yp ConState ByteString
patternIden = do
  b <- label
  isPatternInscope b
  pure b
  <?> "patternIden"

-- | @intExp@
-- TODO.
-- To be implimented.
intExp :: Integral a => Yp s a
intExp = do
  undefined
  <?> "intExp"
{-# SPECIALIZE intExp :: Yp s Integer #-}

-- | @unsignedIntExp@ parses an unsigned integer (ie. nonnegative integer)
unsignedIntExp :: Integral a => Yp s a
unsignedIntExp = do
  i <- intExp
  if i >= 0
    then pure i
    else parseError "Expected unsigned integer expression"
  <?> "unsignedIntExp"
{-# INLINE unsignedIntExp #-}

-- | Get the offset or virtual address of the i-th occurrence of string $a
-- by using @a[i]. The indexes are one-based, so the first occurrence would
-- be @a[1] the second one @a[2] and so on. If you provide an index greater
-- then the number of occurrences of the string, the result will be a Nothing.
ithOccurenceVal :: Yp ConState OffsetPrim
ithOccurenceVal = do
  b <- liftA2 seq at identifierNoImport
  isPatternInscope b
  n <- between sqBra sqKet intExp
  if n > 0
    then pure $ OffsetIthOcc n b
    else parseError "Bad index: occurence indexes are one-based (1,2,3..)"
  <?> "ithOccurenceVal"
{-# INLINE ithOccurenceVal #-}

bound :: Yp ConState OffsetPrim
bound = do
  n <- intExp <|> hexadecimal
  if n >= 0
    then pure n
    else parseError "Bad bounds: bound values must be nonnegative"
  <?> "bound"
{-# INLINE bound #-}

offsetVal :: Yp ConState Integer
offsetVal = do
  n <- intExp <|> hexadecimal
  if n > 0
    then pure n
    else parseError "Bad index: offset values must be nonnegative"
  <?> "offsetVal"
{-# INLINE offsetVal #-}

-- | YARA specification allows offsets (virtual addresses) to be
-- written in hexadecimal with prefix '0X'
--
-- Remark: also referred to virtual address in the specification.
-- The distinction arises not in the rule file itself but what is
-- currently being scanned.
offset :: Yp ConState ConVal
offset = do
  s <- (OffsetVal <$> offsetVal) <|> ithOccurenceVal
  pure $ ConOffset s
  <?> "offset"
{-# INLINABLE offset #-}

-------------------------------------------------------------------------------
-- 2.3.1 Counting strings

stringCount :: Yp ConState ConVal
stringCount = do
  e <- ofTwo (hash *> identifierNoImport) decimal
  o <- seek relOp
  seek $ case e of
    Left l  -> do
      d <- decimal
      isPatternInscope l
      pure $ ConStrCount l (o $/ d)
    Right r -> do
      i <- hash *> identifierNoImport
      isPatternInscope i
      pure ConStrCount i (o $/ r)
{-# INLINABLE stringCount #-}

-------------------------------------------------------------------------------
-- 2.3.2 String offsets or virtual addresses

stringIn :: Yp ConState (ByteString -> ConVal)
stringIn = do
  string "in"
  seek oParen
  low <- seek $ bound <|> entrypoint
  seek ellipsis

  -- The upperbound can either be a non-negative integer value
  -- or the string "filesize".
  let parseUpperBound :: Yp ConState (Either Integer ByteString)
      parseUpperBound = seek $
        entrypoint <|> ofTwo bound (string "filesize")
      {-# INLINABLE parseUpperBound #-}

  let handleIntBound :: Integer -> Yp ConState (ByteString -> ConVal)
      handleIntBound up = if up <= low
        then parseError "Bad range: bounds must satisfy upper >= lower"
        else pure $ ConStrIn low up
      {-# INLINE handleIntBound #-}

  let handleFilesizeBound :: a -> Yp ConState (ByteString -> ConVal)
      handleFilesizeBound _ = pure $ ConStrInFilesize low
      {-# INLINE handleFilesizeBound #-}

  res <- eitherM handleIntBound handleFilesizeBound parseUpperBound
  seek cParen
  pure res
  <?> "stringIn"

stringAt :: Yp ConState (ByteString -> ConVal)
stringAt = do
  string "at"
  seek $ ConStrAt <$> offset <|> entrypoint
  <?> "stringAt"

stringInAt :: Yp ConState ConVal
stringInAt = do
  i <- patternIden
  c <- seek $ stringAt <|> stringIn
  pure $ c i
  <?> "stringInAt"
{-# INLINABLE stringInAt #-}

-------------------------------------------------------------------------------
-- 2.3.3 Match length

{- The specification is particularly unclear here (reads like an after thought,
and provided no example). Our best interpretation:

Match length ONLY applies to regex and hex string patterns.
For regular strings, they always only match the full string, so the
length is fixed.
-}

-- | Get length value of i-th match of a pattern. Only makes sense as regex
-- and hex matches can have variable length.
matchLength :: Yp ConState ConVal
matchLength = do
  bs <- liftA2 seq bang identifierNoImport
  rule <- reader ruleLabel
  pats <- reader localPatterns
  case HM.lookup bs pats of
    Nothing                 ->
      (parseError $ "The string '" ++ bs ++ "' is not inscope for rule" ++ rule)
    Just (Pattern pb pt pp) -> do
      n <- between sqBra sqKet intExp
      if n < 0
      then parseError "Bad index: occurence indexes are one-based (1,2,3..)"
      else case pt of
        Str -> MatchLengthVal n $ length bs
        _   -> MatchLength n bs
  <?> "matchLength"
{-# INLINE matchLength #-}

-------------------------------------------------------------------------------
-- 2.3.4 Filesize

-- | 'tokensWith' is nearly identical to 'tokens' but checks
-- string match after applying morphism.
tokensWith :: (ByteString -> ByteString) -> [T2 ByteString a] -> Yp s a
tokensWith f ls =
  asumMap (\(T2 s v) -> stringWithMorph f s $> v) ls
  <?> "tokensWith"
{-# INLINE tokensWith #-}

-- 'unitsToken' tokenizes unit text into values
unitsToken :: Yp s Integer
unitsToken = tokensWith toLower
  [ T2 "b"  1
  , T2 "kb" 1_000
  , T2 "mb" 1_000_000
  , T2 "gb" 1_000_000_000
  , T2 "tb" 1_000_000_000_000
  , T2 "pb" 1_000_000_000_000_000
  , T2 "eb" 1_000_000_000_000_000_000
  , T2 "zb" 1_000_000_000_000_000_000_000 ]
  <?> "unitsToken"
{-# INLINABLE unitsToken #-}

-- Units parser, space NOT OK between the value and the units
parseUnits :: Yp s Integer
parseUnits = unitsToken <* notFollowedBy isAlpha
  <|> notFollowedBy isAlpha $> 1
  <|> (do b <- takeWhile1 isAlpha
          parseError $ "Bad units: unrecognized filesize units '"++b++"'")
  <?> "parseUnits"
{-# INLINE parseUnits #-}

-- | Match filesize of file being scanned; size is expressed in bytes.
filesizeCondition :: Yp ConState ConVal
filesizeCondition = do
  string "filesize"
  o <- seek relOp
  s <- seek decimal
  x <- parseUnits
  pure $ ConFilesize $ flip o (x * s)
  <?> "filesize"
{-# INLINABLE filesizeCondition #-}

-------------------------------------------------------------------------------
-- 2.3.5 Executable entry point

-- Use of 'entrypoint' keyword has been depreciated below, see warning
-- at the end of 2.3.5 (unless imported via PE module)
entrypoint :: Yp ConState a
entrypoint = do
  string "entrypoint"
  parseError $ mconcat [
      "Warning: The entrypoint variable is deprecated,"
    , "you should use the equivalent pe.entry_point from the PE module"
    , "instead. Starting with YARA 3.0 you’ll get a warning if you use"
    , "entrypoint and it will be completely removed in future versions."]
  <?> "entrypoint"
{-# INLINE entrypoint #-}

-------------------------------------------------------------------------------
-- 2.3.6 Accessing data at a given position

u_ :: Yp s ()
u_ = void $ byte 117
{-# INLINE u_ #-}

intType :: Yp s IntType
intType = do
  string "int"
  tokens [ T2 "8"    Int8
         , T2 "16"   Int16
         , T2 "32"   Int32
         , T2 "8be"  Int8BE
         , T2 "16be" Int16BE
         , T2 "32be" Int32BE ]
{-# INLINE intType #-}

accessConLoop :: Yp ConState AccessOffset
accessConLoop = delimited $ asum
  -- I: Unsigned integer (expression), decimal or hexadecimal
  [ offset
  -- II: nested uintXX function
  , liftA2 AccessExp (u_ *> intType) accessCon_
  -- III: inappropriate signed intXX function nested
  , (do string "int"
        asumMap string ["8", "16", "32"]
        string "be" <|> pure ""
        parseError "Offset or virtual address cannot be a signed int" )
  -- IV: argument is entirely unrecognized
  , parseError "Unrecognized offset or virtual address argument."
  ]
{-# INLINABLE accessConLoop #-}

accessCon :: Yp ConState ConVal
accessCon = liftA3 ConAccess (isSucc u_) intType accessConLoop

-------------------------------------------------------------------------------
-- 2.3.7 Sets of strings
-- 2.3.8 Applying the same condition to many strings
-- 2.3.9 Using anonymous strings with of and for..of
-- 2.3.10 Iterating over string occurrences

forOfCon :: Yp ConState ConVal
forOfCon = do

  -- Are we in for-loop or string iteration?
  b <- isSucc $ string "for"

  -- OK since intExp only returns non-negative integers
  d <- seek $ tokens [T2 "all" -2, T2 "any" -1] <|> unsignedIntExp

  let ofExp = do
        string "of"
        seek $ token "them" Nothing
             <|> Just <$> grouped comma (liftA2 T2 label $ isSucc asterick)

  let strIter = do
        ids <- undefined
        seek $ string "in"
        ixs <- seek index
        pure $ T2 ids ixses

  et <- seek $ ofTwo ofExp strIter

  -- If we are in for loop, we are expecting a for-loop style expression.
  e <- if b
     then do
       seek $ byte 58
       seek $ delimited boolExp_
     else undefined

  if | d == 0  -> ConBool False
     | d == -1 -> undefined
     | d == -2 -> undefined
     | d < -2  -> internalError "'forOfCon' had a negative value???"


-- | Parse an identifier preceeded by a '$' but possible ending with an
-- asterick. The spec permits wildcarding.
labelAst :: Yp s (T2 ByteString Bool)
labelAst = undefined

-------------------------------------------------------------------------------
-- 2.3.11 Referencing other rules

-- | 'ruleRef'
-- Parse reference in manner of rules depending on others.
ruleRef :: Yp ConState ConVal
ruleRef = do
  i <- _identifier
  r <- reader inscopeRules
  if i `HS.member` r
    then pure $ ConRuleRef i
    else parseError $ "Referenced rule '" ++ i ++ "' is not in scope."





















{-




--
-- Use that the following are identical when returning constructor:
--   any of ($a,$b,$c)
--   for any of ($a,$b,$c) : ( $ )
--
-- Not done because there are many ways the following can be writen using bool
-- expressions and so forth. Plus that decimal could acutally be an integer
-- expressions. A working example may need to be done to discover issues.
--
-- Three general formats:
--   >  <expression> of <string_set>
--   >  for <expression> of <string_set> : ( <boolean_expression> )
--   >  for <expression> <identifier> in <indexes> : ( <boolean_expression> )



-------------------------------------------------------------------------------
-- AST Evaluation

parseConVal :: Yp ConState ConVal
parseConVal = do
  i <- seek $ optional $ string "not" *> space1
  d <- seek $ (ConBool <$> tokens [T2 "true" True, T2 "false" False])
          <|> (ConGrp <$> delimited parseConExp)
          -- Conditions:
          <|> stringCount
          <|> strInAt
          <|> ruleRef
          <|> filesizeCondition
  pure $ maybe d (\_ -> ConNeg d) i

parseConAnd :: Yp ConState ConAnd
parseConAnd = do
  v <- parseConVal
  vs <- seek $ sepBy (do string "and"; seek parseConVal) spaces
  spaces
  pure $ ConAnd v vs

parseConOr :: Yp ConState ConOr
parseConOr = do
  v <- parseConAnd
  vs <- seek $ sepBy (do string "or"; seek parseConAnd) spaces
  spaces
  pure $ ConOr v vs

parseConExp :: Yp ConState ConExp
parseConExp = ConExp <$> parseConOr

evalConExp :: ConExp -> Bool
evalConExp (ConExp s) = evalConOr s

evalConOr :: ConOr -> Bool
evalConOr (ConOr v vs) = foldl (\x y -> x || evalConAnd y) (evalConAnd v) vs

evalConAnd :: ConAnd -> Bool
evalConAnd (ConAnd v vs) = foldl (\x y -> x && evalConVal y) (evalConVal v) vs

-- Place holder. Actual evaluation will be a lot more complicated
evalConVal :: ConVal -> Bool
evalConVal (ConBool i) = i
evalConVal (ConNeg v)  = not (evalConVal v)
evalConVal (ConGrp g)  = evalConOr g
evalConVal _           = error "An evaluation stradgey of a 'ConVal' hasn't \
                               \been implimented"

-}









