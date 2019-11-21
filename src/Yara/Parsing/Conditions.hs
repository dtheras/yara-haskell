{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE BlockArguments #-}
{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE NegativeLiterals #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}
-- |
-- Module      :  Yara.Parsing.Conditions
-- Copyright   :  David Heras 2019
-- License     :  GPL-3
--
-- Maintainer  :  dheras@protonmail.com
-- Stability   :  experimental
-- Portability :  unknown
--
-- To annotate.
--
module Yara.Parsing.Conditions ( parseConditions )

import Yara.Parsing.AST
import Yara.Parsing.Patterns
import Yara.Parsing.Combinators
import Yara.Parsing.Parser
import Yara.Prelude

import qualified Data.HashMap.Strict as HM
import qualified Data.HashSet        as HS

-- To-Do list for implimenting conditions:
-- [X] 2.3.1
-- [X] 2.3.2
-- [ ] 2.3.3
-- [X] 2.3.4
-- [X] 2.3.5
-- [ ] 2.3.6
--
-- [X] 2.3.11

-------------------------------------------------------------------------
-- Condition AST, AST parsers, & evaluator


-- | 'ConExp' is a conditional expression that can be evaluated true or false
-- while scanning a document. Structurally, its nearly identical to the boolean
-- bnf; it has a several more value constructors for each condition type (as
-- required).
data ConExp = ConExp ConOr

data ConOr = ConOr ConAnd [ConAnd]

data ConAnd = ConAnd ConVal [ConVal]

data ConVal = ConNeg ConVal
            | ConGrp ConOr
            | ConBool Bool
            --
            | ConStrCount ByteString (Word64 -> Bool)
            | ConStrAt ByteString Integer
            | ConStrIn ByteString Integer Integer
            | ConRuleRef ByteString
            -- ConArith ArithE (Integer -> Integer -> Bool) ArithE
          {- real wish to flatten this and make convals each condition type--}

parseConVal :: Yp ConState ConVal
parseConVal = do
  i <- seek $ optional $ string "not" *> space1
  d <- seek $ (ConBool <$> tokens [T2 "true" True, T2 "false" False])
          <|> (ConGrp <$> delimited parseConExp)
          -- Conditions:
          <|> stringCount
          <|> stringInAt
          <|> ruleRef
          <|> filesize
  pure $ maybe d (\_ -> ConNeg d) i

parseConAnd :: Yp s ConAnd
parseConAnd = do
  v <- parseConVal
  vs <- seek $ sepBy (do string "and"; seek parseConVal) spaces
  spaces
  pure $ ConAnd v vs

parseConOr :: Yp s ConOr
parseConOr = do
  v <- parseConAnd
  vs <- seek $ sepBy (do string "or"; seek parseConAnd) spaces
  spaces
  pure $ ConOr v vs

parseConExp :: Yp s ConExp
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

-------------------------------------------------------------------------
-- Conditions parsers

data ConState = ConState {
    filesize :: Integer
  , patterns :: Patterns
  , imports  :: ()
  , inscopeRules  :: HS.HashSet ByteString
  , localPatterns :: Patterns
  }

-- We are gonna fetch filesize first thing before
-- evening parsing yara rules.
-- Prevents interweaving IO as well as making code impure.
filesizeToken :: Yp ConState Integer
filesizeToken = string "filesize" *> reader filesize
{-# INLINE filesizeToken #-}

-- | `isPatternInscope`
isPatternInscope :: ByteString -> Yp ConState ()
isPatternInscope bs v = do
  pats <- reader localPatterns
  unless (hasPattern bs pats) $ fault_ PatternNotInscope bs
{-# INLINABLE isPatternInscope #-}

-- DONE 2.3.1 Counting strings
-- |
--
--
stringCount :: Yp ConState ConVal
stringCount = do
  let hashId = hash *> identifier {-# INLINE hashId #-}
  e <- ofTwo hashId decimal
  o <- seek relOp
  pnr
  seek $ case e of
--         | ConStrCount ByteString (Word64 -> Bool)
    Left l  -> do
      d <- decimal
      isPatternInscope l
      pure $ ConStrCount l (o $/ d)

    Right r -> do
      i <- hashId
      isPatternInscope i
      pure ConStrCount i (o $/ r)
{-# INLINABLE stringCount #-}


-- | YARA specification allows offsets to be written in hexadecimal with
-- prefix '0x' (we allow '0X' as well) as its handy when writing
-- virtual addresses.
offset :: Yp s Integer
offset = decimal <|> hexadecimal
{-# INLINE offset #-}

-- DONE 2.3.2
-- |
--
--
strInAt :: Yp ConState ConVal
strInAt = do
  i <- label
  isPatternInscope i

  -- Use of 'entrypoint' key word has been depreciated here, see warning
  -- at the end of 2.3.5 (unless imported via PE module)
  let entrypoint :: Yp ConState ConVal
      entrypoint = do
        string "entrypoint"
        fault_ InternalError "Warning: The entrypoint variable is deprecated,\
          \ you should use the equivalent pe.entry_point from the PE module \
          \instead. Starting with YARA 3.0 you’ll get a warning if you use \
          \entrypoint and it will be completely removed in future versions."
        <?> "entrypoint"
      {-# INLINABLE entrypoint #-}

  let stringIn :: Yp ConState ConVal
      stringIn = do
        string "in"
        seek oParen
        l <- seek $ nonNegIntExp <|> entrypoint
        seek ellipsis
        u <- seek $ nonNegIntExp <|> filesizeToken <|> entrypoint
        seek cParen
        pure $ ConStrIn i l u

  let stringAt :: Yp ConState ConVal
      stringAt = do
        string "at"
        (ConStrAt i) <$> offset <|> entrypoint

  seek $ stringAt <|> stringIn
  <?> "strInAt"
{-# INLINABLE strInAt #-}

-- DONE 2.3.11 Referencing other rules
-- | 'ruleRef'
-- When writing the conditions for a certain rule, you can also make reference
-- to a rule in a manner that resembles a function invocation
-- of traditional programming languages. In this way you can create rules
-- that depend on others. Let’s see an example:
--
-- rule Rule1 {
--    strings:
--        $a = "dummy1"
--    condition:
--        $a
-- }
-- rule Rule2 {
--    strings:
--        $a = "dummy2"
--    condition:
--        $a and Rule1
-- }
--
-- As can be seen in the example, a file will satisfy Rule2 only if it
-- contains the string “dummy2” and satisfies Rule1. Note that it is strictly
-- necessary to define the rule being invoked before the one that will make
-- the invocation.
ruleRef :: Yp ConState ConVal
ruleRef = do
  i <- _identifier
  r <- reader inscopeRules
  if i `HS.member` r
  then pure $ ConRuleRef i
  else fault_ RuleNotInscope $ "Referenced rule is not in scope '" ++ i ++ "'"

-- DONE 2.3.4
-- |
-- Match filesize of file being scanned; size is expressed in bytes.
--
-- rule FileSizeExample
-- {
--    condition:
--        filesize > 200KB
-- }
--
-- Here: the parser doesn't immediately check the condition, true or false.
--
-- 1) parsing of yara rules is pure. so we cannot simply fetch it.
-- 2) it could be included in state? no. if we are scanning several documents,
--    it varies. plus it would mean calculating file size ahead of time with
--    no promise of using it. may be an issue on huge files.
-- 3) but keeping a constructor with two fields is computationally higher than
--    just a bool. Not entirely. Since ti would be a bool contructor wrapper
--    around the value anyways. so its neglegible.
--
-- Note: this is distinct from the "filesize" keyword, which gets replaced with
-- the value of the file-being-scanned's digital size.
--
filesize :: Yp ConState ConVal
filesize = do
  d <- filesizeToken
  o <- seek ordering             -- ordering token
  s <- seek decimal              -- integer value
  let parseUnits = tokensWith toLower
        [ T2 "b"  1
        , T2 "kb" 1_000
        , T2 "mb" 1_000_000
        , T2 "gb" 1_000_000_000
        , T2 "tb" 1_000_000_000_000
        , T2 "pb" 1_000_000_000_000_000
        , T2 "eb" 1_000_000_000_000_000_000
        , T2 "zb" 1_000_000_000_000_000_000_000
        ] <* notLetter
  u <- seek $ parseUnits <|> string " " *> 1 <|> pure 0
  if u <= 0
    then do
      b <- takeWhile1 isAlpha
      fault_ BadUnits $ "Unrecognized units value for a filesize: '"++b++"'"
    -- Here, we can immediately calculate the truth-iness of the condition
    else pure $ ConBool (o d $ u * s)
  <?> "filesize"
  where
    -- 'tokensWith' is nearly identical to 'tokens' but checks string
    -- after applying morphism, so that we don't need worry about case.
    tokensWith :: (ByteString -> ByteString) -> [T2 ByteString a] -> Yp s a
    tokensWith f ls =
      asumMap (\(T2 s v) -> stringWithMorph f s $> v) ls <?> "tokensWith"
    {-# INLINE tokensWith #-}
{-# INLINABLE filesize #-}

-- goal is to make this obsolete
data SetOfStrings = AllOf
                  | AnyOf
                  | NumOf Word


intExp :: (Integral i) => Yp s i
intExp = undefined
{-# SPECIALIZE intExp :: Yp s Integer #-}

nonNegIntExp :: Yp s Integer
nonNegIntExp = do
  i <- intExp
  if i < 0
    then error ""
    else pure i
{-# INLINE nonNegIntExp #-}

-- not done because there are many ways the following can be writen using bool
-- expressions and so forth. Plus that decimal could acutally be an integer
-- expressions
--
-- Three general formats:
--   >  <expression> of <string_set>
--   >  for <expression> of <string_set> : ( <boolean_expression> )
--   >  for <expression> <identifier> in <indexes> : ( <boolean_expression> )

forOfCon :: Yp ConState ConVal
forOfCon = do

  -- Are we in for-loop or string iteration?
  b <- isSucc $ string "for"

  -- OK since intExp only returns non-negative integers
  d <- seek $ tokens [T2 "all" -2, T2 "any" -1] <|> nonNegIntExp

  let ofExp = do
        string "of"
        seek $ token "them" Nothing
             <|> grouped comma (liftA2 T2 label $ isSucc asterick)

  let strIter = do
        ids <- undefined
        seek $ string "in"
        ixs <- seek indexes
        pure $ T2 ids ixs

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
     | d < -2  -> fault_ InternalError "'forOfCon' had a negative value???"


-- | Parse an identifier preceeded by a '$' but possible ending with an
-- asterick. The spec permits wildcarding. However, in this sitution 
labelAst :: Yp s (T2 ByteString Bool)
labelAst =
 


--
-- Use that the following are identical when returning constructor:
--   any of ($a,$b,$c)
--   for any of ($a,$b,$c) : ( $ )
--





{-


type BigEndian = Bool

#define GO()
GO(int8,)
GO(int16,)
GO(int32,)
GO(uint8,)
GO(uint16,)
GO(uint32,)
GO(int8be,)
GO(int16be,)
GO(int32be,)
GO(uint8be,)
GO(uint16be,)
GO(uint32be,)
#undef GO


-- | Get the offset or virtual address of the i-th occurrence of string $a
-- by using @a[i]. The indexes are one-based, so the first occurrence would
-- be @a[1] the second one @a[2] and so on. If you provide an index greater
-- then the number of occurrences of the string, the result will be a Nothing.
offsetOf :: Yp ConditionalExp
offsetOf =
  liftA2 Offset (identifier <* sqBra <* spaces) (offset <* spaces <* sqKet)
{-# INLINE offsetOf #-}
-}
