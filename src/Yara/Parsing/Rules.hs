-- |
-- Module      :  Yara.Parsing.Rules
-- Copyright   :  David Heras 2019
-- License     :  GPL-3
--
-- Maintainer  :  dheras@protonmail.com
-- Stability   :  experimental
-- Portability :  unknown
--
-- To annotate.
--
{-Zip -- haskell lib
based on LibZip
This is a binding to C library libzip.-}
module Yara.Parsing.Rules where

import Yara.Prelude
import Yara.Parsing.AST
import Yara.Parsing.Combinators
import Yara.Parsing.Parser
import Yara.Parsing.ByteStrings
import Yara.Parsing.Patterns

value :: Yp Value
value = void bool <|> void decimal <|> void textString
  where
    bool :: Yp Bool
    bool = (string "false" $> False) <|> (string "true" $> True) <?> "bool"
    {-# INLINE bool #-}
{-# INLINE value #-}

-- | @parseRuleType@
parseRuleType :: Yp YaraRule
parseRuleType = annotate "ruletype" $ peekByte >>= \case
   114 -> rule def
   103 -> global def  >>| private >>= rule
   112 -> private def >>| global  >>= rule
   _   -> takeWhile $ not . isSpace >>= fault UnrecognizedKeyword
  where
    infixl 1 >>|
    (>>|) :: Yp a -> (a -> Yp a) -> Yp a
    v >>| k = YP $ \b !e l s ->
      runParser v b e l (\t_ e_ a ->
        runParser (k a <|> pure a) t_ e_ l s)
    {-# INLINE (>>|) #-}
    global :: YaraRule -> Yp YaraRule
    global s =
      string "global" *> space1 $> s {isGlobal = True} <?> "global"
    {-# INLINABLE global #-}
    private :: YaraRule -> Yp YaraRule
    private s =
      string "private" *> space1 $> s {isPrivate = True} <?> "private"
    {-# INLINABLE private #-}
    -- NOTE: According to YARA specification, anonymous rules seem to not
    -- be a supported feature. Hence "rule" is to be followed by at least
    -- one whitespace token to seperate it from the rule label.
    rule :: YaraRule -> Yp YaraRule
    rule s = string "rule" *> space1 $> s <?> "rule"
    {-# INLINABLE rule #-}
{-# INLINABLE parseRuleType #-}

parseRuleName :: Yp YaraRule
parseRuleName = _identifier
{-# INLINE parseRuleName #-}

parseRuleTags :: Yp (Maybe YaraRule)
parseRuleTags = maybeM def id (optional $ do
  seek colon
  seek $ sepBy1HashSet _identifier space1)
{-# INLINABLE parseRuleTags #-}

-------------------------------------------------------------
-- Metadatum

-- | Parses the metadata of a yara rule.
-- Simple parser since metadata are just paired labels and a string.
parseMetadatum :: Yp ()
parseMetadatum = do
  seek $ string "meta:"
  seek $ oddSepBy (_identifier *> seek equal *> seek value) space1
{-# INLINABLE parseMetadatum #-}

-------------------------------------------------------------
-- Conditions

parseConditions :: YaraRule -> Yp YaraRule
parseConditions s = do
  seek $ string "condition:"
  pure s
{-# INLINABLE parseConditions #-}

parseRuleBlock :: Yp YaraRule
parseRuleBlock = do
  r <- parseRuleType
  i <- parseRuleName
  t <- parseRuleTags
  seek oCurly
  parseMetadatum
  c <- parsePatterns >>= parseConditions
  seek cCurly
  pure $ r {rulename = i, tags = t, conditions = c}
{-# INLINABLE parseRuleBlock #-}
