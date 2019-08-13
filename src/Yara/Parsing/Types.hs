{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE CPP #-}
-- |
-- Module      :  Yara.Parsing.Types
-- Copyright   :  David Heras 2018-2019
-- License     :  GPL-3
--
-- Maintainer  :  dheras@protonmail.com
-- Stability   :
-- Portability :  unknown
--
-- To annotate.
--
module Yara.Parsing.Types where

import Prelude hiding ((++))
import Data.ByteString
import Data.Word
    -----
import qualified Data.Map      as Map
import qualified Data.Sequence as Seq
import qualified Data.Set      as Set

import Yara.Shared

-- CONSTANTS
#define CO(label,val) label :: Word; label = val; {-# INLINE label #-}
CO(maxTags,32)
CO(maxIdentifiers,32)
CO(maxExternalVariables,32)
CO(maxModuleData,32)
CO(maxQueuedFiles,64)
#undef CO

data Value = ValueInteger Int
           | ValueString ByteString
           | ValueBool Bool
           deriving (Show, Eq)


-- | Meta
type Metadatum = Map.Map ByteString Value

data Pattern = StringPattern ByteString
             | RegexPattern ByteString
             | HexStringPattern ByteString
             deriving Eq

instance Show Pattern where
  showsPrec d l =
    (showParen (d > 10)) $ case l of
      (StringPattern bs)     -> shows "String Pattern: " . toShows bs
      (RegexPattern bs)      -> shows "Regex Pattern: " . toShows bs
      (HexStringPattern bs)  -> shows "Hex Pattern: " . toShows bs

-- | Holds the type of
data RuleType = Normal
              | Global
              | Private
              | GblPrv
              deriving Show

-- | This instance may look really odd. Only used to greatly clear up the
-- parsing of a rule type. It follows
instance Semigroup RuleType where
  _       <> GblPrv   = GblPrv
  GblPrv  <> _        = GblPrv
  Global  <> Global   = Global
  Private <> Private  = Private
  Global  <> Private  = GblPrv
  Private <> Global   = GblPrv
  Normal  <> m        = m
  n       <> Normal   = n

-- |
type Patterns = Map.Map ByteString (Pattern , Set.Set ByteString)

-- |
--
data ConditionalExp
  = Boolean Bool
  -- ^
  | And ConditionalExp ConditionalExp
  -- ^
  | Or ConditionalExp ConditionalExp
  -- ^
  | StringMatch ByteString
  -- ^
  | StringAt ByteString Word
  -- ^
  | StringIn ByteString Word Word
  -- ^
  | StringCount ByteString Ordering Word
  -- ^
  | Offset ByteString Word
  -- ^
  | FileSize Int Ordering
  -- ^
  | RuleReference ByteString
  -- ^ Holder of a reference to another rules success.
  deriving Show

-- |
type Conditions = Seq.Seq ConditionalExp

-- |
data Rule = Rule {
    ruletype   :: RuleType
  , rulename   :: ByteString
  , tags       :: Set.Set ByteString
  , metadatum  :: Metadatum
  , patterns   :: Patterns
  , conditions :: Conditions
  }










data PkgName = ByteString

data Name = LocalName ByteString
          | CmdName ByteString
          -- ImportName NameSpace PkgName ByteString



--data BinOp = BinOp {-# Unpack #-} Int!

{-
type family NameSpace i
type instance NameSpace TagName = ByteString
type instance NameSpace RuleName = ByteString

type TagName = ByteString
type RuleName = ByteString
type RuleStrings = ByteString
type MetadataSnippet = ByteString
newtype StringName = StringName ByteStrin
data NameSpace = VarName
--              | DataName
---             | TcClsName


--type NameSpaceSet = forall i. NameSpace i => Set.Set i


-- To annotate
-- newtype NameSpaceSet = NameSpaceSet {
--  getNamespace :: forall r. Set.Set r
--  }


data NameSpace = VarName        -- ^ Variables
               | DataName       -- ^ Data constructors
               | TcClsName      -- ^ Type constructors and classes; Haskell has them
                                -- in the same name space for now.
               deriving( Eq, Ord, Show{-, Data , Generic-} )
-}

