{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE OverloadedStrings #-}
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

import Data.ByteString
    -----
import qualified Data.Map      as Map
import qualified Data.Set      as Set

-- CONSTANTS

max_argsTag :: Int
max_argsTag = 32

max_argsIdentifier :: Int
max_argsIdentifier = 32

max_argsExternVar :: Int
max_argsExternVar = 32

max_argsModuleData :: Int
max_argsModuleData = 32

max_queuedFiles :: Int
max_queuedFiles = 64


type Identifier = ByteString
            


type Label = ByteString

{-
data RuleString
  = RuleString Label ByteString                 (Seq.Seq ByteString)
  | RuleReg    Label (ByteString -> ByteString) (Seq.Seq ByteString)
  | RuleHex    Label HexStr                     (Seq.Seq ByteString)
-}
data Value = ValueI Int
           | ValueS ByteString
           | ValueB Bool
           deriving (Show, Eq)

type Metadata = Map.Map Identifier Value

data RuleType = Normal | Global | Private | GblPrv deriving Show

instance Semigroup RuleType where
  _       <> GblPrv   = GblPrv
  GblPrv  <> _        = GblPrv
  Global  <> Global   = Global
  Private <> Private  = Private
  Global  <> Private  = GblPrv
  Private <> Global   = GblPrv
  Normal  <> m        = m
  n       <> Normal   = n

data PkgName = ByteString

data Name = LocalName ByteString
          | CmdName ByteString
          -- ImportName NameSpace PkgName ByteString

data RuleBlock = RuleBlock {
    ruletype   :: RuleType
  , rulename   :: RuleName
  , tags       :: Set.Set TagName
  , meta       :: Set.Set (Identifier, Value)
  , stringss   :: !(Set.Set RuleStrings)
  , conditions :: Bool
  }

type TagName = ByteString
type RuleName = ByteString
type RuleStrings = ByteString
type MetadataSnippet = ByteString

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

