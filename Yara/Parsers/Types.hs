{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE OverloadedStrings #-}
-- |
-- Module      :  Yara.Parsers.Types
-- Copyright   :  David Heras 2018-2019
-- License     :  GPL-3
--
-- Maintainer  :  dheras@protonmail.com
-- Stability   :
-- Portability :  unknown
--
-- To annotate.
--
module Types where

import Data.ByteString
import Data.Default
import Data.Word
    -----
import qualified Data.Map      as Map
import qualified Data.Set      as Set
import qualified Data.Sequence as Seq

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


instance Default ByteString where
  def = ""

-- | Type alias that assists in reading, since parsers views
-- input as a stream of bytes in the structure of a ByteString.
type Byte = Word8

type FilePath = ByteString

type Identifier = ByteString

type Label = ByteString

data ConMap where
  ConBool :: (ByteString -> Bool) -> ConMap
  ConList :: ([ByteString] -> Bool) -> ConMap
  ConOr   :: (ConMap -> ConMap -> Bool) -> ConMap

type HexStr = Seq.Seq HexSubStr

data HexSubStr where
  Std ::         HexTokens -> HexSubStr
  Grp :: Seq.Seq HexTokens -> HexSubStr
  deriving Show

type HexTokens = Seq.Seq HexToken

data HexToken where
  Pair :: Word8 -> Word8 -> HexToken
  RJmp :: Word  -> Word  -> HexToken
  IJmp ::          Word  -> HexToken

instance Show HexToken where
  show (Pair x y) = show x <> show y
  show (RJmp x y) = "[" <> show x <> "-" <> show y <> "]"
  show (IJmp x)   = "[" <> show x <> "-]"

data RuleString
  = RuleString Label ByteString                 (Seq.Seq ByteString)
  | RuleReg    Label (ByteString -> ByteString) (Seq.Seq ByteString)
  | RuleHex    Label HexStr                     (Seq.Seq ByteString)

data Value = ValueI Int
           | ValueS ByteString
           | ValueB Bool
           deriving Show

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

