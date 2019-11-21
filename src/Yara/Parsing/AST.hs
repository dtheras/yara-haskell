{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ExplicitForAll #-}
{-# LANGUAGE UnboxedTuples #-}
{-# OPTIONS_GHC -fno-full-laziness #-}
{-# OPTIONS_GHC -funbox-strict-fields #-}
-- |
-- Module      :  Yara.Parsing.Types
-- Copyright   :  David Heras 2018-2019
-- License     :  GPL-3
--
-- Maintainer  :  dheras@protonmail.com
-- Stability   :
-- Portability :  unknown
--
-- Module contains the yara document AST and related types.
--
module Yara.Parsing.AST where

import Yara.Prelude

import Data.Hashable
import qualified Data.HashMap.Strict as H
import qualified Data.HashSet        as S

data HexToken = HexPair !Byte !Byte
              | HexJump !(Maybe Word64) !(Maybe Word64)
              deriving (Eq, Show, Generic, NFData)

data HexSubPattern = HexString ![HexToken]
                   | HexGrouping ![HexSubPattern]
                   deriving (Eq, Show, Generic, NFData)

data Pattern
   = StringPattern !ByteString !(S.HashSet ByteString)
   | RegexPattern !ByteString
   | HexPattern ![HexSubPattern]
   deriving (Eq, Generic, NFData)

instance Hashable HexToken where
instance Hashable HexSubPattern where
instance Hashable Pattern where

instance Show Pattern where
  show (StringPattern bs _)  = bs2s $ "string-pattern{ " ++ bs ++ "}"
  show (RegexPattern bs)     = bs2s $ "regex-pattern{ " ++ bs ++ "}"
  show (HexPattern bs) = bs2s $ "hex-string-pattern{ " ++ (s2bs $ show bs) ++ "}"

data Patterns = Patterns {
    stdPatterns  :: H.HashMap ByteString Pattern
  , anonPatterns :: S.HashSet Pattern
  } deriving (Generic, NFData)

instance Show Patterns where
  show = undefined

instance Default Patterns where
  def = Patterns H.empty S.empty

data Value = ValueInteger Int
           | ValueString ByteString
           | ValueBool Bool
           deriving (Show, Eq, Generic, NFData)

-- | Holds the type of
data RuleType = Normal
              | Global
              | Private
              | GblPrv
              deriving (Show, Generic, NFData)

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
--type Conditions = Seq.Seq ConditionalExp

-- |
data Rule a = Rule {
    ruletype   :: RuleType
  , rulename   :: ByteString
  , tags       :: S.HashSet ByteString
--  , metadatum  :: Metadatum
  , patterns   :: Patterns
--  , conditions :: Conditions
  }


data LinearOrder = LessThan
                 | LessThanOrEqual
                 | Equal
                 | GreaterThanOrEqual
                 | GreaterThan
                 deriving (Eq, Show, Ord)

data PkgName = ByteString

data Name = LocalName ByteString
          | CmdName ByteString
          -- ImportName NameSpace PkgName ByteString

