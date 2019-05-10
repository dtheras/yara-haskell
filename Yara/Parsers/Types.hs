
module Types where

import Data.ByteString

-- CONSTANSTS

maxArgsTag = 32
maxArgsIdentifier = 32
maxArgsExternVar = 32
maxArgsModuleData = 32

type FilePath = ByteString

type Identifier = ByteString

type Label = ByteString

data Value = Value_I Int
           | Value_S ByteString
           | Value_B Bool
           deriving Show

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
          | ImportName NameSpace PkgName ByteString


data NameSpace = VarName        -- ^ Variables
               | DataName       -- ^ Data constructors
               | TcClsName      -- ^ Type constructors and classes; Haskell has them
                                -- in the same name space for now.
               deriving( Eq, Ord, Show{-, Data , Generic-} )


