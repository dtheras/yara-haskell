{-# OPTIONS_GHC -fno-full-laziness #-}
-- |
-- Module      :  Yara.Parsing.Types
-- Copyright   :  David Heras 2019
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

import qualified Data.HashMap.Strict as HM
import qualified Data.HashSet as HS
import qualified Data.Set as S

class HasImports s where
  imports :: s -> HM.HashMap ByteString ByteString

{-# WARNING InternalError "'InternalError' remains in code" #-}
data ExceptionCode
   = ExceptionSuccess
   -- ^ Successfull exception, whatever that is
   | ParseError
   -- ^ Uncatchable exception => prevent catching of particular error.
   -- The exception code is used for reporting errors during program used
   -- such as a parsing error of a misformatted YARA rule or a stack overflow.
   -- Since errors are reported with a message, it should contain a description
   -- of issue.
   | InternalError
   -- ^ Error for internal issues and shouldn't be thrown under normal runtime.
   -- Used for development/debugging only. It is intended to be removed after
   -- completion.

-- The exceptions below are "catchable". Why have any catchable ones?
-- Assists in avoiding back tracking in certain areas. These are a work
-- in progress.
   deriving (Generic, NFData, Show, Eq)

instance Default ExceptionCode where
  def = ExceptionSuccess

{-}   | UnterminatedInclude
   | FileDoesNotExist
   | ExpectedFilePathMissing
   | UnrecognizedPragma
   | IndentifierOverflow
   | InvalidIdentifier
   | IncorrectlyAlignedPragma
   | MutuallyDependentYaraFiles
   | UnterminatedStringLiteral
   | UnexpectedNewline
   | UnrecognizedEscapeCharacter
   | UnrecognizedKeyword
   | RuleNotInscope
   | UnrecognizedFlag
   | LonelyOpenParen
   | LonelyClosedParen -- ^ Encountered a closed paraenthesis without an opener
   | EndOfInput
   | BadRangeBounds
   | NotEnoughInput
   | OpenBlockComment -- ^ Unterminated block comment.
   | RemainingBufferToShort
   | InsufficientMemory
   | ScanTimeOut
   | CouldNotReadFile
   | UnsupportedFileVersion
   | InvalidExternalVariableType
   | TooManyMatches
   | ExceedingMaxStringPerRule
   | BadUnits
   | PatternNotInScope  -- ^
  {-      ExceptionSuccess
          ->
        FatalException
          ->
        InternalError
          ->

        UnterminatedInclude
          -> ["unterminated include pragma '", m, "' found in '", f, "'"]
        FileDoesNotExist
          -> ["included header file '", m, "' does not exist"]
        UnrecognizedPragma
          -> ["unrecognized pragma '", m]
        IncorrectlyAlignedPragma
          -> undefined
        InternalError
          -> ["generic exception ",m," ", int2bs $ position e ]
        UnterminatedStringLiteral
          -> ["unterminated string literal"]
        UnexpectedNewline
          -> ["unexpected newline"]
        UnrecognizedEscapeCharacter
          -> ["Unrecognized escape character ",m]
        UnrecognizedKeyword
          -> ["Unrecognized keyword: '",m,"' "]-}

-}


------------------------------------------------------------------------
-- Patterns

data PatternType = Str | Regex | Hex deriving (Generic, NFData, Show, Eq, Ord)

data Pattern = Pattern {
     patternBody      :: ByteString
   , patternType      :: PatternType
   , isPrivatePattern :: Bool
   } deriving (Generic, NFData, Show, Eq, Ord)

-- There are two types of patterns: name and anonymous.
data Patterns = Patterns {
    stdPatterns  :: HM.HashMap ByteString Pattern
  , anonPatterns :: S.Set Pattern
  } deriving (Generic, NFData, Show)

instance Default Patterns where
  def = Patterns HM.empty S.empty

data Value = ValueInteger Int
           | ValueString ByteString
           | ValueBool Bool
           deriving (Show, Eq, Generic, NFData)

data YaraRule = YaraRule
  { isGlobal   :: !Bool
  , isPrivate  :: !Bool
  , rulename   :: !ByteString
  , tags       :: !(HS.HashSet ByteString)
  , conditions :: !Conditions
  } deriving (Show,Generic,NFData)

instance Default YaraRule where
  def = YaraRule False False "" def Conditions

data Conditions = Conditions deriving (Show,Generic,NFData)

data Import  = Import  { filepat  :: FilePath }
data Include = Include { yararule :: FilePath }

data PkgName = ByteString

type Count = Integer





























data Name = LocalName ByteString
          | CmdName ByteString
          -- ImportName NameSpace PkgName ByteString

{-
data HexToken = HexPair !Byte !Byte
              | HexJump !(Maybe Word64) !(Maybe Word64)
              deriving (Eq, Show, Generic, NFData)

data HexSubPattern = HexString ![HexToken]
                   | HexGrouping ![HexSubPattern]
                   deriving (Eq, Show, Generic, NFData)

data HexPattern = HexPattern ![HexSubPattern]
   deriving (Eq, Generic, NFData)

instance Hashable HexToken where
instance Hashable HexSubPattern where
instance Hashable Pattern where

instance Show Pattern where
  show (StringPattern bs _)  = bs2s $ "string-pattern{ " ++ bs ++ "}"
  show (RegexPattern bs)     = bs2s $ "regex-pattern{ " ++ bs ++ "}"
  show (HexPattern bs) =
    bs2s $ "hex-string-pattern{ " ++ foldMap showHexSubPattern bs ++ "}"

showHexSubPattern :: HexSubPattern -> ByteString
showHexSubPattern (HexString xs)   = intercalate " " $ fmap rho xs
  where
    tt = s2bs . show
    rho :: HexToken -> ByteString
    rho (HexPair b1 b2)               = pack [b1,b2]
    rho (HexJump Nothing Nothing)     = "[-]"
    rho (HexJump Nothing (Just b2))   = "[-"++tt b2++"]"
    rho (HexJump (Just b1) Nothing)   = "["++tt b1++"-]"
    rho (HexJump (Just b1) (Just b2)) = "["++tt b1++"-"++tt b2++"]"

showHexSubPattern (HexGrouping xs) =
  " ( " ++ intercalate " | " (fmap showHexSubPattern xs) ++ " ) "

data Pattern = Pattern {
    patternRep       :: ByteString
  , isPrivatePattern :: Bool
  } deriving (Show)

-}
