
-- |
-- Module      :  Yara.Scanning.Prim
-- Copyright   :  David Heras 2018-2019
-- License     :  GPL-3
--
-- Maintainer  :  dheras@protonmail.com
-- Stability   :  experimental
-- Portability :  unknown
--
-- Primitive YARA file scaning types.
-- [Really a place holder for now.]
module Yara.Scanning where


data Flags = Flags {
  , sourceFiles :: !(Map.Map Label FilePath)
  , moduleData       :: !(Map.Map Label FilePath)
  , onlyTags         :: !(Seq.Seq Label)
  , onlyIdens        :: !(Seq.Seq Label)
  , atomTable        :: !(Maybe FilePath)
  , maxRules         :: Int
  , timeout          :: Int
  , maxStrPerRule    :: Int
  , stackSize        :: Int
  , threads          :: Int
  , fastScan         :: Bool
  , failOnWarnings   :: Bool
  , compiledRules    :: Bool
  , oppositeDay      :: Bool
  , disableWarnings  :: Bool
  , recursiveSearch  :: Bool
  , printNumMatches  :: Bool
  , printMetadata    :: Bool
  , printModule      :: Bool
  , printNamespace   :: Bool
  , printStats       :: Bool
  , printStrings     :: Bool
  , printStrLength   :: Bool
  , printTags        :: Bool
  , printVersion     :: Bool
  , printHelp        :: Bool
  }


    , sourceFiles = Map.empty
    , targetFile = ""
   , moduleData = Map.empty
    , onlyTags = Seq.empty
    , onlyIdens = Seq.empty
    , atomTable = Nothing
    , maxRules = 32
    , timeout = 100000
    , maxStrPerRule = 10000
    , stackSize = 16384
    , threads = 1
    , fastScan = True
    , failOnWarnings = False
    , compiledRules = False
    , oppositeDay = False
    , disableWarnings = False
    , recursiveSearch = False
    , printNumMatches = False
    , printMetadata = False
    , printModule = False
    , printNamespace = False
    , printStats = False
    , printStrings = False
    , printStrLength = False
    , printTags = False
    , printVersion = False
    , printHelp = False
    }
