{-# LANGUAGE NoImplicitPrelude #-}
-- |
-- Module      :  Yara.Main
-- Copyright   :  David Heras 2018-2019
-- License     :  GPL-3
--
-- Maintainer  :  dheras@protonmail.com
-- Stability   :  experimental
-- Portability :  unknown
--
-- yara-haskell is a Haskell implimentation of the YARA specification
--
module Yara.Main ( yara_haskell ) where

import Yara.Prelude
--import Yara.Parsing.Args
import Yara.Parsing.Parser

yara_haskell :: Env -> IO ()
yara_haskell env = do
  args <- getArgs
  case parseArgs args of
    Done _ env'  -> undefined
    Fail _ _ _   -> undefined
    Partial _    -> undefined


-- | Since yara now permits user-defined modules, may be possible to accomplish
-- this with the way that `xmonad --recompile` works.
--
-- The advantage is yara modules can be written in Haskell source.
--
--
--
-- | {-# LANGUAGE OverloadedStrings #-}
-- | import Yara.Modules
-- | moduleName :: ByteString
-- | moduleName = "skjfl;"
--
--
--
--

-- launchWithCustomModules :: _
launchWithCustomModules = undefined


moduleTemplate :: ByteString
moduleTemplate =
  "{-# LANGUAGE OverloadedStrings #-}      \
  \module TemplateModule where             \
  \import Yara.Modules                     \
  \                                        \
  \moduleName = \"templateModule\"        "




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

instance Default Flags where
  def = Flags {
      sourceFiles = Map.empty
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
