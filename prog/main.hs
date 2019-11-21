{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE UnboxedSums #-}
{-# LANGUAGE UnboxedTuples #-}
{-# OPTIONS_GHC -funbox-strict-fields #-}
-- |
-- Module      :  Main
-- Copyright   :  David Heras 2019
-- License     :  GPL-3
--
-- Maintainer  :  dheras@protonmail.com
-- Stability   :  experimental
-- Portability :  unknown
--
-- To annotate
--
module Main (main)

import Yara.Prelude
import System.IO (hSetBuffering, BufferMode(..), stdout, stderr)
import System.Posix.Env.ByteString (getArgs)
import qualified Data.HashSet as HS
import qualified Data.HashMap.Strict as HM

main :: IO ()
main = launch def

-- | 'launch' initiates the program by taking the cmdargs & setting up
-- the evironment for the program.
launch :: GlobalEnv -> IO ()
launch e = do
  hSetBuffering stdout LineBuffering
  hSetBuffering stderr LineBuffering
  args0 <- getArgs
  let -- Parses command line arguments.
      handleArgs = undefined

      (# glbEnv, rules, targets #) = handleArgs args0
  undefined

-- | 'GlobalEnv' record holds the enviromental parameters used
-- while scanning. Defaults match yara spec.
data GlobalEnv = GlobalEnv  {
  , sourceFiles      :: !(HS.HashSet FilePath)
  , moduleData       :: !(HM.HashMap ShortByteString FilePath)
  , onlyTags         :: !([Label])
  , onlyIdens        :: !([Label])
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

instance Default GlobalEnv where
  def = Flags {
      sourceFiles = def
    , moduleData = def
    , onlyTags = []
    , onlyIdens = []
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
