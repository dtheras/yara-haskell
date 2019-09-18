{-# LANGUAGE OverloadedStrings #-}

module Yara.Modules.Template where

import Prelude hiding (unlines)
import Data.ByteString
import Data.ByteString.Char8 (unlines)
import Data.Word
import System.Posix.Directory.ByteString (getWorkingDirectory)

import Yara.Shared
import Yara.System



templateContents :: ByteString
templateContents = unlines $
  [ "{-# LANGUAGE CPP #-}      "
  , "-- \"Yara.Modules\"  is where the definitions for YARA’s"
  , "-- module API reside, therefore this include directive is required"
  , "-- in all your modules. The second line is:"
  , "import Yara.Modules       "
  , ""
  , "-- Replace \"demo\" with you own module name"
  , "#define MODULE_NAME demo  "
  , ""
  ]

--- | --create-template-module
-- | One of the advantages of YARA is that modules are written in Haskell
-- souce code.
writeModuleTemplate :: MonadIO m => m Bool
writeModuleTemplate = io $ do
  d <- getWorkingDirectory
  let temp = d ++ "Template.hs"
  b <- doesFileExist temp
  if b
    then writeWithIncc temp templateContents 0
    else writeFile tempt templateContents


writeWithIncc :: FilePath -> ByteString -> Word -> IO ()
writeWithIncc f c n = do
  let fn = replaceFileName f $ concat [takeFileName f, "(", int2bs n,  ")"]
  b <- doesFileExist fn
  if b
    then writeWithIncc f c (n+1)
    else writeFile fn c
