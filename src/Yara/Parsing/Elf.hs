{-# LANGUAGE OverloadedStrings #-}
-- |
-- Module      :  Text.Yara.Parsing.Elf
-- Copyright   :  David Heras 2018-2019
-- License     :  GPL-3
--
-- Maintainer  :  dheras@protonmail.com
-- Stability   :  experimental
-- Portability :  unknown
--
-- To annotate.
--
module Yara.Parsing.Elf where

import Prelude hiding (FilePath)
import Data.ByteString.Char8 (unpack)
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString as S
import Yara.Shared

elfMagic :: S.ByteString
elfMagic = "\DELELF"

-- Even though L.toStrict is very expensive, generally O(n), we will only
-- ever have 4 bytes here.
hasElfMagic :: L.ByteString -> Bool
hasElfMagic bs = L.toStrict (L.take 4 bs) == elfMagic

isElfFile :: FilePath -> IO Bool
isElfFile path = do
  content <- L.readFile $ unpack path
  return $! hasElfMagic content
