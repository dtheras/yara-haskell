{-# LANGUAGE NoImplicitPrelude #-}
-- |
-- Module      :  Text.Yara.Parsing.PE
-- Copyright   :  David Heras 2018-2019
-- License     :  GPL-3
--
-- Maintainer  :  dheras@protonmail.com
-- Stability   :  experimental
-- Portability :  unknown
--
-- PE module contains more fine-grained rules for scanning PE files.
--
module Text.Yara.Parsing.PE where

import Yara.Prelude



numberOfSections :: Yp _
numberOfSections = do
  string "number_of_sections"
  spaces
  doubleEqual
  spaces
  i <- decimal
  _ doSomething i

exports :: Yp _
exports = do
  string "exports"
  spaces
  openParen
  spaces
  i <- quotedString
  spaces
  closeParen
  _ doSomething i

dll :: Yp _
dll = do
  string "DLL"
  _

characteristics :: Yp _
