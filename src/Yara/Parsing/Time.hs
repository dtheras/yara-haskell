{-# LANGUAGE NoImplicitPrelude #-}
-- |
-- Module      :  Text.Yara.Parsing.Time
-- Copyright   :  David Heras 2018-2019
-- License     :  GPL-3
--
-- Maintainer  :  dheras@protonmail.com
-- Stability   :  experimental
-- Portability :  unknown
--
-- Time-related functions module.
module Text.Yara.Parsing.Time where

import Yara.Prelude

data NumConTok = Time_Now

toTimeModuleFunction :: ByteString -> Either () NumConTok
toTimeModuleFunction bs = case bs of
  "now()" -> Right Time_Now
  _       -> Left ()
