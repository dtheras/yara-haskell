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
import Yara.Prelude
import Yara.Parsing.Args
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
