-- |
-- Module      :  Yara.Prelude
-- Copyright   :  David Heras 2018-2019
-- License     :  GPL-3
--
-- Maintainer  :  dheras@protonmail.com
-- Stability   :  experimental
-- Portability :  unknown
--
-- Local prelude replacement (the extension
-- NoImplicitPrelude is enabled globally).
--
-- See Yara.Prelude.Internal for design targets.
--
module Yara.Prelude (
    module Export
  ) where

import Yara.Prelude.Internal as Export
import Yara.Prelude.System as Export
