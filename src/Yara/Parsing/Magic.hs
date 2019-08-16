-- |
-- Module      :  Yara.Parsers.Magic
-- Copyright   :  David Heras 2018-2019
-- License     :  GPL-3
--
-- Maintainer  :  dheras@protonmail.com
-- Stability   :  experimental
-- Portability :  unknown
--
-- "The Magic module allows you to identify the type of the file based on the
--  output of 'file', the standard Unix command.""
module Yara.Parsing.Magic (
  --  magicType, magicMimeType
  ) where

import Yara.Prelude
import Yara.Parsing.Parser

{-
type FileTest = L.ByteString -> IO Bool

magicUnsupportedMsg :: ByteString -> Yp a
magicUnsupportedMsg bs = fault $ "ahhd" ++ bs

magicType :: Yp FileTest
magicType bs = if onWindows
  then magicUnsupportedMsg "type_"
  else undefined

-- | Function returning a string with the MIME type of the file.
--
-- Example: magic.mime_type() == “application/pdf”
magicMimeType :: Yp FileTest
magicMimeType bs = if onWindows
  then magicUnsupportedMsg "mine_type"
  else do
    string "mime_type"
    openParen
    closeParen
    spaces
    doubleEqual
    spaces
    quotedString


hasMagic :: S.ByteString -> FileTest

-}
{-

-- This module is not supported on Windows.

There are two functions in this module: type() and mime_type(). The first one returns the descriptive string returned by file, for example, if you run file against some PDF document you’ll get something like this:

$file some.pdf
some.pdf: PDF document, version 1.5

The type() function would return “PDF document, version 1.5” in this case. Using the mime_type() function is similar to passing the --mime argument to file.:

$file --mime some.pdf
some.pdf: application/pdf; charset=binary

mime_type() would return “application/pdf”, without the charset part.

By experimenting a little with the file command you can learn which output to expect for different file types. These are a few examples:

        JPEG image data, JFIF standard 1.01
        PE32 executable for MS Windows (GUI) Intel 80386 32-bit
        PNG image data, 1240 x 1753, 8-bit/color RGBA, non-interlaced
        ASCII text, with no line terminators
        Zip archive data, at least v2.0 to extract

type()

    Function returning a string with the type of the file.

    Example: magic.type() contains “PDF”

mime_type()




-}
