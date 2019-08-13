{-# LANGUAGE PatternGuards #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE MultiWayIf #-}
-- |
-- Module      :  Text.Yara.System.FilePath
-- Copyright   :  David Heras 2018-2019
-- License     :  _
--
-- Maintainer  :  dheras@protonmail.com
-- Stability   :  stable
-- Portability :  portable
--
--  A library for FilePath manipulations using bytestrings.
module Yara.System.FilePath where

import Prelude hiding (last, null, span, (++))
import Yara.Parsers.Utilities (isWindows)
import Data.Word
import Data.ByteString
import Data.ByteString.Internal (accursedUnutterablePerformIO, ByteString(..))
import Data.ByteString.Unsafe
import Foreign

import Yara.Shared
--infixr 7  <.>, -<.>
--infixr 5  </>





{--------------------------------------------------------------------}
{-- BELONG IN UTILITIES FOLDER BUT HERE FOR NOW --}
type FilePath = ByteString
type Byte = Word8

b_slash :: Byte
b_slash = 92

f_slash :: Byte
f_slash = 47

colon :: Byte
colon = 58

semicolon :: Byte
semicolon = 59

dot :: Byte
dot = 46

q_mark :: Byte
q_mark = 63

isAlpha :: Byte -> Bool
isAlpha b = b - 65 < 26 || b - 97 < 26
{-# INLINE isAlpha #-}
{--------------------------------------------------------------------}
{--------------------------------------------------------------------}




(</>) :: FilePath -> FilePath -> FilePath
(</>)  a b | not (null b) && isPathSeparator (head b) = b
           | otherwise = combineRaw a b



isExtSeparator :: Byte -> Bool
isExtSeparator = (== doc)

searchPathSeparator :: Byte
searchPathSeparator = if isWindows then semicolon else colon

isSearchPathSeparator :: Byte -> Bool
isSearchPathSeparator = (== searchPathSeparator)

pathSeparator :: Byte
pathSeparator = if isWindows then b_slash else f_slash

isPathSeparator :: Byte -> Bool
isPathSeparator f_slash  = True
isPathSeparator b_slash  = isWindows
isPathSeparator _        = False

hasTrailingPathSeparator :: FilePath -> Bool
hasTrailingPathSeparator "" = False
hasTrailingPathSeparator x  = isPathSeparator (last x)

dropTrailingPathSeparator :: FilePath -> FilePath
dropTrailingPathSeparator fp
  | b && null n = singleton (unsafeLast fp)
  | b           = n
  | otherwise   = fp
  where b = hasTrailingPathSeparator fp && not (isDrive fp)
        n = dropEndWhile isPathSeparator fp

isDrive :: FilePath -> Bool
isDrive x = not (null x) && null (dropDrive x)
{-# INLINE isDrive #-}

dropDrive :: FilePath -> FilePath
dropDrive = snd . splitDrive
{-# INLINE dropDrive #-}

splitDrive :: FilePath -> (FilePath, FilePath)
splitDrive x | isPosix                     = span (== f_slash) x
splitDrive x | Just y <- readDriveLetter x = y
splitDrive x | Just y <- readDriveUNC x    = y
splitDrive x | Just y <- readDriveShare x  = y
splitDrive x                               = ("",x)
{-# INLINE splitDrive #-}


readDriveLetter :: FilePath -> Maybe (FilePath, FilePath)
readDriveLetter fp = case uncons2 fp of
  Just (x,colon,xs) -> if
            | isletter x -> if (not $ null xs) && isPathSeparator (head xs)
                  then Just $ addSlash (x <+ ":") xs
                  else Just (x <+ ":", xs)
            | otherwise ->  Nothing
  _             -> Nothing


readDriveShare :: FilePath -> Maybe (FilePath, FilePath)
readDriveShare fp = case uncons2 fp of
  Just (x1,x2,xs) -> if all isPathSeparator [x1,x2]
                       then Just (x1 <+ x2 <+ u, v)
                       else Nothing
  Nothing         -> Nothing
    where (u,v) = readDriveShareName xs




splitSearchPath :: ByteString -> [ByteString]
splitSearchPath _ (PS _ _ 0) = []
splitSearchPath w (PS x s l) = loop 0
  where
    g xs = if
      | isPosix   && xs == "" -> "."
      | isWindows && (head xs, tail xs == (34, 34) -> (init $ tail xs)
      | otherwise -> xs
    sep = searchPathSeparator
    loop !n =
      let q = accursedUnutterablePerformIO $ withForeignPtr x $ \p ->
                memchr (p `plusPtr` (s+n)) sep (fromIntegral (l-n))
      in if q == nullPtr
           then [map g $! PS x (s+n) (l-n)]
           else let i = accursedUnutterablePerformIO $ withForeignPtr x $ \p ->
                          return (q `minusPtr` (p `plusPtr` s))
                in (map g $! PS x (s+n) (i-n)) : loop (i+1)
{-# INLINE splitSearchPath #-}


isRelative :: FilePath -> Bool
isRelative x = null drive || isRelativeDrive drive
  where drive = takeDrive x

-- current directory on the drive with the specified letter."
isRelativeDrive :: String -> Bool
isRelativeDrive x =
    maybe False (not . hasTrailingPathSeparator . fst) (readDriveLetter x)

isAbsolute :: FilePath -> Bool
isAbsolute = not . isRelative


--------------------------------------------------
--------- DONE TO HERE ---------------------------
--------------------------------------------------

makeValid :: FilePath -> FilePath
makeValid "" = "_"
makeValid path
        | isPosix = map (\x -> if x == '\0' then '_' else x) path
        | isJust (readDriveShare drv) && all isPathSeparator drv = take 2 drv ++ "drive"
        | isJust (readDriveUNC drv) && not (hasTrailingPathSeparator drv) =
            makeValid (drv ++ [pathSeparator] ++ pth)
        | otherwise = joinDrive drv $ validElements $ validChars pth
    where
        (drv,pth) = splitDrive path

        validChars = map f
        f x = if isBadCharacter x then '_' else x

        validElements x = joinPath $ map g $ splitPath x
        g x = h a ++ b
            where (a,b) = break isPathSeparator x
        h x = if map toUpper (dropWhileEnd (== ' ') a) `elem` badElements then a ++ "_" <.> b else x
            where (a,b) = splitExtensions x






dropFileName :: FilePath -> FilePath
dropFileName = undefined
