{-# OPTIONS_GHC -funbox-strict-fields #-}
{-# LANGUAGE BangPatterns #-}
-- |
-- Module      :  Yara.Parsing.Buffer
-- Copyright   :  David Heras 2018-2019
-- License     :  GPL-3
--
-- Maintainer  :  dheras@protonmail.com
-- Stability   :  experimental
-- Portability :  unknown
--
-- A buffer holds the bytestring currently being parsed in a fast
-- (for our parsing operations) structure.
--
module Yara.Parsing.Buffer (
  Pos, Buffer(..),
  toBuffer, bufferLength, bufferLengthAtLeast,
  bufferPappend, bufferAppend, bufferUnsafeIndex,
  bufferUnsafeDrop, bufferElemAt, bufferSubstring,

  -- ! CAREFULL ! See documentation.
  accursedUnutterablePerformIO
  ) where

import Prelude hiding (length, map)
import Control.Exception
import Data.ByteString.Internal
import Foreign.ForeignPtr
import Foreign.Ptr
import Foreign.Storable
import GHC.ForeignPtr
    -----
import Yara.Shared

type Pos = Int

-- | The buffer of text being parsed.
data Buffer = Buf {
    _fp  :: !(ForeignPtr Byte)  -- ^ Buffer payload
  , _off :: !Int                -- ^ Buffer offset
  , _len :: !Int                -- ^ Buffer length
  , _cap :: !Int                -- ^ Cap length
  , _gen :: !Int                -- ^
  }

-- | To annotate
bufferSubstring :: Int        -- ^ Offset marker
                -> Int        -- ^ Length of substring
                -> Buffer     -- ^ Buffer to use
                -> ByteString
bufferSubstring s l (Buf fp off len _ _) =
  assert (s >= 0 && s <= len) .
  assert (l >= 0 && l <= len-s) $!
  PS fp (off+s) l
{-# INLINE bufferSubstring #-}

-- | Convert a bytestring to a buffer
toBuffer :: ByteString -> Buffer
toBuffer (PS fp off len) = Buf fp off len len 0
{-# INLINE toBuffer #-}

bufferLength :: Buffer -> Int
bufferLength (Buf _ _ len _ _) = len
{-# INLINE bufferLength #-}

-- | To annotate
bufferLengthAtLeast :: Pos -> Int -> Buffer -> Bool
bufferLengthAtLeast p n bs = bufferLength bs >= p + n
{-# INLINE bufferLengthAtLeast #-}

-- | To annotate
bufferPappend :: Buffer -> ByteString -> Buffer
bufferPappend (Buf _ _ _ 0 _) bs   = toBuffer bs
bufferPappend buf (PS fp off len)  = bufferAppend buf fp off len
{-# INLINE bufferPappend #-}

-- | To annotate
bufferAppend :: Buffer -> ForeignPtr a -> Int -> Int -> Buffer
bufferAppend (Buf fp0 off0 len0 cap0 gen0) !fp1 !off1 !len1 =
  accursedUnutterablePerformIO . withForeignPtr fp0 $ \ptr0 ->
    withForeignPtr fp1 $ \ptr1 -> do
      let genSize = sizeOf (0::Int)
          newlen  = len0 + len1
      gen <- if gen0 == 0
          then return 0
          else peek (castPtr ptr0)
      if | gen == gen0 && newlen <= cap0 -> do
              let newgen = gen + 1
              poke (castPtr ptr0) newgen
              memcpy (ptr0 `plusPtr` (off0+len0))
                     (ptr1 `plusPtr` off1)
                     len1
              return (Buf fp0 off0 newlen cap0 newgen)
         | otherwise                     -> do
              let newcap = newlen * 2
              fp <- mallocPlainForeignPtrBytes (newcap + genSize)
              withForeignPtr fp $ \ptr_ -> do
                let ptr    = ptr_ `plusPtr` genSize
                    newgen = 1
                poke (castPtr ptr_) newgen
                memcpy ptr (ptr0 `plusPtr` off0) len0
                memcpy (ptr `plusPtr` len0) (ptr1 `plusPtr` off1)
                       len1
                return (Buf fp genSize newlen newcap newgen)
{-# INLINE bufferAppend #-}

-- | To annotate
bufferUnsafeIndex :: Buffer -> Int -> Byte
bufferUnsafeIndex (Buf fp off len _ _) i = assert (i >= 0 && i < len)
  . accursedUnutterablePerformIO . withForeignPtr fp $ flip peekByteOff (off+i)
{-# INLINE bufferUnsafeIndex #-}

-- | To annotate
bufferUnsafeDrop :: Int -> Buffer -> ByteString
bufferUnsafeDrop s (Buf fp off len _ _) =
  assert (s >= 0 && s <= len) $ PS fp (off+s) (len-s)
{-# INLINE bufferUnsafeDrop #-}

-- | Return the buffer element at the given position along with its length.
bufferElemAt :: ByteString -> Pos -> Buffer -> Maybe (Byte, Int)
bufferElemAt _ p b
  | p < bufferLength b   = Just (bufferUnsafeIndex b p, 1)
  | otherwise            = Nothing
{-# INLINE bufferElemAt #-}
