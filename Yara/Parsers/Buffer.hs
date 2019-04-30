{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE Rank2Types #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE UnboxedTuples #-}

module Buffer
  ( toBuffer
  , bufferLength
  , bufferLengthAtLeast
  , bufferPappend
  , bufferAppend
  , bufferUnsafeIndex
  , bufferUnsafeDrop
  , bufferElemAt
  , inlinePerformIO
  , getBuff
  , endOfBuffer
  , substring
  ) where

import Data.ByteString.Internal hiding (inlinePerformIO)
import Data.Word
import Foreign.ForeignPtr
import Foreign.Ptr
import Foreign.Storable
import GHC.ForeignPtr
import GHC.Base

import Types

toBuffer :: ByteString -> Buffer
toBuffer (PS fp off len) = Buf fp off len len 0
{-# INLINE toBuffer #-}

bufferLength :: Buffer -> Int
bufferLength (Buf _ _ len _ _) = len
{-# INLINE bufferLength #-}

bufferLengthAtLeast :: Pos -> Int -> Buffer -> Bool
bufferLengthAtLeast (Pos pos) n bs = bufferLength bs >= pos + n
{-# INLINE bufferLengthAtLeast #-}

bufferPappend :: Buffer -> ByteString -> Buffer
bufferPappend (Buf _ _ _ 0 _) bs  = toBuffer bs
bufferPappend buf (PS fp off len) = bufferAppend buf fp off len
{-# INLINE bufferPappend #-}

bufferAppend :: Buffer -> ForeignPtr a -> Int -> Int -> Buffer
bufferAppend (Buf fp0 off0 len0 cap0 gen0) !fp1 !off1 !len1 =
  inlinePerformIO . withForeignPtr fp0 $ \ptr0 ->
    withForeignPtr fp1 $ \ptr1 -> do
      let genSize = sizeOf (0::Int)
          newlen  = len0 + len1
      gen <- if gen0 == 0
             then return 0
             else peek (castPtr ptr0)
      if gen == gen0 && newlen <= cap0
        then do
          let newgen = gen + 1
          poke (castPtr ptr0) newgen
          memcpy (ptr0 `plusPtr` (off0+len0))
                 (ptr1 `plusPtr` off1)
                 (fromIntegral len1)
          return (Buf fp0 off0 newlen cap0 newgen)
        else do
          let newcap = newlen * 2
          fp <- mallocPlainForeignPtrBytes (newcap + genSize)
          withForeignPtr fp $ \ptr_ -> do
            let ptr    = ptr_ `plusPtr` genSize
                newgen = 1
            poke (castPtr ptr_) newgen
            memcpy ptr (ptr0 `plusPtr` off0) (fromIntegral len0)
            memcpy (ptr `plusPtr` len0) (ptr1 `plusPtr` off1)
                   (fromIntegral len1)
            return (Buf fp genSize newlen newcap newgen)

bufferUnsafeIndex :: Buffer -> Int -> Word8
bufferUnsafeIndex (Buf fp off len _ _) i = assert (i >= 0 && i < len) .
    inlinePerformIO . withForeignPtr fp $ flip peekByteOff (off+i)
{-# INLINE bufferUnsafeIndex #-}

bufferUnsafeDrop :: Int -> Buffer -> ByteString
bufferUnsafeDrop s (Buf fp off len _ _) =
  assert (s >= 0 && s <= len) $
  PS fp (off+s) (len-s)
{-# INLINE bufferUnsafeDrop #-}

inlinePerformIO :: IO a -> a
inlinePerformIO (IO m) = case m realWorld# of (# _, r #) -> r
{-# INLINE inlinePerformIO #-}

getBuff :: YaraParser ByteString
getBuff = YaraParser $ \_ t pos more _lose suc ->
  suc t pos more (bufferUnsafeDrop (fromPos pos) t)
{-# INLINE getBuff #-}

-- | Return the buffer element at the given position along with its length.
bufferElemAt :: ByteString -> Pos -> Buffer -> Maybe (Word8, Int)
bufferElemAt _ (Pos i) buf
  | i < bufferLength buf = Just (bufferUnsafeIndex buf i, 1)
  | otherwise      = Nothing
{-# INLINE bufferElemAt #-}

endOfBuffer :: YaraParser Bool
endOfBuffer = YaraParser $ \_ t pos more _lose suc ->
  suc t pos more (fromPos pos == bufferLength t)
{-# INLINE endOfBuffer #-}

substring :: Pos -> Pos -> Buffer -> ByteString
substring (Pos s) (Pos l) (Buf fp off len _ _) =
  assert (s >= 0 && s <= len) .
  assert (l >= 0 && l <= len-s) $
  PS fp (off+s) l
{-# INLINE substring #-}

unBuffer :: Buffer -> ByteString
unBuffer (Buf fp off len _ _) = PS fp off len
{-# INLINE unBuffer #-}


bufferFrontAppend :: ByteString -> Buffer -> Buffer
bufferFrontAppend bs buf = bufferPappend (toBuffer bs) (unBuffer buf)
