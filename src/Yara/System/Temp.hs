
--- | This is just a temp file to test an idea:
--
--
--

module Text.Yara.System.Temp

import Data.ByteString.Lazy as L
import Data.ByteString as S

import GHC.IO.IOMode

-- | 
-- 
readFileWith :: FilePath -> Int -> Int -> IO L.ByteString
readFileWith


{-
-- and passes the resulting handle to the computation @act@.  The handle
-- will be closed on exit from 'withBinaryFile', whether by normal
-- termination or by raising an exception.
withBinaryFile :: FilePath -> IOMode -> (Handle -> IO r) -> IO r
withBinaryFile name mode = bracket (openBinaryFile name mode) hClose



-----------------------------------------------------------------------------
-- Detecting and changing the size of a file

-- | For a handle @hdl@ which attached to a physical file,
-- 'hFileSize' @hdl@ returns the size of that file in 8-bit bytes.

hFileSize :: Handle -> IO Integer
hFileSize handle =
    withHandle_ "hFileSize" handle $ \ handle_@Handle__{haDevice=dev} -> do
    case haType handle_ of
      ClosedHandle              -> ioe_closedHandle
      SemiClosedHandle          -> ioe_semiclosedHandle
      _ -> do flushWriteBuffer handle_
              r <- IODevice.getSize dev
              if r /= -1
                 then return r
                 else ioException (IOError Nothing InappropriateType "hFileSize"
                                   "not a regular file" Nothing Nothing)




openBinaryFile :: FilePath -> IOMode -> IO Handle
openBinaryFile fp m =
  catchException
    (openFile' fp m True True)
    (\e -> ioError (addFilePathToIOError "openBinaryFile" fp e))

openFile' :: String -> IOMode -> Bool -> Bool -> IO Handle
openFile' filepath iomode binary non_blocking = do
  -- first open the file to get an FD
  (fd, fd_type) <- FD.openFile filepath iomode non_blocking

  mb_codec <- if binary then return Nothing else fmap Just getLocaleEncoding

  -- then use it to make a Handle
  mkHandleFromFD fd fd_type filepath iomode
                   False {- do not *set* non-blocking mode -}
                   mb_codec
            `onException` IODevice.close fd
        -- NB. don't forget to close the FD if mkHandleFromFD fails, otherwise
        -- this FD leaks.
        -- ASSERT: if we just created the file, then fdToHandle' won't fail
        -- (so we don't need to worry about removing the newly created file
        --  in the event of an error).
-}
