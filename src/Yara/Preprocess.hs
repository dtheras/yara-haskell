{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE NoImplicitPrelude #-}
-- |
-- Module      :  Yara.Parsing.Preprocess
-- Copyright   :  David Heras 2019
-- License     :  GPL-3
--
-- Maintainer  :  dheras@protonmail.com
-- Stability   :  experimental
-- Portability :  unknown
--
-- Preprocess round 1.
--
-- Remove any comments from souce file.
--
module Yara.Parsing.Preprocess where

import Yara.Prelude

import Foreign

-- | @S@ a state token used for `removeComments`
data S = MaybeComment          -- encountered a '/' in normal text
       | SingleLineComment     -- in single line comment
       | BlockComment          -- in block comment without newline char yet
       | MaybeEndBlockComment  -- enocountered a '*' in a block comment
       | QuoteBlock            -- in a quote block
       | EscingQuoteBlock      -- escapping quote block
       | HangingQuoteBlock     -- hanging block quote --> issue!
       | NormalSrc             -- regular source
       deriving (Eq,Show)

-- | @removedComments@ removes any C-style comments from a bytestring,
-- returning the final state for exception handling.
removeComments :: ByteString -> (ByteString, S)
removeComments bs@(PS _ _ l) = atomicModification (atomic l) NormalSrc bs
  where
    atomic :: Int -> S -> Ptr Byte -> Int -> Int -> IO (Int, S)
    atomic _ s@HangingQuoteBlock _ _ hare = pure (hare, s)
    atomic len !st !ptr !tort !hare
      | hare >= len = pure (tort, st)
      | otherwise   = do
         b <- peekByteOff ptr hare
         let T2 t s = update tort b st
         -- Should be a way to tidy following up. Seems redundant.
         -- See "textString" for ideas.
         when (st == MaybeComment && b /= 47 && b /= 42)
              (pokeByteOff ptr tort (47::Word8))
         when (s /= MaybeComment && t > tort) (pokeByteOff ptr tort b)
         atomic len s ptr t (hare+1)
    {-# INLINE atomic #-}

    update :: Int -> Byte -> S -> T2 Int S
    update t b NormalSrc = case b of
      47 -> T2 t MaybeComment
      34 -> T2 (t+1) QuoteBlock
      _  -> T2 (t+1) NormalSrc
    update t b MaybeComment = case b of
      42 -> T2 t BlockComment
      47 -> T2 t SingleLineComment
      34 -> T2 (t+1) QuoteBlock
      _  -> T2 (t+1) NormalSrc
    update t b QuoteBlock = case b of
      34 -> T2 (t+1) NormalSrc
      92 -> T2 (t+1) EscingQuoteBlock
      _  -> if isEndOfLine b
       then T2 t HangingQuoteBlock
       else T2 (t+1) QuoteBlock
    update t b BlockComment = case b of
      42 -> T2 t MaybeEndBlockComment
      _  -> T2 t BlockComment
    update t b MaybeEndBlockComment = case b of
      47 -> T2 t NormalSrc
      _  -> T2 t BlockComment
    update t b SingleLineComment = if isEndOfLine b
       then T2 (t+1) NormalSrc
       else T2 t SingleLineComment
    update t b EscingQuoteBlock = if isHorizontalSpace b
       then T2 (t+1) EscingQuoteBlock
       else T2 (t+1) QuoteBlock
    update t _ HangingQuoteBlock = T2 t HangingQuoteBlock
    {-# INLINABLE update #-}
{-# INLINABLE removeComments #-}







{- CODE SALVAGEYARD, MEMORYYARD, & GRAVEYARD

-- Moves focus back one if prevous needs to over written
remPrev :: S -> Byte -> Tort -> Tort
remPrev (MaybeCmt _) 42 = if (> 0) then (-1) else id
remPrev (MaybeCmt _) 47 = if (> 0) then (-1) else id
remPrev (MaybeEnd _) 47 = (-1)
remPrec _            _  = id
  if needBackdate s x && _tort > 0
    then pokeByteOff p2 (_tort-1) (32 :: Byte)
    else return ()

-- | `removedComments_` removes any C-like comments from a bytestring and then
-- returns the final internal state for use in error reporting.
--
removeComments_ :: ByteString -> (S, ByteString)
removeComments_ (PS fp off len) =
  -- Body of `removeComments` function sets up needed memory
  -- while `atomic` does the transformation
  unsafeDupablePerformIO $ withForeignPtr fp $ \a -> do
    ptr       <- mallocByteString len
    (# l,s #) <- withForeignPtr ptr $ atomic OK 0 0 (a `plusPtr` off)
    assert (l <= len) $ return $! (s, PS ptr 0 l)
  where
    -- `atomic` applies the current state with current byte
    -- to determine how modify byte, before updating the state.
    atomic :: S -> Int -> Int -> Ptr Byte -> Ptr Byte -> IO (# Int, S #)
    atomic !st !tort !hare !p1 !p2
       | hard >= len = return (tort, s)
       | otherwise   = do
           x <- peekByteOff p1 foc
           -- If newline in quote is not escaped within quote block,
           -- exit with state for reporting. Otherwise, keep looping
           -- forward
           if st == Quote && isNewline x
           then return (# hare, Quote #)
           else do
           --this is conditional pokeByteOff p2 _tort _x

           if | st `elem` [Quote,OK]
              -> pokeByteOff p2 tort x
              | st == BlkCmtWONL && isNewline x
              -> pokeByteOff
              | otherwise
              -> return ()

          atomic _st _tort (hare+1) p1 p2

---- only reason to
           let (# _tort_, _st #) = transform tort x st

-- | `removedComments` removes
removeComments :: ByteString -> (S, ByteString)
removeComments (PS fp s len) =
  unsafeDupablePerformIO $ withForeignPtr fp $ \a -> do
    createS len $ atomic (S 0 OK) 0 (a `plusPtr` s)
  where
    createS :: Int -> (Ptr Byte -> IO S) -> IO (S, ByteString)
    createS l f = do
      ptr <- mallocByteString l
      st <- withForeignPtr ptr $ \p -> f p
      return $! (st, PS ptr 0 l)

--- Original attempt to parse chunks and eventually gluing them back togehter.
-- While faily intuitve and uses our parser cominators, not likely to be
-- very case since bytestring appending means copying strings.
parseRemoveComments_ :: ByteString -> Yp ByteString
parseRemoveComments_ pre = do
  bs <- takeWhile (not.importantByte)
  let acc = pre ++ bs
  ifM endOfBuffer
      (pure acc)
      $ (handleLineComment acc <|> handleBlockComment acc)
       `catchError` \e -> if e == OpenBlockComment
        then fault e (toByteString e)
        else handleQuotation acc
        `catchError` \e -> if isStringLiteralException e
        then fault e (toByteString e)
        else handleCatchCase acc

  where

    importantByte :: Byte -> Bool
    importantByte = (==34) <> (==45) <> (==47) --quote,dash,forwardslash

    -- Parses out a standard C-like line comment:
    --
    -- >
    -- > -- this is a single line comment
    -- >
    handleLineComment :: ByteString -> Yp ByteString
    handleLineComment a = do
      string "//"
      scan () $ \_ b -> if isEndOfLine b then Nothing else Just ()
      parseRemoveComments_ a

    -- Parses out a standard C-like block comment:
    --
    -- >
    -- > /*
    -- > this is a block/multi-line comment
    -- > */
    -- >
    --
    handleBlockComment :: ByteString -> Yp ByteString
    handleBlockComment a = do
      string "/*"
      (void $ scan 0 $ \st b -> if
             | b==42           -> Just 1  -- '*'
             | b==47 && st==1  -> Just 2  -- '/' following a '*'
             | st>1            -> Nothing
             | otherwise       -> Just 0
        ) <|> fault OpenBlockComment "handleBlockComment"
      parseRemoveComments_ a

    -- If the next byte is a quote, parse a block of literal text.
    --
    -- > "this is a literal block of text "
    --
    -- Handled since its possible a literal text may contain
    -- comment syntax.
    handleQuotation :: ByteString -> Yp ByteString
    handleQuotation a = do
      s <- quotedString
      let acc = a ++ s
      parseRemoveComments_ acc

    -- Since 'parseRemoveComments_' only stops accumulating bytes is if it
    -- comes accross a '/' or '"',
    handleCatchCase :: ByteString -> Yp ByteString
    handleCatchCase a = do
      b <- anyByte
      parseRemoveComments_ $ a +> b

    isStringLiteralException :: ExceptionCode -> Bool
    isStringLiteralException e =
      e == UnterminatedStringLiteral ||e ==  UnrecognizedEscapeCharacter


parseRemoveComments :: ByteString -> Either String ByteString
parseRemoveComments bs = case parse_ (parseRemoveComments_ "") bs of
  f@(Fail _ _ _)  -> Left $ show f
  Partial _       -> Left "partial. some reason. didn't all parse"
  Done "" v       -> Right v
  Done rem v      ->
    Left $ concat ["done but some reason. didn't all parse", bs2s rem, " ", show v]



-- | `comment` parses a C-style block or single-line comment
-- in a YARA rule source file.
comment :: Yp ()
comment = blockComment <|> lineComment
  where
    blockComment = do
      string "/*"
      void $ scan 0 $ \st b -> if
             | b==42           -> Just 1  -- '*'
             | b==47 && st==1  -> Just 2  -- '/' following a '*'
             | st>1            -> Nothing
             | otherwise       -> Just 0
    lineComment = do
      string "--"
      scan () $ \_ b -> if isEndOfLine b then Nothing else Just ()
      endOfLine
{-# INLINE comment #-}


guardEOI :: Yp a -> Yp a
guardEOI p = ifM endOfInput (fault EndOfInput "endOfInput") p


parseHeader :: Yp PreprocessState
parseHeader = do
  let interestingByte = -\"*ri
  bs <- takeWhile not.interestingByte
  let acc = a ++ bs
  b <- peekByte
  atInit <- atLineInit
  atEnd <- endOfInput
  if | b isR -> seeIfRuleOtherwiseFault
     | atEnd -> 




-- | Peek at previous byte, returning 'Nothing' if at the beginning, else
--       'Just' previous byte.
--
-- Target use: determine if pragmas are placed at the begining of a file line.
--
-- Does not modify buffer.
peekPrevByte :: Yp (Maybe Byte)
peekPrevByte = YP $ \b e l s -> do
  pos <- getPos
  pure $ if pos > 0
    then Just $ bufferUnsafeIndex b (pos-1)
    else Nothing
{-# INLINE peekPrevByte #-}

atLineInit :: Yp Bool
atLineInit = do
  b <- peekPrevByte
  pure $ maybe True ((==13)<>(==10)) b
{-# INLINE atLineInit #-}

run :: IO ()
run = print . runPreprocess =<< readFile

runPreprocess :: ByteString -> Result ByteString
runPreprocess bs = let ps = Preprocessing "" Nothing bs in undefined
   parse env parsePrelude ps)

data PreprocessState = PreprocessState { processed :: ByteString
                                       , focusToken :: Maybe Token
                                       , toProcess  :: ByteString
                                       } deriving Show



    atomic :: S -> Int -> Int -> Ptr Byte -> Ptr Byte -> IO (Int, S)
    atomic !st !tort !hare !r !w
      | hare >= len = return (tort, st)
      | otherwise   = do
         b <- peekByteOff r hare
         let (# t, s #) = update tort b st
         when (st == MaybeComment && b /= 47 && b /= 42)
              (pokeByteOff w tort (47::Byte))
         if s /= MaybeComment && t > tort
                  then pokeByteOff w tort b
                  else unit
        {- if tort == 0
           then if s == MaybeComment
                  then unit
                  else pokeByteOff w tort b
           else if t > tort
                  then pokeByteOff w tort b
                  else unit-}
         if s == HangingQuoteBlock
           then return (hare, s)
           else atomic s t (hare+1) r w
    {-# INLINE atomic #-}



aux :: ByteString -> Yp ByteString
aux acc = do
  bs <- takeWhile notQuoteOrCommentStarter
  b <- peekByte
  atend <- endOfInput
  let n = acc ++ bs
  if atend
    then -> pure $ n
    else do b <- peekByte
            if | isQuote b -> do q <- quotedString
                                 aux $ n ++ q
               | isCommentStarter b
            -> do (do comment; aux n)
                     <|> (do b <- anyByte; aux $ n +> b)
  where isQuote = (==34)
        isComment = (==-) <> (==/)

-- | Parse a yara rule pragma.
pragma :: IO (Yp ByteString)
pragma = ifM atLineInit parsePragma (fault_ "pragma")
  where
    parsePragma :: IO
    parsePragma = do
      
      p <- quotedString $> PPQuotedString
         <|> comment $> PPComment
         <|> string "rule" $> PPRule
         <|> string "import" $> PPImport
         <|> string "#include" $> PPInclude
         <|> pure PPOther
      case p of
        PPImport  -> undefined
        PPInclude -> undefined

        -- We are in a rule block, and import statements cannot be here.
        PPRule    -> do

        PPOther   -> undefined

parser :: ByteString -> IO (Yp ByteString)
parser bs = do
  spaces
  b1 <- comment $> False <|> pure True
  spaces
  b2 <- atLineInit
  m <- peekByte
  if b
    then if | 
  --either import or include, else parser.

-- | @Preprocess@ runs a first pass through a YARA rules file expanding
-- include pragmas and stripping comments.
preprocess :: FilePath -> IO (Either PreprocessError (Result a))
preprocess fp = do
  f <- readFile fp -- should be imporved to handle issues

parseImport :: Yp Import
parseImport = do
  b <- atLineInit
  string "import"
  satisfy isHorizontalSpace
  m <- peekByte
  if isHorizontalSpace m
    then 
  horizontalSpace1
  s <- quotedString
  r <- remainderOfLineIsWhiteSpace
  if | not b -> fault "parseImport" IncorrectlyAlignedPragma

       if s `elem` predefinedModules
        then PredefinedModule s
        else UserModule s
    then 
    else do

data Import = PredefinedModule ByteString
            | UserModule ByteString
            deriving (Show, Eq, Ord)

predefinedModules :: [ByteString]
predefinedModules = ["cuckoo", "dotnet", "hash", "magic", "math", "pe", "time"]

-- | Parses all bytes from current cursor point to (and including) next
-- newline token.
remainderOfLineIsWhiteSpace :: Yp (Maybe ByteString)
remainderOfLineIsWhiteSpace = do
  (bs,st) <- scanSt True $ \s b -> if
     | isEndOfLine b             -> Nothing
     | isHorizontalSpace b && s  -> Just True
     | otherwise                 -> Just False
  endOfLine
  if st True
    then Nothing
    else Just bs



parseInclude :: Yp ByteString
parseInclude = do
  string "include"
  horizontalSpace1
  s <- quotedString
  r <- remainderOfLineIsWhiteSpace
  case r of
    Just msg  -> fault msg
    Nothing   -> pure s




-- | `comment` parses a C-style block or single-line comment
-- in a YARA rule source file.
comment :: Yp ()
comment = blockComment <|> lineComment
  where
    blockComment = do
      string "/*"
      void $ scan 0 $ \st b -> if
             | b==42           -> Just 1  -- '*'
             | b==47 && st==1  -> Just 2  -- '/' following a '*'
             | st>1            -> Nothing
             | otherwise       -> Just 0
    lineComment = do
      string "--"
      scan () $ \_ b -> if isEndOfLine b then Nothing else Just ()
      endOfLine
{-# INLINE comment #-}





-- | @comment@ parses either a single-line or multi-line
--
-- YARA rules can be comment just as if a C source file
-- >
-- > /*
-- >    This is a multi-line comment ...
-- > */
-- >
-- > // ... and this is single-line comment
--
-- Returns the just the comment contents
comment :: Yp Comment
comment = do -- Double Line
  string "/*"
  bs <- scan False $ \s b -> if
      | b == 42       -> Just True  -- If '*', set 's' to 'True'
      | b == 47 && s  -> Nothing    -- If '/' following a '*', end scan
      | otherwise     -> Just False -- Else, set 's' to False
  {- With how 'scan' is written, we will have the need to strip a '*'
     off the end. Thankfully ByteStrings allow O(1) 'unsnoc'.         -}
  pure $ MultiLineComment $ maybe "" fst $ unsnoc bs
  <|>     do -- Singe Line
  string "--"
  -- scan until a new line byte is found ('\n' or '\r')
  bs <- scan () $ \_ b -> if b == 10 || b == 13 then Nothing else Just ()
  pure $ SingleLineComment bs
{-# INLINE comment #-}





-- | `S` a state token used for `removeComments_` && `removeComments`
data S = MaybeComment
       -- Found a forward slash
       | SingleLineComment
       -- Currently in a single line comment
       | BlockCommentWithNL
       -- In block comment that has at least one newline occurence
       | BlockCommentWithoutNL
       -- In block comment with no newline occurence yet
       | MaybeEndWithoutNL
       -- Possibly closing a block comment
       | MaybeEndWithNL
       --
       | QuoteBlock
       -- Currently in quote block
       | EscingQuoteBlock
       -- Escaping the quote block (only '"', baddies later)
       | HangingQuoteBlock
       -- Quote was not ended before new line
       | NormalText
       -- Normal text
       deriving Eq

-- | `removedComments_` removes any C-like comments from a bytestring,
-- returning the final state for exception handling.
removeComments_ :: ByteString -> (ByteString, S)
removeComments_ (PS fp off len) =
  unsafeDupablePerformIO $ withForeignPtr fp $ \a ->
    create_ len $ atomic NormalText 0 0 (a `plusPtr` off)
  where

    -- `atomic` roughly-traverses the bytestring using a
    -- state `S`, coupled with two offset counters to atomically
    -- modify the bytestring. The offets are labeled as follows:
    --    * `hare` offset corresponds to read-byte location
    --    * `tort` offset corresponds to write-byte location
    --
    --  ** Always: Tort <= Hare **
    --
    -- `hare` gets incramented (move forward one) at the end of the loop block
    -- only.
    --
    -- `Tort` gets incramented only at the update spot. So, when entering a
    -- loop, the pointed "spot" for tort is "filled."
    atomic :: S -> Int -> Int -> Ptr Byte -> Ptr Byte -> IO (Byte, S)
    atomic !st !tort !hare !r !w
      | hare >= len = return (tort, st)
      | otherwise   = do
         b <- peekByteOff r hare
         let (# t, s #) = update tort b st
         -- [1] If we have a '/' followed by
         -- anything other than a '*' or '/', we need to go
         -- write the '/'. Noting that `update` has moved
         -- tort forward one.
         when (st == MaybeComment && b /= 47 && b /= 42)
              (pokeByteOff w tort (47::Byte))

         -- [2] If we've moved the tort forward there
         --   is definitely something to write (forall cases)
         when (t > tort) (pokeByteOff w t b)
         if s == OpenQuote     -- returning 'hare' here since we need
         then return (hare, s) -- to report error location.
         else atomic s t (hare+1) r w

    -- `update` modifies state and tortise pointer based on
    -- current state and focused byte. Originally written as
    -- two functions, rewritten as one to better keep track
    -- of cases.
    update :: Int -> Byte -> S -> (# Int, S #)
    update t b OK = case b of
      47 -> (# t  , MaybeCmt #)
      34 -> (# t+1, Quote    #)
      _  -> (# t+1, OK       #)
    update t b MaybeCmt = case b of
      42 -> (# t  , BlkCmtWONL #)
      47 -> (# t  , SigCmt     #)
      34 -> (# t+1, Quote      #)
      _  -> (# t+1, OK         #)
    update t b Quote = case b of
      34 -> (# t+1, OK        #)
      92 -> (# t+1, Escing    #)
      _  -> if isEndOfLine b
       then (# t  , OpenQuote #)
       else (# t+1, Quote     #)
    update t b BlkCmtWNL = case b of
      42 -> (# t  , MaybeEndNL #)
      _  -> (# t  , BlkCmtWNL  #)
    update t b MaybeEndNL = case b of
      47 -> (# t  , OK        #)
      _  -> (# t  , BlkCmtWNL #)
    update t b BlkCmtWONL = case b of
      42 -> (# t  , MaybeEndWONL #)
      _  -> if isEndOfLine b
       then (# t+1, BlkCmtWNL    #)
       else (# t  , BlkCmtWONL   #)
    update t b MaybeEndWONL = case b of
      47 -> (# t  , OK         #)
      _  -> (# t  , BlkCmtWONL #)
    update t b SigCmt = if isEndOfLine b
      then (# t+1, OK     #)
      else (# t  , SigCmt #)
    update t b Escing = if isHorizontalSpace b
      then (# t+1, Escing #)
      else (# t+1, Quote  #)
    update t b OpenQuote = (# t  , OpenQuote #)
    {-# INLINABLE update #-}

{-# INLINABLE removeComments_ #-}





getWorkingdir :: YP a
getWorkingdir = dropFileName <$> getFilepath

fetchRule :: FilePath  --- "unverified" path that has been included
          -> YpIO (Either PreprocessError ByteString)
fetchRule fp = do
  foc <- getFilepath
  let wp = dropFileName foc
      path = wd </> fp
  b <- doesFileExist path
  if b
    then
    else do let err = PreprocessError foc fp HeaderFileDoesNotExist
            Left err





displayTests :: IO ()
displayTests = do
  putStrLn "test 1"
  print_ "write" "write"
  putStrLn "test 2"
  print_ "wri\nte" "wri//  \nte"
  putStrLn "test 3"
  print_ "david" "dav/* dad */id"
  print "test 4"
  print_ "david" "dav/*   */id"
  print "test 5"
  print_ "dav id" "dav/*   */ id"
  print "test 6"
  print_ "dav\nid" "dav/*\n*/id"
  print "test 7"
  print_ "dav\nid" "dav/*\n\n*/id"
  print "test 8"
  print_ "dav\nid" "dav//vvvv\nid"
  putStrLn "test 9"
  print_ "\"//\"" "\"//\""
  putStrLn "test 10"
  print_ "dav\n\nid"      "dav// vvvv\n//  \nid"
  putStrLn "test 11"
  print_ "dav\"/**/\"id"  "dav\"/**/\"id"
  putStrLn "test 12"
  print_ "dav\" \\\n \"id" "dav\" \\\n \"id"
  putStrLn "test 13"
  print_ "dav\" \\  \n \"id" "dav\" \\  \n \"id"
  putStrLn "test 14"
  print_ "david is \"the mostes \\\"\" handsome\"  "
         "david is \"the mostes \\\"\"/* hello */ handsome\"  "
  where
    print_ :: ByteString -> ByteString -> IO ()
    print_ a b = do
      let a_ = (Right a :: Either EC ByteString)
          b_ = removeCComments_ b
      print a_
      print b_
      print $ a_ == b_
      print ""
    {-# INLINE print_ #-}

--------------------------------------------------------------------------------
-- Strict/Unpacked Tuples

-- Note: the -funbox-strict-fields lets us to omit the UNPACK pragmas
--
-- The following reasoning was used in choosing using.
--
--  * [To the extent of my knowledge] The fusion optimization GHC does in
--    eliminating intermediate tuples is in the following case:
--      > f (a,b) = f' a b
--      > f' a b = doSomething
--    In those cases, we use normal tuples since syntactically its nicer
--    and computationally irrevant. However, quite often there is the
--    following:
--    > someFun = do
--    >   (a,b) <- crazyComputation
--    >   if | f a -> doFirstBranch
--    >      | h b -> doSecondBranch
--    Ostensibly there is much bigger step in the code that would prevent
--    fusion. In reality, the compiler may still be able to optimize that
--    away. No information has been found, and we have yet to be able to
--    test.
--
--  * Unboxed tuples are very nice, sytactically convinent but have two
--    limitations.
--
--    Again, it is unknown the speed gains.
-}
