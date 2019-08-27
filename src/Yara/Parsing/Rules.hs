{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE BlockArguments #-}
{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
-- |
-- Module      :  Yara.Parsing.Rules
-- Copyright   :  David Heras 2018-2019
-- License     :  GPL-3
--
-- Maintainer  :  dheras@protonmail.com
-- Stability   :  experimental
-- Portability :  unknown
--
-- To annotate.
--
{-Zip -- haskell lib
based on LibZip
This is a binding to C library libzip.-}
module Yara.Parsing.Rules where

import Yara.Prelude
import Yara.Parsing.Combinators
import Yara.Parsing.Conditions
import Yara.Parsing.Parser
import Yara.Parsing.Strings
import Yara.Parsing.AST
import Yara.Parsing.Hash

import Text.Regex.Posix.Wrap
import Text.Regex.Posix ()
    -----
import qualified Data.Map.Strict as Map
import qualified Data.Sequence   as Seq
import qualified Data.Set        as Set



import Debug.Trace


{- Would is be possible to write something allong the lines of:

parseRules :: ______
parseRules = handleComments $ do
  parser1
  ...
  parserN

handleComments :: Yp a -> Yp a
handleComments p = case runParser p of
  sucessfill -> then sucessful
  fail       -> do
       parseComment
       continue from left of spots
-}




badModule i = fault $ "'" ++ i ++ "' is not an imported module"

--data ConditionOperator a =
  --MkHash :: Hash -> ConditionOperator Hash
 -- MkFile ::
bool :: Yp Bool
bool = (string "false" $> False) <|> (string "true" $> True) <?> "bool"
{-# INLINE bool #-}

value :: Yp Value
value = (ValueBool <$> bool) <|> {-ValueS <$> quotedString,-}
        (ValueInteger <$> decimal)
{-# INLINE value #-}

-- KEYWORD SETS

yaraKeywords :: Set.Set ByteString
yaraKeywords = Set.fromDistinctAscList [
   "all"       , "and"       , "any"      , "ascii"      ,
   "at"        , "condition" , "contains" , "entrypoint" ,
   "false"     , "filesize"  , "for"      , "fullword"   ,
   "global"    , "import"    , "in"       , "include"    ,
   "int16"     , "int16be"   , "int32"    , "int32be"    ,
   "int8"      , "int8be"    , "matches"  , "meta"       ,
   "nocase"    , "not"       , "of"       , "or"         ,
   "private"   , "rule"      , "strings"  , "them"       ,
   "true"      , "uint16"    , "uint16be" , "uint32"     ,
   "uint32be"  , "uint8"     , "uint8be"  , "wide"       ]

isKeyword :: ByteString -> Bool
isKeyword = flip Set.member yaraKeywords
-- IDENTIFIERS


-- possibly temporary. does the parsing of an identifier
-- but doesnt check if imported. very helpful.
_identifier :: Yp ByteString
_identifier = do
  -- must start with underscore or letter
  w <- satisfy isLeadingByte
  r <- scan 0 rho
  let i = w <+ r
  b <- peekByte
  if -- If the following byte is an id byte then identifier is illegal
     | isIdByte b -> do
         rest <- takeWhile isIdByte
         fault $ "Illegal identifier (must be <128 bytes): " ++ i ++ rest
     -- Keywords are not acceptable
     | isKeyword i -> fault $ "Identifier cannot be a keyword: '" ++ i ++ "'"
     -- Simply an underscore or digit is not an acceptable identifier
     | null r && not (isAlpha w) -> fault $ "Unacceptable identifier: " +> w
     -- Otherwise, we have an acceptable identifier
     | otherwise   -> pure i
  <?> "_identifier"
  where
    -- Read only upto 128 bytes (127 plus leading byte)
    rho :: Int -> Byte -> Maybe Int
    rho n b | n < 0 || 127 <= n  = Nothing
            | isIdByte b         = Just $ n + 1
            | otherwise          = Nothing
{-# INLINE _identifier #-}

-- | Parses an identifier.
--
-- Identifiers must follow the same lexical conventions of C identifiers:
-- > They can contain any alphanumeric character and the underscore character
-- > But the first character can not be a digit.
-- > Rule identifiers are case sensitive.
-- > Identifiers cannot exceed 128 characters.
--
-- The yara keywords are reserved and cannot be used as an identifier; see
-- @yaraKeywords@ for a list.
--
-- We additionally imposed that identifiers cannot be a single number or
-- just an underscore for the time being, due to parsing issues.
identifier :: Yp ByteString
identifier = do
  i <- _identifier
  b <- isDot <$> peekByte
  -- If the next byte is a dot, may be trying to import a module.
  -- Parse another identifier and check if it was imported
  if b
    then do -- Ensure that possible module is an imported one.
      m <- reader imports
      if Set.member i m
        then dot *> _identifier
        else badModule i
    else pure i
  <?> "identifier"
{-# INLINE identifier #-}

-- | Parse an identifier that doesn't/isn't "imported," ie. is not module name
-- trailed by a '.' trailed by an identifier
identifierNoImport :: Yp ByteString
identifierNoImport = do
  l <- _identifier
  s <- getStrings
  if l `Map.member` s
    then pure l
    else fault $ "String not in scope: " ++ l
{-# INLINE identifierNoImport #-}

-- | Parse an identifier preceeded by a '$'
-- Returns only the identifier.
label :: Yp ByteString
label = liftA2 seq dollarSign identifierNoImport
{-# INLINE label #-}


-- strings             ->
-- patterns            ->
-- identifiers         ->
-- identifiersWOImport -> situations where an identifier cannot be imported
--    eg: rule name.
--
-- labels        -> identifiers that are preceeded by a '$'
-- labelWOImport -> idenitifers that are preceeded by a '$'


ruleType :: Yp RuleType
ruleType = do
  spaces
  b <- peekByte
  case b of
    -- If 'r' then could only expect string  "rule."
    114 -> rule $> Normal
    -- If 'g' then could only expect string "global"
    -- ...but that may be followed be either string "rule" or "global"
    103 -> liftA2 (<>) global (private <* rule <|> rule)
    -- If 'p' then could only expect the string "private"
    -- ... which may be followed be either string "rule" or "global"
    112 -> liftA2 (<>) private (global <* rule <|> rule)
    -- Any other byte would suggest we've run into gibberish, so gobble it up
    -- and let them know!
    _   -> do
      gibberish <- takeWhile $ not . isSpace
      fault $ "Unrecognized keyword: '" ++ gibberish ++ "'"
  <?> "ruleType"
  where -- The key words "rule", "global" & "private" must be followed by at
        -- least one whitespace byte. Returns the assciated RuleType.
        global  = string "global"  <* space1 $> Global  <?> "global"
        private = string "private" <* space1 $> Private <?> "private"
        rule    = string "rule"    <* space1 $> Normal  <?> "rule"
        -- NOTE: According to YARA specification, anonymous rules seem to not
        -- be a supported feature and thus must have a label. Hence "rule" is
        -- to be followed by at least one whitespace token to seperate it from
        -- the rule label.
{-# INLINE ruleType #-}


-- type Metadata = Map.Map Identifier Value
-- | Parses the metadata of a yara rule.
--
-- Simple parser since metadata are just paired labels and a string.
parseMetadatum :: Yp Metadatum
parseMetadatum = do
  skipTo $ string "meta:"
  seekOnNewLine $ sepByMap aMetadata lineSeperated
                -- why not
  where
    aMetaData = pair identifier (Just $ skipToHz eq) (skipToHz value)



---------------------- CONDITIONS ---------------------------
-------------------------------------------------------------





{-
block :: (a -> f a -> f a)
      -> ByteString
      -> Yp a
      -> Yp (f a)
block s p = do
  string s <* colon
  skipTo $ sepBy p space1


-}


{-
strModifiers :: Yp
strModifiers = do
  skipTo $ perhaps "xor"
  sepBy1Set space1 $ foldMap string ["ascii", "fullword", "nocase", "wide"]
-}

{-
-- PARSE RULE BLOCK
-- YARA rules consist of:
--    - Possible keyword of "global" and/or "private"
--    - "rule" keyword
--    - Possible semicolon, followed by space seperated tags
--    - open curl bracket
--    - metadata block
--    - strings block
--    - conditions block (depends on the strings block)
parseRuleBlock :: Yp ()
parseRuleBlock = do
  oCurl
  meta <- parseMetadata keep_meta
  ss <- block "strings" patterns
  -- >>= (block "condition:") . conditions
  cCurl
  return $ Seq.singleton () -- Data.Map.empty <?> "Parse Rule Block"
  where


-- HEX

parseConditions :: Yp ()--[(ByteString,Pattern)]->Parser[ByteString->Bool]
parseConditions = do
  string "condition:"
  skipSpace

launch :: IO (Env, ExitCode)
launch = do
  res <- parseArgs `liftM` getArgs
  case res of
   Fail b1 bs b2 -> undefined
   Partial _     -> undefined
   Done b e      -> when (printHelp e) $ hPutStrLn stderr help $> ExitSuccess {- start running the program-}


main :: IO ()
main =
  (env,ec) <- launch
  case ec of
    ExitSuccess   -> if showHelp env == True
      then undefined
      else undefined {- if show help true, do so, else if show version true do so, otherwise proceeed-}
    ExitFailure 0 -> return ()
    ExitFailure 1 -> return ()
-}


{-}
range :: Yp (Word64, Word64)
range = do
  openParen
  spaces
  l <- decimal
  spaces
  dot
  dot
  spaces
  f <- getFilesize
  u <- decimal <|>
  spaces
  closeParen
-}



-- |
--
--               | Type        -> RuleType
--  RuleBlock -- | Name        -> Identifier
--               | :
--               | Tags        -> [Identifiers]
--               | {
--               | Metadata    -> [String Literal]
--               | Strings     -> [Hex-byte String | String Literal | Regex]
--               | Conditions  -> Many types
--               | }
--
--
ruleBlock :: Yp ByteString
ruleBlock = do
  spaces
  r <- ruleType
  n <- skipTo identifier
  t <- option mempty $ do
      skipTo colon
      skipTo (sepBy1Set identifier space1)
  skipTo oCurly
  m <- perhaps metadatum
--s <- perhaps strings
--modify (\e -> e { localStrings = s })
--c <- perhaps conditions
  spaces
  skipTo cCurly
         -- return t) <|> pure [""] -- tags-}
  -- need to merge if multiple of same tags
  def
  --return $ RuleBlock r n t _ _ _ --

-- ruleBlock = RuleBlock <$> ruleType
                      -- <*> ruleName
                     --  <*> ruleTags
                     --  <*  openCurl
                      -- <*> ruleMetadata
                      -- <*> ruleStrings
                     --  <*> ruleConditions
                     --  <* closeCurl

data YaraDoc = YaraDoc {
     docImports  :: Set.Set ByteString
  ,  docIncludes :: Set.Set ByteString
  ,  docRules    :: Set.Set YaraRuleBlock
  }
data YaraRuleBlock

{-

preprocess :: FilePath -> IO YaraDoc
preprocess fp = do
  b <- doesFileExist fp
  if b
    then undefined
    else undefined
  s <- preprocessIncludes
  return ""

-- 2.8 include files
-- run a preprocessing phase!
--preprocessing =
--
-- The argument passed in is the
--
-- NOTE: the function operates under the hypothesis that all "include"
--       statements are placed before all rule statements. Spec says "include"
--       statements behave as in C source files and those come at the begining
--       of C documents
--
preprocessIncludes :: FilePath
                   -- ^ Location of YARA rule in focus.
                   -> IO ByteString
                   -- ^ Results of expansion during preproccessing phrase
preprocessIncludes fp = do
    else do
      y <- readFile fp
          lns = lines y
      foldrM (\a acc -> liftA2 mplus (go fp a) (return acc)) [] bs
  where

    -- An YARA rule that gets "included" into a document may itself be
    -- in another folder and have its own "included" rules, (which will)
    -- be relative to included rule rather than the original) we need to
    -- manipulate the filepath a bit
    relFilePath :: FilePath -- current YARA rule
                -> FilePath -- relative location of included rule
                -> FilePath -- relative filepath from current dir
    relFilePath c f = dropFileName c </> f

    -- 'go' runs the 'include' parser and handles the results
    go :: FilePath -> ByteString -> IO [ByteString]
    go lc bs = case parseDef (processLine <|> pure $ Left bs) bs of
      Left bs  -> undefined
      Left ot  -> undefined
      Right fp -> do
        b <- doesFileExist fp
        -- Note the recursion!
        -- First: an included YARA rule could contain its own 'include' pragmas
        --        which must be handled (which may contain their own includes)
        -- Second: those include filepaths will be written relative to their
        --         location in the directory, not the original, so that must
        --         be handled

    include :: ByteString -> Either ByteString ByteString
    include bs = if isPrefixOf "include" bs
      then let bs_ = drop 7 bs
           in case parseDef (processLine <|> pure $ Left bs) of

      else Left ""
      where
        processLine = do
          buf <- getBuffer
          takeWhile1 isHorizontalSpace
          fp <- quotedString
          takeWhile isHorizontalSpace
          b <- atEnd
          return $ if b
            then Right fp
            else Left $ take 5 buf ++ ".."



newtype Proc a = Proc (IO (Either ProcessError a))
  deriving (Functor, )

instance Functor Proc where
  fmap f (Proc a) = Proc (liftM . liftM $ f a)
-}
