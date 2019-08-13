{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE BlockArguments #-}
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

import Prelude hiding ((++), takeWhile, unlines, quot, sequence, null,
                       unwords, putStrLn, replicate, replicate, head,
                       FilePath, span, all, take, drop, concat, length)
import Data.ByteString hiding (foldl1, foldl, foldr1, putStrLn,
                               zip, map, replicate, takeWhile, empty,
                               elem, count, tail, unpack, pack)
import Control.Monad.Reader
import Data.Default
import Text.Regex.Posix.Wrap
import Text.Regex.Posix ()
    -----
import qualified Data.Map.Strict as Map
import qualified Data.Sequence   as Seq
import qualified Data.Set        as Set
    -----
import Yara.Parsing.Combinators
import Yara.Parsing.Parser
import Yara.Parsing.Types
import Yara.Parsing.Hash
import Yara.Shared

import Debug.Trace

data Comment = MultiLineComment ByteString
             | SingleLineComment ByteString

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
comment :: YP Comment
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
{- Would is be possible to write something allong the lines of:

parseRules :: ______
parseRules = handleComments $ do
  parser1
  ...
  parserN

handleComments :: YP a -> YP a
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
bool :: YP Bool
bool = (string "false" $> False) <|> (string "true" $> True) <?> "bool"
{-# INLINE bool #-}

value :: YP Value
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
_identifier :: YP ByteString
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
identifier :: YP ByteString
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
identifierNoImport :: YP ByteString
identifierNoImport = do
  l <- _identifier
  s <- getStrings
  if l `Map.member` s
    then pure l
    else fault $ "String not in scope: " ++ l
{-# INLINE identifierNoImport #-}

-- | Parse an identifier preceeded by a '$'
-- Returns only the identifier.
label :: YP ByteString
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


ruleType :: YP RuleType
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
parseMetadatum :: YP Metadatum
parseMetadatum = do
  -- Preceeded by the keyword "meta"
  skipTo $ string "meta:"
  -- First meta
  seekFirstMetadataLn
  sepByMap (pair identifier (Just $ space1 *> eq *> space1) value)  space1
  where
    seekFirstMetadataLn = do
      horizontalSpace
      endOfLine
      spaces
      <?> ""






{-- |
--
--
-- 2.3.9 Anonymous strings
sss :: YP Metadata
sss = do
  skipTo $ string "strings:"
  space1
  sepByMap (pair label value) space1
  where
    aux = do
      dollarSign
      label
      spaces *> eq *> spaces
-}

-- | Parse a regex string -- Text.Regex.TDFA
regex :: YP (ByteString -> ByteString)
regex = do
  -- Opens with a forward slash '/'
  fSlash
  -- Scan source until unescaped forward slash '/' is encountered
  rx <- scan False p
  return $ (rx =~)
  <?> "error building regex map"
  where p s w | s && w /= 47  = Nothing
              | w == 47       = Just True
              | otherwise     = Just False





---------------------- CONDITIONS ---------------------------
-------------------------------------------------------------


-- | 'parseCondition' is the main function that parses a conditional line in a
-- YARA rules file
parseConditions :: YP ConditionalExp
parseConditions = undefined


parseACondition :: YP ConditionalExp
parseACondition = undefined



--- horribly inefficent because if it gets to the  "and" and finds a "r"
-- itll restart from the begining of the parser 
and :: YP ConditionalExp
and = do
  c1 <- condition
  horizontalSpaces
  string "and"
  horizontalSpaces
  c2 <- perhaps condition
  if c2 == Nothing
    then undefined
    else
     return $ And c1 c2

condition :: YP ConditionalExp
condition = do
  b <- peekByte
  if b == 40       -- if '('
    then do
      c <- condition
      cParen
      return c
    else undefined
      --one of the conditions

-- | YARA specification allows offsets to be written in hexadecimal with
-- prefix '0x' (we allow '0X' as well) as its handy when writing
-- virtual addresses.
offset :: YP Word
offset = decimal <|> hexadecimal
{-# INLINE offset #-}


-- | DONE 2.3.1 Counting strings
stringCount :: YP ConditionalExp
stringCount = do
  byte 35          -- For counting occurences of strings, identifiers are
  i <- identifier  -- preceeded by a '#' rather than the normal '$'
  horizontalSpaces
  p <- ordering
  horizontalSpaces
  n <- decimal
  pure $ StringCount i p n
{-# INLINE stringCount #-}


-- | Get the offset or virtual address of the i-th occurrence of string $a
-- by using @a[i]. The indexes are one-based, so the first occurrence would
-- be @a[1] the second one @a[2] and so on. If you provide an index greater
-- then the number of occurrences of the string, the result will be a Nothing.
offsetOf :: YP ConditionalExp
offsetOf =
  liftA2 Offset (identifier <* sqBra <* spaces) (offset <* spaces <* sqKet)
{-# INLINE offsetOf #-}

-- DONE 2.3.2
stringInAt :: YP ConditionalExp
stringInAt = do
  i <- label
  horizontalSpaces
  s <- string "at" <|> string "in"
  horizontalSpaces
  if s == "at"
    then do
      n <- offset
      return $ StringAt i n
    else do
      oParen
      l <- offset
      ellipsis
      -- Remark: YARA spec allows the string "filesize" to indicate
      -- the upper offset as the end of file
      u <- offset -- <|> string "filesize" *> getFilesize
      cParen
      return $ StringIn i l u
{-# INLINE stringInAt #-}



-- 2.3.11 Referencing other rules
-- | 'ruleRef'
-- When writing the conditions for a certain rule, you can also make reference
-- to a rule in a manner that resembles a function invocation
-- of traditional programming languages. In this way you can create rules
-- that depend on others. Let’s see an example:
--
-- rule Rule1 {
--    strings:
--        $a = "dummy1"
--    condition:
--        $a
-- }
-- rule Rule2 {
--    strings:
--        $a = "dummy2"
--    condition:
--        $a and Rule1
-- }
--
-- As can be seen in the example, a file will satisfy Rule2 only if it
-- contains the string “dummy2” and satisfies Rule1. Note that it is strictly
-- necessary to define the rule being invoked before the one that will make
-- the invocation.
ruleRef :: YP ConditionalExp
ruleRef = do
  -- Why '_identifier' instead of 'identifier'?
  -- Need to avoid the check that it is in the strings (its empty anyways).
  i <- _identifier
  r <- getInscopeRules
  if i `Set.member` r
    then pure $ RuleReference i
    else fault $ "Referenced rule is not in scope '" ++ i ++ "'"


-- 2.3.4
-- |
-- Match filesize of file being scanned; size is expressed in bytes.
--
-- rule FileSizeExample
-- {
--    condition:
--        filesize > 200KB
-- }
--
-- Here: the parser doesn't immediately check the condition, true or false.
--
-- 1) parsing of yara rules is pure. so we cannot simply fetch it.
-- 2) it could be included in state? no. if we are scanning several documents,
--    it varies. plus it would mean calculating file size ahead of time with
--    no promise of using it. may be an issue on huge files.
-- 3) but keeping a constructor with two fields is computationally higher than
--    just a bool. Not entirely. Since ti would be a bool contructor wrapper
--    around the value anyways. so its neglegible.
--
-- Note: this is distinct from the "filesize" keyword, which gets replaced with
-- the value of the file-being-scanned's digital size.
--
conditionFilesize :: YP ConditionalExp
conditionFilesize  = do
  string "filesize"
  spaces          -- 0 or more horizontal spaces is OK
  o <- ordering   -- '<' '>' or '=='
  spaces          -- 0 or more horizontal spaces is OK
  s <- decimal    -- integer value
  u <- takeWhile isAlpha  -- Handle the units
  let fac = case toLower u of
        ""   -> 1
        "b"  -> 1
        "kb" -> 1000
        "mb" -> 1000000
        "gb" -> 1000000000
        "tb" -> 1000000000000
        _    -> 0
  if fac > 0
    then return $ FileSize (fac * s) o
    else fault $ "Unrecognized units value for a filesize: '" ++ u ++ "'"
{-# INLINE conditionFilesize #-}


data SetOfStrings
  = AllOfStrings
  | AnyOfStrings
  | OfStrings Word

conditionSetOfStrings :: YP ConditionalExp
conditionSetOfStrings = do
  _ <- string "all" $> All
         <|> string "any" $> Any
         <|> N <$> decimal
  spaces
  string "of"
  spaces
  --_ <- (grouping (label <|> regex) comma)
   --    (string "them") <|>
  fault "" 





allconditions = ruleRel <|> conditionFilesize <|> conditionSetOfStrings
{-
_and :: YP Condition
_and = do
  m <- subCondition
  spaces
  string "and"
  spaces
  n <- subCondition
  return $ AndCon m n

-}












{-
block :: (a -> f a -> f a)
      -> ByteString
      -> YP a
      -> YP (f a)
block s p = do
  string s <* colon
  skipTo $ sepBy p space1


-}


{-
strModifiers :: YP
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
parseRuleBlock :: YP ()
parseRuleBlock = do
  oCurl
  meta <- parseMetadata keep_meta
  ss <- block "strings" patterns
  -- >>= (block "condition:") . conditions
  cCurl
  return $ Seq.singleton () -- Data.Map.empty <?> "Parse Rule Block"
  where


-- HEX

hexPr :: YP HexTokens
hexPr = Seq.singleton . uncurry Pair <$> (hexDigit `pair` hexDigit)
     where hexDigit = satisfy $ \w -> w == 63 || w - 48 <=  9
                              || w - 97 <= 25 || w - 65 <= 25

hexJump :: YP HexTokens
hexJump = between sqBra sqKet $ do
  l <- optional decimal
  flank space dash
  u <- optional decimal
  return $ maybe Seq.empty Seq.singleton $ if
    | isNothing l && isNothing u  -> IJmp 0
    | isNothing l                 -> RJmp 0 <$> u
    | isNothing u                 -> IJmp <$> l
    | otherwise                   -> uncurry RJmp <$> untuple (l,u)

hex :: YP HexStr
hex = between oCurl cCurl $ sepBy1 (hexGrp <|> hexStd) space1
  where
    hexAux = Seq.fromList <$> sepBy1 (hexPr <|> hexJump) space1
    hexStd = Std <$> hexAux
    hexGrp = Grp <$> between oPar cPar (sepBy1 hexAux $ flank space vBar)

-- PARSE YARA STRING

patterns :: YP YaraStr
patterns = do
  l <- label
  skipTo eq
  let regex'  = YReg l <$> regex
      string' = YStr l <$> string
      hex'    = YHex l <$> hex
  skipTo (regex' <|> string' <|> hex') <*> skipTo modifiers
  <?> "patterns"
  where
    -- Using a set here to automatically remove dupicates. Since modifiers as a "set"
    -- data structure will later be consumed in conditional clauses (and not used
    -- futher) they will shortly be dropped

    scan' = liftA2 Set.insert keys ((space1 *> scan') <|> pure Set.empty)
    scan = foldl (|>) empty <$> scan' -- change to a sequence


parseConditions :: YP ()--[(ByteString,Pattern)]->Parser[ByteString->Bool]
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
range :: YP (Word64, Word64)
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
ruleBlock :: YP ByteString
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
