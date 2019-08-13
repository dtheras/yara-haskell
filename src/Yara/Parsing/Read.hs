{-
this is just to test streaming for now.
evalutating verse pipes vse conduit


probably pipes


https://github.com/fpco/inline-c/tree/master/inline-c

https://hackage.haskell.org/package/word8
https://github.com/fpco/store
https://hackage.haskell.org/package/pipes-parse
https://hackage.haskell.org/package/pipes-attoparsec-0.5.1.5/docs/Pipes-Attoparsec.html
https://hackage.haskell.org/package/pipes-bytestring-2.1.6/docs/Pipes-ByteString.html
https://hackage.haskell.org/package/hierarchy-1.0.2/docs/Hierarchy.html



https://hackage.haskell.org/package/Glob-0.9.2/docs/System-FilePath-Glob.html
-}
-- {-# OPTIONS_GHC -fno-warn-unused-imports #-}
{-# OPTIONS_GHC -fwarn-unused-imports #-}
module Read where

import Parser
import Types
import Utilities




-- | Convert our 'YP' to a @pipes-parse@
-- 'Pipes.Parser'.
--
-- This 'Pipes.Parser' is compatible with the tools from "Pipes.Parse".
--
-- It returns 'Nothing' if the underlying 'Producer' is exhausted, otherwise
-- it attempts to run the given attoparsec 'Attoparsec.Parser' on the underlying
-- 'Producer', possibly failing with 'ParsingError'.
parse
  :: (Monad m, ParserInput a)
  => Attoparsec.Parser a b                            -- ^ Attoparsec parser
  -> Pipes.Parser a m (Maybe (Either ParsingError b)) -- ^ Pipes parser
parse parser = S.StateT $ \p0 -> do
    x <- nextSkipEmpty p0
    case x of
      Left r       -> return (Nothing, return r)
      Right (a,p1) -> step (yield a >>) (_parse parser a) p1
  where
    step diffP res p0 = case res of
      Fail _ c m -> return (Just (Left (ParsingError c m)), diffP p0)
      Done a b   -> return (Just (Right b), yield a >> p0)
      Partial k  -> do
        x <- nextSkipEmpty p0
        case x of
          Left e -> step diffP (k mempty) (return e)
          Right (a,p1) -> step (diffP . (yield a >>)) (k a) p1
{-# INLINABLE parse #-}









{----
FreeT

pipes ---- way to insert boundaies in a stream. so like a stream of files. 



-----}

----run :: Configuration -> Logger -> Rules a -> IO (ExitCode, RuleSet)



-- | Type that allows matching on identifiers
data Pattern
    = Everything
    | Complement Pattern
    | And Pattern Pattern
    | Glob [GlobComponent]
    | List (Set Identifier)
    | Regex String
    | Version (Maybe String)
    deriving (Show)

#if MIN_VERSION_base(4,9,0)
instance Semigroup Pattern where
    (<>) = And

instance Monoid Pattern where
    mempty  = Everything
    mappend = (<>)
#else
instance Monoid Pattern where
    mempty  = Everything
    mappend = And
#endif
