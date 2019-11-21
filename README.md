# yarah

The [yara homepage](https://virustotal.github.io/yara/) contains the mainstream implimentation of the yara specification (written in C) as well as the spec document itself.

## Coding Guide Lines

The coding style should generally follow the

## Checklist

Checklist is a working section, in that parts are added/removed continuously while writing.


- [ ] Parser yara file
  - [ ] Parse Rule Block
    - [X] Type
    - [X] Label
    - [X] Tags
    - [X] Metadata
    - [X] Patterns
    - [ ] Conditions
  - [ ] Handle Include/Import Pragam
  - [ ] Impliment built in modules (that are not Windows specific)
    - [ ] Math
    - [ ] Time
    - [ ] Magic
    - [ ] Elf 
    - [ ] Hash
    - [ ] Cuckoo
- [ ] File Scanner
- [ ] Core of Application
  - [ ] Parallel/Concurrent parsing/sorting
  - [ ] Proper error/display
- [ ] Testing Suite
  - [ ] Rule Parser Testing
  - [ ] File Scanning Testing
- [ ] Add Final Spec Features
  - [ ] Custom Modules
  - [ ] Impliment Windows Modules
  - [ ] Expand encoding handling (beyond ASCII)
  - [ ] Ensure multi-platform compatibility
  - [ ] yara-python
- [ ] Optimization/Steamline Code/Everything else
  - [ ] Remove unused code/language extensions
  - [ ] Refactor code
  - [ ] Clean up comments & add needed comments
  - [ ] Scan compressed files (ie. yextend)


## Language Extensions

These following languages are all standard and turned on universally in the code base.
- MultiParamTypeClasses
- PolyKinds
- RankNTypes
- InstanceSigs
- DeriveTraversable
- DeriveFoldable
- QuasiQuotes
- TemplateHaskell
- ScopedTypeVariables
- StandaloneDeriving
- ViewPatterns
- TypeSynonymInstances
- ConstraintKinds
- MultiWayIf
- LambdaCase
- TypeFamilies
- PatternSynonyms
- PatternGuards
- DataKinds
- GADTs
- TypeOperators
- KindSignatures
- FlexibleInstances
- FlexibleContexts
- FunctionalDependencies
- DeriveGeneric
- DeriveFunctor
- BangPatterns
- OverloadedLists
- NoImplicitPrelude
- OverloadedStrings
- TupleSections
- UnboxedTuples
- UnboxedSums
- GeneralizedNewtypeDeriving
- ApplicativeDo
- DeriveAnyClass
- DeriveLift

It is a hastle during development to constantly turn these on and off as needed. 

