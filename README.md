# YARA

<<<<<<< HEAD
The target of the project is to build an implimention the current YARA 3.9.0 specification in Haskell.

## The Original Implimentation

The [yara homepage](https://virustotal.github.io/yara/) contains the orginial implimentation of the author of the yara specification (written in C) as well as a description of the software. One can find the specification document there as well.

## Portablity
=======
Posix [yara homepage](https://virustotal.github.io/yara/) port. 

Home page contains the original implimentations as well as the specification doc. 

>>>>>>> a3def91c4619819f10b5beabd3963a62b63a7878

Currently only testing on macOS and should be portable to POSIX systems. The Windows-specific YARA features/modules will not likely be included; the author doesn't use Windows or have regular access to a system running Windows.

## Code Style/Guidelines

To fill in after the bulk of the code is written. We've not spent time looking at the original C-implimentation souce; the goal is to impliment the YARA spec using the functional programing approach.

## Checklist

Checklist is a working section, in that parts are added/removed continuously while writing. There is a lot of work to do.

Part I) Minimal Working Implimentation (Not Full Spec)
- [ ] Parser basic yara file
  - [ ] Parse Rule Block
    - [X] Type
    - [x] Label
    - [X] Tags
    - [X] Metadata
    - [X] Patterns
    - [ ] Conditions
  - [ ] Handle include/import pragma in parser
  - [ ] Impliment basic built-in modules (that are not Windows specific)
    - [ ] Add handling for modules in parser
    - [ ] Math
    - [ ] Time
    - [ ] Magic
    - [ ] Elf
    - [ ] Hash
- [ ] File Scanning
  - [ ] Verify proper behavior of regex builder and parser
- [ ] Core of Application
  - [ ] Parallel/Concurrent parsing/sorting
  - [ ] Proper error/display

Part II) Full Implimentation & Polish
- [ ] Impliment advanced built-in modules
  - [ ] Cuckoo
  - [ ] Improve module parser
  - [ ] Add support & defined interface for custom Modules
- [ ] Testing Suite
  - [ ] Rule Parser Testing
  - [ ] File Scanning Testing
- [ ] Add Final Spec Features
  - [ ] Expand encoding handling (beyond ASCII)
  - [ ] Ensure multi-platform compatibility
  - [ ] yara-python (* large uninteresting task, may omit.)
- [ ] Optimization/Steamline Code/Everything else
  - [ ] Remove unused code/language extensions
  - [ ] Refactor code
  - [ ] Clean up comments & add needed comments
  - [ ] Scan compressed files (ie. yextend)

<<<<<<< HEAD
## Roadmap

The following list was a "learning roadmap" to teach myself the bread & butter of a professional Haskell programmer. In fact, the project was specifically selected because it would nontrivially required the use of each concept. Many are not Haskell specific (regex) but are listed because of the importance.

- [x] Parser Monads
- [x] CPP and FFF
- [x] Advanced Language Extensions
- [x] Advanced Use of ByteString libraries
- [x] Regular Expressions (Generally)
- [ ] Write binding to an outside (non-Haskell) program
- [ ] Runtime internal parsing of Haskell code
- [ ] Cabal packaging & building
- [ ] Lenses
- [ ] Monad Stacks
- [ ] Thorough Documentation
- [ ] Program Portability
- [ ] GHC Flag Options
- [ ] Code Gen Optimization
- [ ] Automated Testing
=======
## Contributing
>>>>>>> a3def91c4619819f10b5beabd3963a62b63a7878
