# RSA Public Key Cryptography

  

This is a program in which the objective is to implement and use public key cryptography to encrypt and decrypt files. There will be a keygen executable which is responsible for creating public and private key files for use in the encrypt and decrypt executables.
  

## Installation

  

Included are the following files:

  

```Files

decrypt.c: Main function for the decrypt program.
encrypt.c: Main function for the encrypt program.
keygen.c: Main function for the keygen program.
numtheory.c: Contains number theory functions such as GCD or prime checking 
numtheory.h: Interface for all necessary number theory functions.
randstate.c: Simple implementation of random state interface for necessary for RSA and number theory.
randstate.h: Interface for initialization and clearing of random state
rsa.c: Contains implementation of RSA interface.
rsa.h: Interface for RSA functions.
```
Make sure each is in the desired installation folder, then simply run 'make' in the terminal. To clean up files afterwards, run 'make clean'.

## Usage

After installation, run './keygen' in the terminal, followed by any of the flags listed below to modify program functionality, but are not necessary. Then run './encrypt' using flags -i (desired infile path), -o (desired outfile path), -n (desired public key, default: rsa.pub). This will encrypt the file which can then only be unlocked using the private key with './decrypt'. Run './decrypt' using flags -i (desired infile path), -o (desired outfile path), -n (desired private key, default: rsa.priv). This will recreate the original file at the specified outfile path.

### Keygen
``` Flags
USAGE
        ./keygen [-h] [-v] [-i iterations] [-n pubkey] [-d privkey] [-s seed] [-b bits]
OPTIONS
        -v      verbose output.
        -h      program usage and help.
        -i iterations       number of Miller-Rabin iterations for testing primes (default: 50).
        -n pubkey      specifies the public key file (default: rsa.pub)
        -d privkey      specifies the private key file (default: rsa.priv)
        -s seed      specifies the random seed for random state (default: time(NULL))
        -b bits      minimum bits for public modulus n (default 256)
```

### Encrypt
``` Flags
USAGE
        ./keygen [-h] [-v] [-i infle] [-o outfile] [-n pubkey]
OPTIONS
        -v      verbose output.
        -h      program usage and help.
        -i infile       input file to encrypt (default: stdin).
        -o outfile       output file to encrypt (default: stdout).
        -n pubkey      file containing the public key (default: rsa.pub).
```
### Decrypt
``` Flags
USAGE
        ./keygen [-h] [-v] [-i infle] [-o outfile] [-n privkey]
OPTIONS
        -v      verbose output.
        -h      program usage and help.
        -i infile       input file to decrypt (default: stdin).
        -o outfile       output file to decrypt (default: stdout).
        -n privkey      file containing the private key (default: rsa.priv).
```
  

## Authored by @RuaTran for Fall 2021 at UCSC.



