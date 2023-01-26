#include "numtheory.h"
#include "randstate.h"

#include <stdlib.h>
#include <math.h>
#include <inttypes.h>
#include <string.h>
#include <gmp.h>
#include <stdbool.h>
#include <stdio.h>

// Creates parts of a new RSA public key: two large primes p and q, their product n, and the public exponent e.
// IN: p (large prime 1), q (large prime 2), n (product of p and q), e (public exponent), nbits(target number of bits), iters (number of Miller-Rabin iterations)
// OUT: p (large prime 1), q (large prime 2), n (product of p and q), e (public exponent)
void rsa_make_pub(mpz_t p, mpz_t q, mpz_t n, mpz_t e, uint64_t nbits, uint64_t iters) {
    // p_bits = random number between range [nbits/4,(3×nbits)/4).
    uint64_t max_bits = 3 * nbits / 4;
    uint64_t min_bits = nbits / 4;
    uint64_t p_bits = rand() % (max_bits + 1 - min_bits) + min_bits;
    // q_bits = remaining bits not used by p_bits
    uint64_t q_bits = nbits - p_bits;

    //create primes of specified bit sizes using 'iters' num Miller-Rabin  iterations
    do {
        make_prime(p, p_bits, iters);
        make_prime(q, q_bits, iters);
        // n = p * q as specified
        mpz_mul(n, p, q);
    } while (mpz_sizeinbase(n, 2) != nbits);
    // initialize temporary variables for totient computation
    mpz_t p_temp, q_temp, totient, divisor;
    mpz_inits(p_temp, q_temp, totient, divisor, NULL);
    //subtract 1 from p and q and calculate totient
    mpz_sub_ui(p_temp, p, 1);
    mpz_sub_ui(q_temp, q, 1);
    mpz_mul(totient, p_temp, q_temp);
    do {
        mpz_urandomb(e, state, nbits);
        gcd(divisor, e, totient);
    } while (mpz_cmp_ui(divisor, 1) != 0); //found coprime of totient (public exponent)

    mpz_clears(p_temp, q_temp, totient, divisor, NULL);
}

// Writes a public RSA key to pbfile.
// IN: n, e, s, username (ordered list of file inputs), pbfile (target file)
// OUT: pbfile (updated target file)
void rsa_write_pub(mpz_t n, mpz_t e, mpz_t s, char username[], FILE *pbfile) {
    gmp_fprintf(pbfile, "%Zx\n", n);
    gmp_fprintf(pbfile, "%Zx\n", e);
    gmp_fprintf(pbfile, "%Zx\n", s);
    gmp_fprintf(pbfile, "%s\n", username);
}

// Read public RSA key from pbfile
// IN: n, e, s, username (ordered list of desired variables in file), pbfile (target file)
// OUT: n, e, s, username (ordered list of desired variables from pbfile)
void rsa_read_pub(mpz_t n, mpz_t e, mpz_t s, char username[], FILE *pbfile) {
    gmp_fscanf(pbfile, "%Zx\n", n);
    gmp_fscanf(pbfile, "%Zx\n", e);
    gmp_fscanf(pbfile, "%Zx\n", s);
    gmp_fscanf(pbfile, "%s\n", username);
    fclose(pbfile);
}

// Creates a new RSA private key d given primes p and q and public exponent e.
// IN: d (output private key), e (public exponent), p q (primes input)
// OUT: d (outputted private key)
void rsa_make_priv(mpz_t d, mpz_t e, mpz_t p, mpz_t q) {
    mpz_t p_temp, q_temp, totient;
    mpz_inits(p_temp, q_temp, totient, NULL);

    mpz_sub_ui(p_temp, p, 1);
    mpz_sub_ui(q_temp, q, 1);
    mpz_mul(totient, p_temp, q_temp);
    mod_inverse(d, e, totient);
    mpz_clears(p_temp, q_temp, totient, NULL);
}

// Writes a private RSA key to pbfile.
// IN: n, d, (ordered list of file inputs), pbfile (target file)
// OUT: pbfile (updated target file)
void rsa_write_priv(mpz_t n, mpz_t d, FILE *pvfile) {
    gmp_fprintf(pvfile, "%Zx\n%Zx\n", n, d);
}

// Read private RSA key from pbfile
// IN: n, d (ordered list of desired variables in file), pbfile (target file)
// OUT: n, d (ordered list of desired variables from pbfile)
void rsa_read_priv(mpz_t n, mpz_t d, FILE *pvfile) {
    gmp_fscanf(pvfile, "%Zx\n%Zx\n", n, d);
    fclose(pvfile);
}

// Encrypts ciphertext c with s E(m) = c = m^e*(mod n).
// IN: c (ciphertext), m(base), e(exponent), n(mod)
// OUT c (encrypted text)
void rsa_encrypt(mpz_t c, mpz_t m, mpz_t e, mpz_t n) {
    pow_mod(c, m, e, n);
}

// Encrypts the contents of infile, writing the encrypted contents to outfile.
// IN: INFILE, OUTFILE (files to be used), n (modulo), e(pub exponent)
// OUT: outfile (encrypted file)
void rsa_encrypt_file(FILE *infile, FILE *outfile, mpz_t n, mpz_t e) {
    size_t log_n = mpz_sizeinbase(n, 2) - 1;
    size_t x = 0;
    uint64_t block_size
        = floor((double) (log_n - 1) / (double) (8)); // calculate block_size (step 1)
    uint8_t *block = (uint8_t *) calloc(
        block_size, sizeof(uint8_t)); // dynamically allocate array of block_size bytes (step 2)
    block[0] = 0xFF; // set zeroth byte (step 3)

    mpz_t m, encrypted;
    mpz_inits(m, encrypted, NULL);

    while ((x = fread(block + 1, sizeof(uint8_t), block_size - 1, infile)) > 0) {
        mpz_import(m, x + 1, 1, sizeof(uint8_t), 1, 0, block);
        rsa_encrypt(encrypted, m, e, n);
        gmp_fprintf(outfile, "%Zx\n", encrypted);
    }
    //free up memory
    mpz_clears(m, encrypted, NULL);
    free(block);
}

// Decrypts ciphertext m with s D(c) = c = c^d*(mod n).$
// IN: m (ciphertext), c(base), d(exponent), n(mod)$
// OUT m (encrypted text)$
void rsa_decrypt(mpz_t m, mpz_t c, mpz_t d, mpz_t n) {
    pow_mod(m, c, d, n);
}

// Decrypts the contents of infile, writing the encrypted contents to outfile.$
// IN: INFILE, OUTFILE (files to be used), n (modulo), d(priv)$
// OUT: outfile (decrypted file)$

void rsa_decrypt_file(FILE *infile, FILE *outfile, mpz_t n, mpz_t d) {
    size_t log_n = mpz_sizeinbase(n, 2) - 1;
    uint64_t block_size
        = floor((double) (log_n - 1) / (double) (8)); // calculate block_size (step 1)
    uint8_t *block = (uint8_t *) calloc(
        block_size, sizeof(uint8_t)); // dynamically allocate array of block_size bytes (step 2)

    mpz_t c, m;
    mpz_inits(c, m, NULL);

    while (gmp_fscanf(infile, "%Zx\n", c) > 0) {
        size_t x = 0;
        rsa_decrypt(m, c, d, n);
        block = (uint8_t *) realloc(block, block_size + mpz_sizeinbase(m, 2));
        mpz_export(block, &x, 1, sizeof(uint8_t), 1, 0, m);
        fwrite(block + 1, sizeof(uint8_t), x - 1, outfile); // account for 0xFF
    }

    //free up memory
    mpz_clears(c, m, NULL);
    free(block);
}

// RSA signing signature s on message m using private key d and public mod n
// IN: s (signature), m(message), d(private key), n(public mod)
// OUT: s (signature)
void rsa_sign(mpz_t s, mpz_t m, mpz_t d, mpz_t n) {
    pow_mod(s, m, d, n);
}

// Performs RSA verification, returning true if signature s is verified and false otherwise.
// IN: m (message), s (signature), e(exponent), n(mod)
// OUT: bool (if the message is properly signed)
bool rsa_verify(mpz_t m, mpz_t s, mpz_t e, mpz_t n) {
    mpz_t fdsa;
    mpz_init(fdsa);
    pow_mod(fdsa, s, e, n);
    if (mpz_cmp(fdsa, m) == 0) {
        mpz_clear(fdsa);
        return true;
    }
    mpz_clear(fdsa);
    return false;
}
