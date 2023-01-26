#include "numtheory.h"
#include "randstate.h"
#include "rsa.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define OPTIONS "i:o:n:vh"

int main(int argc, char **argv) {

    FILE *public_key;

    char *infile_path = NULL;
    char *outfile_path = NULL;
    char *public_key_path = "rsa.pub";

    bool verbose = false;
    int opt = 0;

    while ((opt = getopt(argc, argv, OPTIONS)) != -1) {
        switch (opt) {
        case 'i': infile_path = optarg; break;
        case 'o': outfile_path = optarg; break;
        case 'n': public_key_path = optarg; break;
        case 'v': verbose = true; break;
        case 'h':
            printf("SYNOPSIS\n");
            printf("   Encrypts data using RSA encryption.\n");
            printf("   Encrypted data is decrypted by the decrypt program.\n\n");
            printf("USAGE\n");
            printf("   ./encrypt [-hv] [-i infile] [-o outfile] -n pubkey\n\n");
            printf("OPTIONS\n");
            printf("   -h              Display program help and usage.\n");
            printf("   -v              Display verbose program output.\n");
            printf("   -i infile       Input file of data to encrypt (default: stdin).\n");
            printf("   -o outfile      Output file for encrypted data (default: stdout).\n");
            printf("   -n pbfile       Public key file (default: rsa.pub).\n");
            return 0;
        }
    }

    //Get public key
    public_key = fopen(public_key_path, "r");

    if (public_key == NULL) {
        fprintf(stderr, "%s: No such file or directory\n", public_key_path);
        return 0;
    }

    // initialize rsa variables
    char username_str[] = "";
    mpz_t n, e, s, username;
    mpz_inits(n, e, s, username, NULL);

    // using public key file, read in all information to the initialized variables
    rsa_read_pub(n, e, s, username_str, public_key);

    // Change the username to a mpz of base 62
    mpz_set_str(username, username_str, 62);
    if (!rsa_verify(username, s, e, n)) {
        fprintf(stderr, "Unable to verify signature.\n");
        return 0;
    }

    // print verbose stats
    if (verbose) {
        printf("user = %s\n", username_str);
        gmp_printf("s (%zu bits) = %Zd\n", mpz_sizeinbase(s, 2), s);
        gmp_printf("n (%zu bits) = %Zd\n", mpz_sizeinbase(n, 2), n);
        gmp_printf("e (%zu bits) = %Zd\n", mpz_sizeinbase(e, 2), e);
    }

    // Open files
    FILE *infile = infile_path == NULL ? stdin : fopen(infile_path, "r");
    FILE *outfile = outfile_path == NULL ? stdout : fopen(outfile_path, "w");

    if (infile == NULL) {
        fprintf(stderr, "Invalid infile.\n");
        return 0;
    }

    // encrypt files using rsa.c
    rsa_encrypt_file(infile, outfile, n, e); // printing 1
    //close both files
    fclose(infile);
    fclose(outfile);
    //clear the remaining mpz variables
    mpz_clears(s, n, e, username, NULL);

    return 0;
}
