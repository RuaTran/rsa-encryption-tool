#include "numtheory.h"
#include "randstate.h"
#include "rsa.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define OPTIONS "i:o:n:vh"

int main(int argc, char **argv) {

    FILE *private_key;

    char *infile_path = NULL;
    char *outfile_path = NULL;
    char *private_key_path = "rsa.priv";

    bool verbose = false;
    int opt = 0;

    while ((opt = getopt(argc, argv, OPTIONS)) != -1) {
        switch (opt) {
        case 'i': infile_path = optarg; break;
        case 'o': outfile_path = optarg; break;
        case 'n': private_key_path = optarg; break;
        case 'v': verbose = true; break;
        case 'h':
            printf("SYNOPSIS\n");
            printf("   Decrypts data using RSA decryption.\n");
            printf("   Encrypted data is encrypted by the encrypt program.\n\n");
            printf("USAGE\n");
            printf("   ./decrypt [-hv] [-i infile] [-o outfile] -n privkey\n\n");
            printf("OPTIONS\n");
            printf("   -h              Display program help and usage.\n");
            printf("   -v              Display verbose program output.\n");
            printf("   -i infile       Input file of data to decrypt (default: stdin).\n");
            printf("   -o outfile      Output file for decrypted data (default: stdout).\n");
            printf("   -n pbfile       Private key file (default: rsa.priv).\n");
            return 0;
        }
    }

    //Get private key
    private_key = fopen(private_key_path, "r");

    if (private_key == NULL) {
        fprintf(stderr, "%s: No such file or directory\n", private_key_path);
        return 0;
    }

    // initialize rsa variables
    mpz_t n, d;
    mpz_inits(n, d, NULL);

    // using private key file, read in all information to the initialized variables
    rsa_read_priv(d, n, private_key);

    // print verbose stats
    if (verbose) {
        gmp_printf("s (%zu bits) = %Zd\n", mpz_sizeinbase(n, 2), n);
        gmp_printf("n (%zu bits) = %Zd\n", mpz_sizeinbase(d, 2), d);
    }

    // Open files
    FILE *infile = infile_path == NULL ? stdin : fopen(infile_path, "r");
    FILE *outfile = outfile_path == NULL ? stdout : fopen(outfile_path, "w");

    if (infile == NULL) {
        fprintf(stderr, "Invalid infile.\n");
        return 0;
    }

    // encrypt files using rsa.c
    rsa_decrypt_file(infile, outfile, d, n);

    //close both files
    fclose(infile);
    fclose(outfile);

    //clear the remaining mpz variables
    mpz_clears(n, d, NULL);

    return 0;
}
