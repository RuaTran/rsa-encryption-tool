#include "numtheory.h"
#include "randstate.h"
#include "rsa.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>

#define OPTIONS "b:i:n:d:s:vh"

int main(int argc, char **argv) {

    FILE *public_key;
    FILE *private_key;
    int opt = 0;

    char *pub_file_path = "rsa.pub";
    char *priv_file_path = "rsa.priv";
    uint64_t bits = 256;
    uint64_t confidence = 50;
    uint64_t seed = time(NULL);

    bool verbose = false;

    while ((opt = getopt(argc, argv, OPTIONS)) != -1) {
        switch (opt) {
        case 'b': bits = atoi(optarg); break;
        case 'i': confidence = atoi(optarg); break;
        case 'n': pub_file_path = optarg; break;
        case 'd': priv_file_path = optarg; break;
        case 's': seed = atoi(optarg); break;
        case 'v': verbose = true; break;
        case 'h':
            printf("SYNOPSIS\n");
            printf("   Generates an RSA public/private key pair.\n\n");
            printf("USAGE\n");
            printf("   ./keygen [-hv] [-b bits] -n pbfile -d pvfile\n\n");
            printf("OPTIONS\n");
            printf("   -h              Display program help and usage.\n");
            printf("   -v              Display verbose program output.\n");
            printf("   -b bits         Minimum bits needed for public key n (default: 256).\n");
            printf(
                "   -i confidence   Miller-Rabin iterations for testing primes (default: 50).\n");
            printf("   -n pbfile       Public key file (default: rsa.pub).\n");
            printf("   -d pvfile       Private key file (default: rsa.priv).\n");
            printf("   -s seed         Random seed for testing.\n");
            return 0;
        }
    }

    //Open public key and private key files
    public_key = fopen(pub_file_path, "w+");
    if (public_key == NULL) {
        fprintf(stderr, "Invalid public key.\n");
        return 0;
    }
    private_key = fopen(priv_file_path, "w+");
    if (private_key == NULL) {
        fprintf(stderr, "Invalid private key.\n");
        return 0;
    }

    //make sure private key file permissions are set to 0600
    int privfd = fileno(private_key);
    fchmod(privfd, S_IRUSR | S_IWUSR);

    // Initialize random state
    randstate_init(seed);
    srand(seed);

    // Make public and private keys
    mpz_t n, e, p, q, d, m, s, d_temp;
    mpz_inits(n, e, p, q, d, m, s, d_temp, NULL);
    rsa_make_pub(p, q, n, e, bits, confidence);
    rsa_make_priv(d, e, p, q);

    mpz_set(d_temp, d);

    // Get username
    char *username = strdup(getenv("USER"));
    mpz_set_str(m, username, 62); //set username of size 62
    rsa_sign(s, m, d, n);

    //write to public and private key files respectively

    rsa_write_pub(n, e, s, username, public_key);
    rsa_write_priv(n, d_temp, private_key);

    // print verbose stats
    if (verbose) {
        printf("user = %s\n", username);
        gmp_printf("s (%zu bits) = %Zd\n", mpz_sizeinbase(s, 2), s);
        gmp_printf("s (%zu bits) = %Zd\n", mpz_sizeinbase(s, 2), p);
        gmp_printf("s (%zu bits) = %Zd\n", mpz_sizeinbase(s, 2), q);
        gmp_printf("n (%zu bits) = %Zd\n", mpz_sizeinbase(n, 2), n);
        gmp_printf("e (%zu bits) = %Zd\n", mpz_sizeinbase(e, 2), e);
        gmp_printf("s (%zu bits) = %Zd\n", mpz_sizeinbase(s, 2), d);
    }

    //close both files
    fclose(public_key);
    fclose(private_key);

    //clear the remaining mpz variables
    randstate_clear();
    mpz_clears(n, e, p, q, d, m, s, d_temp, NULL);
    free(username);
    username = NULL;
    return 0;
}
