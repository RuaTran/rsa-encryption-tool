#include "randstate.h"
#include "numtheory.h"
//

//Computes the greatest common divisor of a and b, storing the value of the computed divisor in d
// IN: a, b (dividents), d (divisor)
// OUT: d (divisor)
void gcd(mpz_t d, mpz_t a, mpz_t b) {
    //create temp mpz variables so as not to modify d, a, or b
    mpz_t a_temp, b_temp, temp;
    mpz_inits(a_temp, b_temp, temp, NULL);

    mpz_set(a_temp, a);
    mpz_set(b_temp, b);

    while (mpz_cmp_ui(b_temp, 0) != 0) { //step 1
        mpz_set(temp, b_temp); //step 2
        mpz_mod(b_temp, a_temp, b_temp); //step 3
        mpz_set(a_temp, temp); //step 4
    }

    mpz_set(d, a_temp); //step 5
    //free mpz variables
    mpz_clears(a_temp, b_temp, temp, NULL);
}

// Computes the inverse i of a modulo n. In the event that a modular inverse cannot be found, set i to 0.
// IN: i (inverse) of  a (mod left side) and b (mod right side)
// OUT: i (inverse)
void mod_inverse(mpz_t i, mpz_t a, mpz_t n) {
    mpz_t r, r_prime, t, t_prime, q;
    mpz_inits(r, r_prime, t, t_prime, q, NULL);
    mpz_set(r, n); //step 1
    mpz_set(r_prime, a);
    mpz_set_ui(t, 0); //step 2
    mpz_set_ui(t_prime, 1);
    while (mpz_cmp_ui(r_prime, 0) != 0) { // step 3
        mpz_fdiv_q(q, r, r_prime); //step 4

        mpz_t r_temp, r_prime_temp, t_temp, t_prime_temp;
        mpz_inits(r_temp, r_prime_temp, t_temp, t_prime_temp, NULL);

        mpz_set(r_temp, r_prime);
        mpz_mul(r_prime_temp, q, r_prime);
        mpz_sub(r_prime_temp, r, r_prime_temp);
        mpz_set(r, r_temp);
        mpz_set(r_prime, r_prime_temp);

        mpz_set(t_temp, t_prime);
        mpz_mul(t_prime_temp, q, t_prime);
        mpz_sub(t_prime_temp, t, t_prime_temp);
        mpz_set(t, t_temp);
        mpz_set(t_prime, t_prime_temp);
        mpz_clears(r_temp, r_prime_temp, t_temp, t_prime_temp, NULL);
    }

    if (mpz_cmp_ui(r, 1) > 0) {
        mpz_set_ui(i, 0);
        mpz_clears(r, r_prime, t, t_prime, q, NULL);
        return;
    }

    if (mpz_cmp_ui(t, 0) < 0) {
        mpz_add(t, t, n);
    }

    mpz_set(i, t);
    mpz_clears(r, r_prime, t, t_prime, q, NULL);
}

// First* function that performs fast modular exponentiation, computing base raised to the exponent power modulo modulus, and storing the computed result in out.
// IN: out (output), base (number raised), exponent (base raised to this power), modulus (base mod)
// OUT: out (output of modular exponentiation)
// * two seperate functions, as this one causes keygen.c to enter an infinite loop, but works with encrypt and decrypt (does not modify exponent)
void pow_mod(mpz_t out, mpz_t base, mpz_t exponent, mpz_t modulus) {
    mpz_t v, p, temp_exponent;
    mpz_inits(v, p, temp_exponent, NULL);

    mpz_set(temp_exponent, exponent);
    mpz_set_ui(v, 1); // step 1
    mpz_set(p, base); //step 2
    while (mpz_cmp_ui(temp_exponent, 0) > 0) { //step 3
        if (mpz_odd_p(temp_exponent) > 0 != 0) { //step 4
            mpz_mul(v, v, p); //step 5
            mpz_mod(v, v, modulus);
        }
        mpz_mul(p, p, p); //step 6
        mpz_mod(p, p, modulus);

        mpz_fdiv_q_ui(temp_exponent, temp_exponent, 2); // step 7
    }
    mpz_set(out, v); //step 8
    mpz_clears(v, p, temp_exponent, NULL);
}

// Second* function that performs fast modular exponentiation, computing base raised to the exponent power modulo modulus,and storing the computed result in out.
// IN: out (output), base (number raised), exponent (base raised to this power), modulus (base mod)
// OUT: out (output of modular exponentiation)
// * two seperate functions, as this one breaks encrypt and decrypt (naturally), but allows keygen.c to run somehow (DOES modify exponent)
void pow_mod2(mpz_t out, mpz_t base, mpz_t exponent, mpz_t modulus) {
    mpz_t v, p, temp_exponent;
    mpz_inits(v, p, temp_exponent, NULL);

    mpz_set(temp_exponent, exponent);
    mpz_set_ui(v, 1); // step 1
    mpz_set(p, base); //step 2
    while (mpz_cmp_ui(exponent, 0) > 0) { //step 3
        if (mpz_odd_p(exponent) != 0) { //step 4
            mpz_mul(v, v, p); //step 5
            mpz_mod(v, v, modulus);
        }
        mpz_mul(p, p, p); //step 6
        mpz_mod(p, p, modulus);

        mpz_div_ui(exponent, exponent, 2); // step 7
    }
    mpz_set(out, v); //step 8
    mpz_clears(v, p, temp_exponent, NULL);
}

// Conducts the Miller-Rabin primality test to indicate whether or not n is prime using iters number of Miller-Rabin iterations.
// IN: n (number to test), iters (number of Miller-Rabin iterations to test)
// OUT: bool (whether or not the number in question is prime (generally))
bool is_prime(mpz_t n, uint64_t iters) {
    //2 is the only non-odd prime.
    if (mpz_cmp_ui(n, 2) == 0) {
        return true;
    }
    //check if the number is divisible by 2 before step 1, if it's divisible by 2 then it's certainly not prime.
    mpz_t temp;
    mpz_init(temp);
    mpz_mod_ui(temp, n, 2);
    if (mpz_cmp_ui(temp, 0) == 0 || (mpz_cmp_ui(n, 1) <= 0)) {
        mpz_clear(temp);
        return false;
    }
    mpz_clear(temp);

    mpz_t s, sfrac, r, base, mod_temp;
    mpz_inits(s, sfrac, r, base, mod_temp, NULL);
    mpz_sub_ui(base, n, 1);
    mpz_set_ui(sfrac, 2);
    mpz_set_ui(s, 1);

    mpz_div(r, base, sfrac);
    mpz_mod_ui(mod_temp, r, 2);

    while (mpz_cmp_ui(mod_temp, 0) == 0) {
        mpz_mul_ui(sfrac, sfrac, 2);
        mpz_add_ui(s, s, 1);
        mpz_div(r, base, sfrac);
        mpz_mod_ui(mod_temp, r, 2);
    }
    //1
    mpz_clears(sfrac, base, mod_temp, NULL);

    for (uint32_t i = 0; i < iters; i++) { //2

        // 3
        mpz_t a, y;
        mpz_inits(a, y, NULL);
        //printf("aa\n"); infinite loop from pow_mod
        do {
            mpz_urandomm(a, state, n);
        } while (mpz_cmp_ui(a, 2) < 0 || mpz_cmp(a, n) > 0);

        pow_mod2(y, a, r, n); //4

        if (mpz_cmp_ui(y, 1) != 0 && mpz_cmp_ui(y, mpz_get_ui(n) - 1) != 0) { //5
            mpz_t j;
            mpz_init(j);
            mpz_set_ui(j, 1); //6

            while (mpz_cmp_ui(j, mpz_get_ui(s) - 1) <= 0
                   && mpz_cmp_ui(y, mpz_get_ui(n) - 1) != 0) { //7
                mpz_t
                    two_temp; // must create temporary mpz variable two, as pow_mod takes in mpz_t, not uint
                mpz_init(two_temp);
                mpz_set_ui(two_temp, 2);
                pow_mod2(y, y, two_temp, n); //8
                mpz_clear(two_temp);
                if (mpz_cmp_ui(y, 1) == 0) { //9
                    mpz_clears(s, r, a, y, j, NULL);
                    return false; //10
                }
                mpz_add_ui(j, j, 1); //11
            }
            if (mpz_cmp_ui(y, mpz_get_ui(n) - 1) != 0) { // 12
                mpz_clears(s, r, a, y, j, NULL);
                return false; //13
            }
            mpz_clear(j);
        }
        mpz_clears(a, y, NULL);
    }
    mpz_clears(s, r, NULL);
    return true;
}

// Generates a new prime number stored in p of at least 'bits' bits, using iters for prime testing
// IN: p (prime stored), bits (min number of bits of prime generated), iters (num Miller-Rabin iterations)
// OUT: p (new prime)
void make_prime(mpz_t p, uint64_t bits, uint64_t iters) {
    mpz_t randomNum;
    mpz_init(randomNum);
    mpz_urandomb(randomNum, state, bits);

    while (is_prime(randomNum, iters) == false) {
        mpz_urandomb(randomNum, state, bits);
    }
    mpz_set(p, randomNum);
    mpz_clear(randomNum);
    return;
}
