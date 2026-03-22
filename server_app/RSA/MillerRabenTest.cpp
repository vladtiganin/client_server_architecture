#include "MillerRabenTest.h"
#include <ctime>

static gmp_randclass rng(gmp_randinit_default);
static bool seeded = false;

void getPrimeValue(mpz_class& p, const int& bc){
    do{
        getFixedLengthBitValue(bc, p);
    }while(!MRTest(p));
};

void getPrimeValueLB(mpz_class& p,const int& bc, mpz_class& ub){
    do{
        getFixedLengthBitValue(bc - 32, p);
    }while(ub < p || !MRTest(p));
};

void getFixedLengthBitValue(const int& bc, mpz_class& p) {
    if (!seeded) {
        rng.seed(time(nullptr));
        seeded = true;
    }
    
    p = rng.get_z_bits(bc);
    p |= (mpz_class(1) << (bc - 1));  
    p |= 1;
}

bool MRTest(const mpz_class& p, const int k) {
    if (p < 2) return false;
    if (p == 2 || p == 3) return true;
    if (p % 2 == 0) return false;
    
    mpz_class s = 0;
    mpz_class t = p - 1;
    
    while (t % 2 == 0) {
        t /= 2;
        s += 1;
    }

    if (!seeded) {
        rng.seed(time(nullptr));
        seeded = true;
    }
    
    for (int i = 0; i < k; ++i) {
        mpz_class a;
        mpz_class range = p - 4;
        a = rng.get_z_range(range) + 2;

        mpz_class x;
        mpz_powm(x.get_mpz_t(), a.get_mpz_t(), t.get_mpz_t(), p.get_mpz_t());

        if(x == 1 || x == p - 1) continue;
        
        bool composite = true;
        for(mpz_class j = 0; j < s - 1; ++j){
            mpz_powm_ui(x.get_mpz_t(), x.get_mpz_t(), 2, p.get_mpz_t());

            if(x == p - 1){
                composite = false;
                break;
            }
        }

        if(composite) return false;
    }

    return true;
}