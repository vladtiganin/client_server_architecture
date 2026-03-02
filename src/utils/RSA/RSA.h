#ifndef RSA_H
#define RSA_H

#include <gmpxx.h>
#include <utility>

class RSA {
private:
    void extendedEuclidean(mpz_class& d, const mpz_class& a, const mpz_class& b);
    
public:
    std::pair<mpz_class, mpz_class> public_key;   
    std::pair<mpz_class, mpz_class> private_key;  
    
    void generateKeys();
};

#endif