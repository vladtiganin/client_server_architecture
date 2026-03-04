#ifndef RSA_H
#define RSA_H

#include <gmpxx.h>
#include <utility>
#include <vector>
#include <algorithm>  

class RSA {
private:
    void extendedEuclidean(mpz_class& d, const mpz_class& a, const mpz_class& b);
    
public:
    std::pair<mpz_class, mpz_class> public_key;   
    std::pair<mpz_class, mpz_class> private_key;  
    
    void generateKeys(const int key_size = 1024);

    mpz_class encryptKey(const mpz_class& data);
    mpz_class decryptKey(const mpz_class& data);
    
    mpz_class bytesToMpz(const std::vector<unsigned char>& bytes);
    std::vector<unsigned char> mpzToBytes(const mpz_class& num);
};

#endif