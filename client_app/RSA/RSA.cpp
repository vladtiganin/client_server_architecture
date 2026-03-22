#include "RSA.h"
#include <gmpxx.h>
#include "MillerRabenTest.h"
#include <string>

void RSA::generateKeys(const int key_size){
    mpz_class p = 0;
    getPrimeValue(p, key_size);

    mpz_class q = 0;
    do{
        getPrimeValue(q, key_size);
    }while(p == q);

    mpz_class N = p * q;
    mpz_class Aliler_N = (p-1)*(q-1);

    mpz_class e;
    mpz_class gcd_result;
    mpz_gcd(gcd_result.get_mpz_t(), e.get_mpz_t(), Aliler_N.get_mpz_t());
    if (gcd_result != 1) {
        getPrimeValueLB(e, key_size, Aliler_N);
    }



    mpz_class d;
    extendedEuclidean(d, Aliler_N, e);

    public_key = {e, N};
    private_key = {d, N};
}


void RSA::extendedEuclidean(mpz_class& d, const mpz_class& AN, const mpz_class& e){
    mpz_class a = AN;  
    mpz_class b = e;   
    
    mpz_class x0 = 1, x1 = 0;  
    mpz_class y0 = 0, y1 = 1;  
    mpz_class temp_a, temp_b;
    mpz_class temp_x, temp_y;

    while (b != 0) {
        mpz_class q = a / b;  
        
        temp_a = b;
        temp_b = a % b;
        
        temp_x = x1;
        temp_y = y1;
        
        x1 = x0 - q * x1;
        y1 = y0 - q * y1;
        

        a = temp_a;
        b = temp_b;
        
        x0 = temp_x;
        y0 = temp_y;
            
    }
    // d = (y0 % e + e) % e; 
    d = (y0 % AN + AN) % AN; 
}


mpz_class RSA::encryptKey(const mpz_class& data){
    if (data >= public_key.second){
        throw std::runtime_error("Encrypting data is too large for RSA modulus");
    }

    mpz_class result;
    mpz_powm(result.get_mpz_t(), data.get_mpz_t(), public_key.first.get_mpz_t(), public_key.second.get_mpz_t());
    return result; 
}

mpz_class RSA::decryptKey(const mpz_class& data) {
    mpz_class result;
    mpz_powm(result.get_mpz_t(), 
             data.get_mpz_t(), 
             private_key.first.get_mpz_t(), 
             private_key.second.get_mpz_t());
    return result;
}


mpz_class RSA::bytesToMpz(const std::vector<unsigned char>& bytes) {
    mpz_class result = 0;
    for (unsigned char byte : bytes) {
        result = (result << 8) | byte;
    }
    return result;
}

std::vector<unsigned char> RSA::mpzToBytes(const mpz_class& num) {
    if (num == 0) return {0};
    
    std::vector<unsigned char> result;
    mpz_class temp = num;
    
    while (temp > 0) {
        unsigned char byte = mpz_class(temp & 0xFF).get_ui();
        result.push_back(byte);
        temp >>= 8;
    }
    
    std::reverse(result.begin(), result.end());
    
    return result;
}