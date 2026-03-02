#include "RSA.h"
#include <gmpxx.h>
#include "MillerRabenTest.h"
#include <string>

void RSA::generateKeys(){
    mpz_class p = 0;
    getPrimeValue(p, 1024);

    mpz_class q = 0;
    do{
        getPrimeValue(q, 1024);
    }while(p == q);

    mpz_class N = p * q;
    mpz_class Aliler_N = (p-1)*(q-1);

    mpz_class e;
    getPrimeValueLB(e, 1024, Aliler_N);


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
            
        d = (y0 % e + e) % e;  
    }
}
