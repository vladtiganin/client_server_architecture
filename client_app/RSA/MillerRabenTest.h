#ifndef MILLERRABENTEST_H
#define MILLERRABENTEST_H
#include <gmpxx.h>
#include <string>

void getPrimeValue(mpz_class& p,const int& bc);

void getPrimeValueLB(mpz_class& p,const int& bc, mpz_class& ub);

void getFixedLengthBitValue(const int& bc, mpz_class& p);

bool MRTest(const mpz_class& p, const int k = 40);

#endif 