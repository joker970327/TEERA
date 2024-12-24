#include <iostream>
#include <ctime>
#include <chrono>
#include <iomanip> // for std::fixed and std::setprecision

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)

inline unsigned long long rdtsc() {
    unsigned int low, high;
    __asm__ volatile ("rdtsc" : "=a" (low), "=d" (high));
    return ((unsigned long long)high << 32) | low;
}

#else

// For other architectures, return 0 or implement alternative time measurements
inline unsigned long long rdtsc() {
   return 0;  // Or consider other mechanisms on non-x86 architectures
}
#endif

#ifdef PAIRING_CP80_TEST
#define MR_PAIRING_CP
#define AES_SECURITY 80
#endif

#ifdef PAIRING_MNT128_TEST
#define MR_PAIRING_MNT
#define AES_SECURITY 128
#endif

#ifdef PAIRING_BN128_TEST
#define MR_PAIRING_BN
#define AES_SECURITY 128
#endif

#ifdef PAIRING_BN192_TEST
#define MR_PAIRING_BN
#define AES_SECURITY 192
#endif

#ifdef PAIRING_KSS192_TEST
#define MR_PAIRING_KSS
#define AES_SECURITY 192
#endif

#ifdef PAIRING_BLS256_TEST
#define MR_PAIRING_BLS
#define AES_SECURITY 256
#endif

#ifndef AES_SECURITY
#define MR_PAIRING_BN
#define AES_SECURITY 128
#endif

#include "pairing_3.h"

void test_pairing(){
    PFC pfc(AES_SECURITY);  // initialise pairing-friendly curve
	miracl* mip=get_mip();

	time_t seed;

    G1 g1;
    G2 g2;

    int cnt = 100;

    auto start_time = std::chrono::high_resolution_clock::now();
    unsigned long long start_cycles = rdtsc();
    
    while(cnt--){
        GT t1=pfc.pairing(g2,g1);
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    unsigned long long end_cycles = rdtsc();

    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    unsigned long long cycles_elapsed = end_cycles - start_cycles;

    // 输出结果
    std::cout << "Function Execution Time:" << std::endl;
    std::cout << "  " << duration.count() << " microseconds" << std::endl;
    std::cout << "  " << static_cast<double>(duration.count()) / 1000.0 << " milliseconds" << std::endl;
    std::cout << "  " << static_cast<double>(duration.count()) / 1000000.0 << " seconds" << std::endl;

    std::cout << "Function Execution Cycles (x86 only):" << std::endl;
    std::cout << "  " << cycles_elapsed << " cycles" << std::endl;
}

int main(){
    test_pairing();
}