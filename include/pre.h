#ifndef PRE_H
#define PRE_H

#include <cstdint>
#include <iostream>
#include <iterator>
#include <vector>

#include "NTL/ZZ.h"

typedef bool bit;

namespace pre {

    struct PublicKey {
        NTL::ZZ N;
        NTL::ZZ g0;
        NTL::ZZ g1;
        NTL::ZZ g2;
    };

    struct SecretKey {
        NTL::ZZ p;
        NTL::ZZ q;
        NTL::ZZ a;
        NTL::ZZ b;
    };

    struct KeyPair {
        PublicKey pk;
        SecretKey sk;
    };

    struct ReEncryptionKey {
        NTL::ZZ A;
        NTL::ZZ B;
        std::vector<bit> C;
        NTL::ZZ R;
    };

    struct Ctxt {
        bool isReEncrypted;
        NTL::ZZ A1;
        NTL::ZZ A2;
        NTL::ZZ A3;
        NTL::ZZ B1;
        NTL::ZZ B2;
        std::vector<bit> C1;
        std::vector<bit> C2;
        NTL::ZZ D;
        std::vector<bit> c;
        NTL::ZZ s;
    };

    class PreScheme {
        size_t const _n;
        size_t const _k1;
        size_t const _k2;

        NTL::ZZ random(NTL::ZZ const &top);
        std::vector<bit> hash(std::vector<bit> const &input, size_t length);

        public:
            PreScheme(size_t n, size_t k1, size_t k2);
            KeyPair keyGen();
            ReEncryptionKey reKeyGen(SecretKey const &skx, PublicKey const &pky);
            Ctxt encrypt(std::vector<bit> const &m, PublicKey const &pk);
            Ctxt reencrypt(Ctxt const &ctxt, PublicKey const &pk, ReEncryptionKey const &rk);
            std::vector<bit> decrypt(Ctxt const &ctxt, PublicKey const &pk, SecretKey const &sk);
    };
}

#endif /* !PRE_H */