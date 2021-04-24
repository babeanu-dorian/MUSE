#ifndef PRE_SCHEME_H
#define PRE_SCHEME_H

#include <vector>

#include "cryptopp/integer.h"
#include "cryptopp/osrng.h"

namespace pre {

    class KeyPair;
    class PublicKey;
    class SecretKey;
    class ReencryptionKey;
    class Ctxt;
    class PrimaryCtxt;
    class ReencryptedCtxt;

    class PreScheme {

        friend class PrimaryCtxt;
        friend class ReencryptedCtxt;

        static CryptoPP::Integer hash(CryptoPP::Integer const &input, size_t bitSize);
        static CryptoPP::Integer hash(CryptoPP::Integer const &input, CryptoPP::Integer const &top);
        static CryptoPP::Integer integerConcat(std::vector<CryptoPP::Integer> args);
        static CryptoPP::Integer generateSafePrime(CryptoPP::AutoSeededRandomPool &rng, size_t bitSize);

        CryptoPP::AutoSeededRandomPool _rng;
        size_t const _k1;
        size_t const _k2;
        size_t const _kp;

        public:
            PreScheme(size_t k1, size_t k2, size_t kp);

            KeyPair keyGen();
            ReencryptionKey reKeyGen(SecretKey const &skx, PublicKey const &pky);
            PrimaryCtxt encrypt(CryptoPP::Integer const &m, PublicKey const &pk);
            ReencryptedCtxt reencrypt(PrimaryCtxt const &ctxt, ReencryptionKey const &rk);
            CryptoPP::Integer decrypt(Ctxt const &ctxt, PublicKey const &pk, SecretKey const &sk);
    };
}

#endif /* !PRE_SCHEME_H */