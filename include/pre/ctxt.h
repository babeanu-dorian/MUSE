#ifndef PRE_CTXT_H
#define PRE_CTXT_H

#include <stdexcept>

#include "cryptopp/integer.h"

#include "pre/public_key.h"

namespace pre {
    class PreScheme;
    class PublicKey;
    class SecretKey;

    class Ctxt {

        size_t const _ptxtBitSize;
        PublicKey const _pk;

        protected:
            static std::invalid_argument const INVALID_CTXT_ERROR;

        public:
            Ctxt(size_t ptxtBitSize, PublicKey const &pk);

            size_t ptxtBitSize() const;
            PublicKey const &pk() const;

            virtual ~Ctxt() = default;
            CryptoPP::Integer decrypt(PreScheme const &pre, PublicKey const &pk, SecretKey const &sk) const;

        private:
            virtual CryptoPP::Integer decryptImpl(PreScheme const &pre, PublicKey const &pk, SecretKey const &sk) const = 0;
    };
}

#endif /* !PRE_CTXT_H */