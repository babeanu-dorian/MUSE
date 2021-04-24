#include "pre/ctxt.h" 

namespace pre {

    std::invalid_argument const Ctxt::INVALID_CTXT_ERROR("Invalid ciphertext.");

    Ctxt::Ctxt(size_t ptxtBitSize, PublicKey const &pk):
        _ptxtBitSize(ptxtBitSize),
        _pk(pk)
    {}

    size_t Ctxt::ptxtBitSize() const {
        return _ptxtBitSize;
    }

    PublicKey const &Ctxt::pk() const {
        return _pk;
    }

    CryptoPP::Integer Ctxt::decrypt(PreScheme const &pre, PublicKey const &pk, SecretKey const &sk) const {
        return this->decryptImpl(pre, pk, sk);
    }
}