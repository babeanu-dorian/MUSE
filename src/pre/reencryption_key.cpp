#include "pre/reencryption_key.h"

namespace pre {
    ReencryptionKey::ReencryptionKey(CryptoPP::Integer const &A, CryptoPP::Integer const &B,
                                     CryptoPP::Integer const &C, CryptoPP::Integer const &R):
        _A(A),
        _B(B),
        _C(C),
        _R(R)
    {}
            
    CryptoPP::Integer const &ReencryptionKey::A() const {
        return _A;
    }

    CryptoPP::Integer const &ReencryptionKey::B() const {
        return _B;
    }
    
    CryptoPP::Integer const &ReencryptionKey::C() const {
        return _C;
    }
    
    CryptoPP::Integer const &ReencryptionKey::R() const {
        return _R;
    }
}
