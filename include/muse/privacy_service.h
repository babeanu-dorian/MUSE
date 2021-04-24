#ifndef MUSE_PRIVACY_SERVICE_H
#define MUSE_PRIVACY_SERVICE_H

#include "he_aes_cmac/key_pair.h"

namespace muse {
    class PrivacyService {
        helib::Context const _heContext;
        HeAesCmac::KeyPair const _heKeys;
        std::vector<CryptoPP::byte> const _hashKey;

        public:
            PrivacyService(CryptoPP::RandomNumberGenerator &rng,
                           HeAesCmac::SecurityParams const &heParams);
            PrivacyService(std::vector<CryptoPP::byte> const &hashKey,
                           HeAesCmac::SecurityParams const &heParams);

            HeAesCmac::PublicKey const &hePk() const;
            void computeHash(helib::Ctxt const &input, std::string &output) const;
        
        private:
            static std::vector<CryptoPP::byte> genAesKey(CryptoPP::RandomNumberGenerator &rng);
    };
}

#endif /* !MUSE_PRIVACY_SERVICE_H */