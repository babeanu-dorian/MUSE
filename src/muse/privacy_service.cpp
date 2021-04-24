#include "muse/privacy_service.h"

#include "cryptopp/cmac.h"
#include "cryptopp/aes.h"
#include "cryptopp/filters.h"


namespace muse {

    PrivacyService::PrivacyService(CryptoPP::RandomNumberGenerator &rng,
                                   HeAesCmac::SecurityParams const &heParams):
        _heContext(HeAesCmac::KeyPair::genContext(heParams)),
        _heKeys(HeAesCmac::KeyPair::genKeyPair(_heContext, heParams.hwsk)),
        _hashKey(genAesKey(rng))
    {}

    PrivacyService::PrivacyService(std::vector<CryptoPP::byte> const &hashKey,
                                   HeAesCmac::SecurityParams const &heParams):
        _heContext(HeAesCmac::KeyPair::genContext(heParams)),
        _heKeys(HeAesCmac::KeyPair::genKeyPair(_heContext, heParams.hwsk)),
        _hashKey(hashKey)
    {}

    HeAesCmac::PublicKey const &PrivacyService::hePk() const {
        return _heKeys.pk();
    }

    void PrivacyService::computeHash(helib::Ctxt const &input, std::string &output) const {
        std::vector<CryptoPP::byte> inputPtxt;
        _heKeys.sk().decryptBlock(input, inputPtxt);
        output.clear();
        CryptoPP::CMAC<CryptoPP::AES> cmac(_hashKey.data(), _hashKey.size());
        CryptoPP::VectorSource(inputPtxt, true,
            new CryptoPP::HashFilter(cmac, new CryptoPP::StringSink(output)));
    }

    std::vector<CryptoPP::byte> PrivacyService::genAesKey(CryptoPP::RandomNumberGenerator &rng) {
        std::vector<CryptoPP::byte> key(CryptoPP::AES::DEFAULT_KEYLENGTH);
        rng.GenerateBlock(key.data(), key.size());
        return key;
    }
}