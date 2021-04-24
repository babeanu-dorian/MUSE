#include "muse/client.h"

namespace muse {

    Client::Client(size_t id, size_t searchKeyLength, DataStorageService &ds):
        _id(id),
        _searchKeyLength(searchKeyLength),
        _preKeys(ds.preScheme().keyGen()),
        _ds(ds)
    {}

    pre::PublicKey const &Client::prePk() const {
        return _preKeys.pk();
    }

    void Client::grantAccess(size_t toId, pre::PublicKey const &toPk) {
        _ds.grantAccess(_id, toId, _ds.preScheme().reKeyGen(_preKeys.sk(), toPk));
    }

    void Client::revokeAccess(size_t toId) {
        _ds.revokeAccess(_id, toId);
    }

    void Client::store(std::vector<std::string> const &searchKeys, CryptoPP::Integer const &data) {
        std::vector<SearchKeyCtxt> encryptedKeys;
        encryptedKeys.reserve(searchKeys.size());
        for (auto key : searchKeys) {
            encryptedKeys.emplace_back(encryptSearchKey(key));
        }
        pre::PrimaryCtxt encryptedData(_ds.preScheme().encrypt(data, _preKeys.pk()));
        _ds.store(_id, encryptedKeys, encryptedData);
    }

    std::vector<CryptoPP::Integer> Client::search(std::string const &searchKey) {
        SearchKeyCtxt searchKeyCtxt(encryptSearchKey(searchKey));
        auto encryptedResult(_ds.search(_id, searchKeyCtxt));
        std::vector<CryptoPP::Integer> result;
        result.reserve(encryptedResult.size());
        for (auto &ctxt : encryptedResult) {
            result.push_back(_ds.preScheme().decrypt(*ctxt, _preKeys.pk(), _preKeys.sk()));
        }
        return result;
    }

    SearchKeyCtxt Client::encryptSearchKey(std::string const &ptxt) const {
        std::vector<helib::Ctxt> ctxt;
        std::vector<CryptoPP::byte> ptxtBytes(ptxt.cbegin(), ptxt.cend());
        _ds.hePk().encryptBlocks(ptxtBytes, ctxt);
        return SearchKeyCtxt(ctxt, ptxt.size() % CryptoPP::AES::BLOCKSIZE);
    }
}