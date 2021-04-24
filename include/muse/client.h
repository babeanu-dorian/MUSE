#ifndef MUSE_CLIENT_H
#define MUSE_CLIENT_H

#include <vector>
#include <string>
#include <stdexcept>

#include "muse/data_storage_service.h"
#include "pre/key_pair.h"

namespace muse {
    class Client {
        size_t const _id;
        size_t const _searchKeyLength;
        pre::KeyPair const _preKeys;
        DataStorageService &_ds;

        public:
            Client(size_t id, size_t searchKeyLength, DataStorageService &ds);

            pre::PublicKey const &prePk() const;

            void grantAccess(size_t toId, pre::PublicKey const &toPk);
            void revokeAccess(size_t toId);

            void store(std::vector<std::string> const &searchKeys, CryptoPP::Integer const &data);
            std::vector<CryptoPP::Integer> search(std::string const &searchKey);
        
        private:
            SearchKeyCtxt encryptSearchKey(std::string const &ptxt) const;
    };
}

#endif /* !MUSE_CLIENT_H */