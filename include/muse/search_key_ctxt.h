#ifndef MUSE_SEARCH_KEY_CTXT_H
#define MUSE_SEARCH_KEY_CTXT_H

#include <vector>

#include "helib/helib.h"

namespace muse {
    class SearchKeyCtxt {
        std::vector<helib::Ctxt> _ctxt;
        bool _padded;

        public:
            SearchKeyCtxt(std::vector<helib::Ctxt> const &ctxt, bool padded);

            std::vector<helib::Ctxt> const &ctxt() const;
            bool isPadded() const;
    };
}

#endif /* !MUSE_SEARCH_KEY_CTXT_H */