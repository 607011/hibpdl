#ifndef __RESPONSE_PARSER_HPP__
#define __RESPONSE_PARSER_HPP__

#include <algorithm>
#include <array>
#include <string>
#include <string_view>

#include "hash_count.hpp"
#include "util.hpp"

namespace hibp
{
    class response_parser final
    {
        static constexpr char CR = '\r';
        static constexpr char LF = '\n';
        static constexpr char NUL = '\0';
        static constexpr char COLON = ':';

    public:
        explicit response_parser(hash_prefix_t const &prefix)
        {
            std::copy(prefix.begin(), prefix.end(), hex_hash_.begin());
        }

        collection_t const &parse(std::string_view source)
        {
            source_ = source;
            reset();
            while (!eof())
            {
                scan_token();
            }
            return result_;
        }

        collection_t const &result() const
        {
            return result_;
        }

        void reset()
        {
            result_ = collection_t{};
            current_ = 0;
        }

    private:
        std::string_view source_;
        collection_t result_;
        hash_count hash_count_;
        std::array<char, 40> hex_hash_;

        std::size_t current_{0};

        inline bool eof() const
        {
            return current_ >= source_.length();
        }

        inline char advance(size_t const n = 1)
        {
            char const c = source_.at(current_);
            current_ += n;
            return c;
        }

        inline char peek() const
        {
            if (eof())
            {
                return NUL;
            }
            return source_.at(current_);
        }

        static inline bool is_digit(char const c)
        {
            return (c >= '0' && c <= '9');
        }

        static inline bool is_hexdigit(char const c)
        {
            return is_digit(c) || (c >= 'A' && c <= 'F');
        }

        void consume_number()
        {
            std::uint32_t num = 0;
            while (is_digit(peek()))
            {
                num *= 10;
                num += advance() - '0';
            };
            hash_count_.count = num;
        }

        void consume_hash()
        {
            std::size_t i = 5; // starting from 5th hex digit
            while (is_hexdigit(peek()))
            {
                if (i == hex_hash_.size())
                {
                    break;
                }
                char const c = advance();
                hex_hash_[i++] = c;
            };
            assert(i == hex_hash_.size());
            assert(peek() == COLON);
            std::size_t hcidx = 0;
            for (std::size_t i = 0; i < hex_hash_.size(); i += 2)
            {
                std::uint8_t hi_nibble = ::util::hex2nibble(hex_hash_.at(i));
                std::uint8_t lo_nibble = ::util::hex2nibble(hex_hash_.at(i + 1));
                hash_count_.data[hcidx++] = (hi_nibble << 4) | lo_nibble;
            }
            advance();
            consume_number();
        }

        void scan_token()
        {
            char const c = peek();
            switch (c)
            {
            case CR:
                advance();
                break;
            case LF:
                result_.push_back(hash_count_);
                advance();
                break;
            default:
                if (is_hexdigit(c))
                {
                    consume_hash();
                }
                else // e.g. ':'
                {
                    advance();
                }
                break;
            }
        }
    };
}

#endif //  __RESPONSE_PARSER_HPP__
