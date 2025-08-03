
#include "crypto_guard_ctx.h"

#include <boost/scope_exit.hpp>
#include <istream>
#include <openssl/evp.h>

namespace CryptoGuard {

struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    int encrypt;                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};

class CryptoGuardCtx::Impl {

    using EVP_CIPHER_CTX_Guard = std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX* ctx) { EVP_CIPHER_CTX_free(ctx); })>;
    using EVP_MD_CTX_Guard = std::unique_ptr<EVP_MD_CTX, decltype([](EVP_MD_CTX* ctx) { EVP_MD_CTX_free(ctx); })>;

public:
    Impl() {
        OpenSSL_add_all_algorithms();
    }

    ~Impl() {
        EVP_cleanup();
    }

    Impl(const Impl&) = delete;
    Impl& operator=(const Impl &) = delete;
    Impl(Impl &&) noexcept = default;
    Impl& operator=(Impl &&) noexcept = delete;

    void encryptFile(std::iostream& inStream, std::iostream& outStream, std::string_view password) {
        AesCipherParams params = CreateChiperParamsFromPassword(password);
        params.encrypt = 1; // 1-шифрование, 0-дешифровка
        doCrypt(inStream, outStream, params);
    }

    void deryptFile(std::iostream& inStream, std::iostream& outStream, std::string_view password) {
        AesCipherParams params = CreateChiperParamsFromPassword(password);
        params.encrypt = 0;
        doCrypt(inStream, outStream, params);
    }

    std::string calculateChecksum(std::iostream& inStream) const {
        return "NOT IMPLEMENTED";
    }

private:

    AesCipherParams CreateChiperParamsFromPassword(std::string_view password) {
        AesCipherParams params;
        constexpr std::array<unsigned char, 8> iv = {'1', '2', '3', '4', '5', '6', '7', '8'};

        int result = EVP_BytesToKey(params.cipher, EVP_sha256(), iv.data(),
                                    reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                    params.key.data(), params.iv.data());

        if (result == 0) {
            throw std::runtime_error{"Failed to create a key from password"};
        }

        return params;
    }

    void checkStreamHealth(std::iostream& stream, bool isInput) {
        if (!stream.good()) {
            throw std::runtime_error(
                std::format("Ошибка при работе с {} потоком.", isInput ? "входящим" : "исходящим")
            );
        }
    }

    void doCrypt(std::iostream& inStream, std::iostream& outStream, AesCipherParams params) {
        if (&inStream == &outStream) {
            throw std::runtime_error("Входящий и исходящий потоки должны отличаться.");
        }
        if(!inStream.good() || !outStream.good()) {
            throw std::runtime_error("Ошибка входящего или исходящего потока.");
        }
        checkStreamHealth(inStream, true);
        checkStreamHealth(outStream, false);
        
        EVP_CIPHER_CTX_Guard ctx{EVP_CIPHER_CTX_new()};
        if (!ctx) {
            throw std::runtime_error("Не удалось инициализировать контекст шифрования.");
        }

        if (!EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt)) {
            throw std::runtime_error("Не удалось инициализировать шифр.");
        }

        std::vector<unsigned char> outBuf(16 + EVP_MAX_BLOCK_LENGTH);
        std::vector<unsigned char> inBuf(16);
        int outLen;

        while (inStream) {
            inStream.read(reinterpret_cast<char *>(inBuf.data()), 16);
            //checkStreamHealth(inStream, true);
            long charsCount = inStream.gcount();

            if (charsCount > 0) {
                if (!EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), charsCount)) {
                    throw std::runtime_error("Ошибка в процессе шифрования.");
                }
                outStream.write(reinterpret_cast<const char*>(outBuf.data()), outLen);
                checkStreamHealth(outStream, false);
            }
        }

        EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen);
        outStream.write(reinterpret_cast<const char*>(outBuf.data()), outLen);
        checkStreamHealth(outStream, false);
    }
};

CryptoGuardCtx::CryptoGuardCtx() : impl_(std::make_unique<Impl>()) {}

CryptoGuardCtx::~CryptoGuardCtx() = default;

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    impl_->encryptFile(inStream, outStream, password);
}

void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    impl_->deryptFile(inStream, outStream, password);
}

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) const {
    return impl_->calculateChecksum(inStream);
}

}  // namespace CryptoGuard
