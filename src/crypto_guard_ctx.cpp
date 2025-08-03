
#include "crypto_guard_ctx.h"

#include <boost/scope_exit.hpp>
#include <iomanip>
#include <ios>
#include <iostream>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

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
        checkStreamHealth(inStream, true);
        
        EVP_MD_CTX_Guard ctx{EVP_MD_CTX_new()};
        if (!ctx) {
            throwOpenSSLError("Не удалось инициализировать контекст хэширования.");
        }

        if (!EVP_DigestInit_ex2(ctx.get(), EVP_sha256(), NULL)) {
            throwOpenSSLError("Не удалось инициализировать хэширование.");
        }

        std::vector<unsigned char> inBuf(32);
        std::vector<unsigned char> outBuf(EVP_MAX_MD_SIZE);
        unsigned int outLen;

        while (inStream) {
            inStream.read(reinterpret_cast<char *>(inBuf.data()), 32);
            long charsCount = inStream.gcount();

            if (charsCount > 0) {
                if (!EVP_DigestUpdate(ctx.get(), inBuf.data(), charsCount)) {
                    throwOpenSSLError("Ошибка в процессе хэширования.");
                }
            }
        }

        if (!EVP_DigestFinal_ex(ctx.get(), outBuf.data(), &outLen)) {
            throwOpenSSLError("Ошибка при завершении хэширования.");
        }
        std::stringstream hashStream{};
        hashStream << std::hex << std::setfill('0');
        for (unsigned int i=0; i < outLen; ++i) {
            hashStream << std::setw(2) << static_cast<int>(outBuf[i]);
        }

        return hashStream.str();
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

    void checkStreamHealth(std::iostream& stream, bool isInput) const {
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
        checkStreamHealth(inStream, true);
        checkStreamHealth(outStream, false);
        
        EVP_CIPHER_CTX_Guard ctx{EVP_CIPHER_CTX_new()};
        if (!ctx) {
            throwOpenSSLError("Не удалось инициализировать контекст шифрования.");
        }

        if (!EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt)) {
            throwOpenSSLError("Не удалось инициализировать шифр.");
        }

        std::vector<unsigned char> outBuf(16 + EVP_MAX_BLOCK_LENGTH);
        std::vector<unsigned char> inBuf(16);
        int outLen;

        while (inStream) {
            inStream.read(reinterpret_cast<char *>(inBuf.data()), 16);
            long charsCount = inStream.gcount();

            if (charsCount > 0) {
                if (!EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), charsCount)) {
                    throwOpenSSLError("Ошибка в процессе шифрования.");
                }
                outStream.write(reinterpret_cast<const char*>(outBuf.data()), outLen);
                checkStreamHealth(outStream, false);
            }
        }

        if(!EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen)) {
            throwOpenSSLError("Ошибка при завершении шифрования.");
        }
        outStream.write(reinterpret_cast<const char*>(outBuf.data()), outLen);
        checkStreamHealth(outStream, false);
    }

    void throwOpenSSLError(const std::string& errorMessage) const {
        unsigned long errorNum = ERR_get_error();
        std::vector<char> buf(ERR_MAX_DATA_SIZE);
        ERR_error_string_n(errorNum, buf.data(), buf.size());
        std::string errorString{buf.data(), buf.size()};
        throw std::runtime_error(std::format("{}\nOpenSSL {}", errorMessage, errorString));
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
