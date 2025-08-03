#include <gtest/gtest.h>
#include <sstream>
#include <stdexcept>
#include <string>

#include "crypto_guard_ctx.h"

TEST(CryptoGuardCtxTest, EncryptNoThrowCheck) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream inStream{"Input Text"};
    std::stringstream outStream;

    EXPECT_NO_THROW(ctx.EncryptFile(inStream, outStream, "my_secure_password"));
}

TEST(CryptoGuardCtxTest, InputIsOutputCheck) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream stream{"Input Text"};

    EXPECT_THROW(ctx.EncryptFile(stream, stream, "my_secure_password"), std::runtime_error);
}

TEST(CryptoGuardCtxTest, EmptyPasswordCheck) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream inStream{"Input Text"};
    std::stringstream outStream;

    //EXPECT_THROW(ctx.EncryptFile(stream, stream, ""), std::runtime_error);
    EXPECT_NO_THROW(ctx.EncryptFile(inStream, outStream, ""));
}

TEST(CryptoGuardCtxTest, EmptyInputCheck) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::string password = "my_secure_password";
    std::string input = "";
    std::stringstream inStream{input};
    std::stringstream cryptStream{};
    std::stringstream outStream;

    EXPECT_NO_THROW(ctx.EncryptFile(inStream, cryptStream, password));
    EXPECT_NO_THROW(ctx.DecryptFile(cryptStream, outStream, password));
    EXPECT_EQ(outStream.str(), input);}


TEST(CryptoGuardCtxTest, BasicEncryptDecryptCheck) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::string password = "my_secure_password";
    std::string input = "Input Text";
    std::stringstream inStream{input};
    std::stringstream cryptStream{};
    std::stringstream outStream{};

    EXPECT_NO_THROW(ctx.EncryptFile(inStream, cryptStream, password));
    EXPECT_NO_THROW(ctx.DecryptFile(cryptStream, outStream, password));
    EXPECT_EQ(outStream.str(), input);
}

TEST(CryptoGuardCtxTest, EncryptDecryptNoPasswordCheck) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::string password = "";
    std::string input = "Input Text";
    std::stringstream inStream{input};
    std::stringstream cryptStream{};
    std::stringstream outStream{};

    EXPECT_NO_THROW(ctx.EncryptFile(inStream, cryptStream, password));
    EXPECT_NO_THROW(ctx.DecryptFile(cryptStream, outStream, password));
    EXPECT_EQ(outStream.str(), input);
}

TEST(CryptoGuardCtxTest, EncryptDecryptWrongPasswordCheck) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::string password = "my_secure_password";
    std::string wrong_password = "my_wrong_password";
    std::string input = "Input Text";
    std::stringstream inStream{input};
    std::stringstream cryptStream{};
    std::stringstream outStream{};

    EXPECT_NO_THROW(ctx.EncryptFile(inStream, cryptStream, password));
    EXPECT_NO_THROW(ctx.DecryptFile(cryptStream, outStream, wrong_password));
    EXPECT_NE(outStream.str(), input);
}

TEST(CryptoGuardCtxTest, InputFailCheck) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::string password = "my_secure_password";
    std::string input = "Input Text";
    std::stringstream inStream{input};
    std::stringstream cryptStream{};
    std::stringstream outStream{};

    inStream.setstate(std::ios::failbit);
    EXPECT_THROW(ctx.EncryptFile(inStream, cryptStream, password), std::runtime_error);
}

TEST(CryptoGuardCtxTest, OutputFailCheck) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::string password = "my_secure_password";
    std::string input = "Input Text";
    std::stringstream inStream{input};
    std::stringstream cryptStream{};
    std::stringstream outStream{};

    outStream.setstate(std::ios::failbit);
    EXPECT_THROW(ctx.EncryptFile(inStream, outStream, password), std::runtime_error);
}
