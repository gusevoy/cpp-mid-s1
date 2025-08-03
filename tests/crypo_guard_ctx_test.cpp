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
    EXPECT_THROW(ctx.DecryptFile(cryptStream, outStream, wrong_password), std::runtime_error);
    EXPECT_NE(outStream.str(), input);
}

TEST(CryptoGuardCtxTest, EncryptInputFailCheck) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::string password = "my_secure_password";
    std::string input = "Input Text";
    std::stringstream inStream{input};
    std::stringstream cryptStream{};
    std::stringstream outStream{};

    inStream.setstate(std::ios::failbit);
    EXPECT_THROW(ctx.EncryptFile(inStream, cryptStream, password), std::runtime_error);
}

TEST(CryptoGuardCtxTest, EncryptOutputFailCheck) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::string password = "my_secure_password";
    std::string input = "Input Text";
    std::stringstream inStream{input};
    std::stringstream cryptStream{};
    std::stringstream outStream{};

    outStream.setstate(std::ios::failbit);
    EXPECT_THROW(ctx.EncryptFile(inStream, outStream, password), std::runtime_error);
}

TEST(CryptoGuardCtxTest, DecryptInputFailCheck) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::string password = "my_secure_password";
    std::string input = "Input Text";
    std::stringstream inStream{input};
    std::stringstream cryptStream{};
    std::stringstream outStream{};

    inStream.setstate(std::ios::failbit);
    EXPECT_THROW(ctx.DecryptFile(inStream, cryptStream, password), std::runtime_error);
}

TEST(CryptoGuardCtxTest, DecryptOutputFailCheck) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::string password = "my_secure_password";
    std::string input = "Input Text";
    std::stringstream inStream{input};
    std::stringstream cryptStream{};
    std::stringstream outStream{};

    outStream.setstate(std::ios::failbit);
    EXPECT_THROW(ctx.DecryptFile(inStream, outStream, password), std::runtime_error);
}

TEST(CryptoGuardCtxTest, ChecksumBasicCheck) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::string input = "Input Text";
    std::stringstream inStream{input};

    EXPECT_EQ(ctx.CalculateChecksum(inStream), "28f88397a74b662d610d667d63e198019043dffc341249404787f7ecee599e59");
}

TEST(CryptoGuardCtxTest, ChecksumInputFailCheck) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::string input = "Input Text";
    std::stringstream inStream{input};

    inStream.setstate(std::ios::failbit);
    EXPECT_THROW(ctx.CalculateChecksum(inStream), std::runtime_error);
}

TEST(CryptoGuardCtxTest, ChecksumEmptyInputCheck) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::string input = "";
    std::stringstream inStream{input};

    EXPECT_EQ(ctx.CalculateChecksum(inStream), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}