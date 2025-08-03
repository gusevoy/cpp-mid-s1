#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <stdexcept>

#include "cmd_options.h"


class ProgramOptionsTest : public ::testing::Test {
protected:
    void SetUp() override {
        originalStreamBuffer_ = std::cout.rdbuf(cout_.rdbuf());
    }

    void TearDown() override {
        std::cout.rdbuf(originalStreamBuffer_);
    }

    std::ostringstream cout_{};
    CryptoGuard::ProgramOptions programOptions_{};

private:
    std::streambuf* originalStreamBuffer_{};
};


class Args {
public:
    explicit Args(std::string_view arguments) {
        {
            std::istringstream inStream{std::string(arguments)};
            std::string token;
            while (inStream >> token) {
                arguments_.push_back(token);
            }
        }
        argv_.reserve(arguments_.size());
        for (const auto &arg : arguments_) {
            argv_.push_back(arg.c_str());
        }
    }
    int argc() const noexcept { return static_cast<int>(argv_.size()); }
    char **argv() const noexcept { return const_cast<char **>(argv_.data()); }

private:
    std::vector<std::string> arguments_;
    std::vector<const char *> argv_;
};


TEST_F(ProgramOptionsTest, NoArgumentsCheck) {
    Args args{"CryptoGuard"};
    EXPECT_THROW(programOptions_.Parse(args.argc(), args.argv()), std::invalid_argument);
    EXPECT_THAT(cout_.str(), ::testing::HasSubstr("Доступные опции:"));

}

TEST_F(ProgramOptionsTest, HelpCheck) {
    Args args{"CryptoGuard --help"};
    EXPECT_THROW(programOptions_.Parse(args.argc(), args.argv()), std::invalid_argument);
    EXPECT_THAT(cout_.str(), ::testing::HasSubstr("Доступные опции:"));
}

TEST_F(ProgramOptionsTest, AllArguments) {
    Args args{"CryptoGuard -i input.txt -o output.txt -c encrypt -p 12345"};
    EXPECT_NO_THROW(programOptions_.Parse(args.argc(), args.argv()));
    EXPECT_EQ(programOptions_.GetInputFile(), "input.txt");
    EXPECT_EQ(programOptions_.GetOutputFile(), "output.txt");
    EXPECT_EQ(programOptions_.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(programOptions_.GetPassword(), "12345");
}

TEST_F(ProgramOptionsTest, AllArgumentsFull) {
    Args args{"CryptoGuard --input input.txt --output output.txt --command encrypt --password 12345"};
    EXPECT_NO_THROW(programOptions_.Parse(args.argc(), args.argv()));
    EXPECT_EQ(programOptions_.GetInputFile(), "input.txt");
    EXPECT_EQ(programOptions_.GetOutputFile(), "output.txt");
    EXPECT_EQ(programOptions_.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(programOptions_.GetPassword(), "12345");
}

TEST_F(ProgramOptionsTest, DefaultOutputValue) {
    Args args{"CryptoGuard -i input.txt -c encrypt -p 12345"};
    EXPECT_NO_THROW(programOptions_.Parse(args.argc(), args.argv()));
    EXPECT_EQ(programOptions_.GetInputFile(), "input.txt");
    EXPECT_EQ(programOptions_.GetOutputFile(), "output.txt");
    EXPECT_EQ(programOptions_.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(programOptions_.GetPassword(), "12345");
}

TEST_F(ProgramOptionsTest, CommandEncrypt) {
    Args args{"CryptoGuard -i input.txt -c encrypt -p 12345"};
    EXPECT_NO_THROW(programOptions_.Parse(args.argc(), args.argv()));
    EXPECT_EQ(programOptions_.GetInputFile(), "input.txt");
    EXPECT_EQ(programOptions_.GetOutputFile(), "output.txt");
    EXPECT_EQ(programOptions_.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(programOptions_.GetPassword(), "12345");
}

TEST_F(ProgramOptionsTest, CommandDecrypt) {
    Args args{"CryptoGuard -i input.txt -c decrypt -p 12345"};
    EXPECT_NO_THROW(programOptions_.Parse(args.argc(), args.argv()));
    EXPECT_EQ(programOptions_.GetInputFile(), "input.txt");
    EXPECT_EQ(programOptions_.GetOutputFile(), "output.txt");
    EXPECT_EQ(programOptions_.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::DECRYPT);
    EXPECT_EQ(programOptions_.GetPassword(), "12345");
}

TEST_F(ProgramOptionsTest, CommandChecksum) {
    Args args{"CryptoGuard -i input.txt -c checksum"};
    EXPECT_NO_THROW(programOptions_.Parse(args.argc(), args.argv()));
    EXPECT_EQ(programOptions_.GetInputFile(), "input.txt");
    EXPECT_EQ(programOptions_.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM);
}

TEST_F(ProgramOptionsTest, InputMissing) {
    Args args{"CryptoGuard input.txt --output output.txt --command encrypt --password 12345"};
    EXPECT_THROW(programOptions_.Parse(args.argc(), args.argv()), std::invalid_argument);
}

TEST_F(ProgramOptionsTest, CommandMissing) {
    Args args{"CryptoGuard --input input.txt --output output.txt encrypt --password 12345"};
    EXPECT_THROW(programOptions_.Parse(args.argc(), args.argv()), std::invalid_argument);
}

TEST_F(ProgramOptionsTest, PasswordMissing) {
    Args args{"CryptoGuard --input input.txt --output output.txt --command encrypt 12345"};
    EXPECT_THROW(programOptions_.Parse(args.argc(), args.argv()), std::invalid_argument);
}

TEST_F(ProgramOptionsTest, PasswordMissingOk) {
    Args args{"CryptoGuard --input input.txt --command checksum"};
    EXPECT_NO_THROW(programOptions_.Parse(args.argc(), args.argv()));
}
