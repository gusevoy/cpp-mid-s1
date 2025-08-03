#include "cmd_options.h"
#include "crypto_guard_ctx.h"

#include <fstream>
#include <iostream>
#include <openssl/evp.h>
#include <print>
#include <stdexcept>
#include <string>

std::fstream createFileStream(const std::string& fileName, bool isOutput = false) {
    std::ios_base::openmode mode;
    if (isOutput) {
        mode = std::ios::out | std::ios::binary | std::ios::trunc;
    } else {
        mode = std::ios::in | std::ios::binary;
    }
    std::fstream stream{fileName, mode};
    if (!stream.is_open()) {
        throw std::runtime_error(std::format("Не удалось открыть файл {} для {}.", fileName, isOutput ? "записи" : "чтения"));
    }
    return stream;
}

int main(int argc, char *argv[]) {
    try {
        CryptoGuard::ProgramOptions options;
        options.Parse(argc, argv);

        CryptoGuard::CryptoGuardCtx cryptoCtx;

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT:
            {
                std::fstream input = createFileStream(options.GetInputFile());
                std::fstream output = createFileStream(options.GetOutputFile(), true);
                cryptoCtx.EncryptFile(input, output, options.GetPassword());
                std::print("File encoded successfully\n");
            }
            break;

        case COMMAND_TYPE::DECRYPT:
            {
                std::fstream input = createFileStream(options.GetInputFile());
                std::fstream output = createFileStream(options.GetOutputFile(), true);
                cryptoCtx.DecryptFile(input, output, options.GetPassword());
                std::print("File decoded successfully\n");
            }
            break;

        case COMMAND_TYPE::CHECKSUM:
            {
                std::fstream input = createFileStream(options.GetInputFile());
                std::print("Checksum: {}\n", cryptoCtx.CalculateChecksum(input));
            }
            break;

        default:
            throw std::runtime_error{"Unsupported command"};
        }

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}