#include "cmd_options.h"
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/variables_map.hpp>
#include <format>
#include <iostream>
#include <stdexcept>

namespace CryptoGuard {

namespace po = boost::program_options;

ProgramOptions::ProgramOptions() : desc_("Доступные опции:") {
    desc_.add_options()
        ("help", "список доступных опций")
        ("command,c", po::value<std::string>(), "команда: 'encrypt', 'decrypt' или 'checksum', обязательно")
        ("input,i", po::value<std::string>(&inputFile_),"путь до входного файла, обязательно")
        ("output,o", po::value<std::string>(&outputFile_)->default_value("output.txt"), "путь до файла, в котором будет сохранён результат")
        ("password,p", po::value<std::string>(&password_), "пароль для шифрования и дешифрования")
    ;
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
    po::variables_map vm;
    po::store(po::command_line_parser(argc, argv).options(desc_).run(), vm);

    if (vm.contains("help") || vm.size() < 2) {
        desc_.print(std::cout);
    }

    if (!vm.contains("command") || !vm.contains("input")) {
        throw std::invalid_argument{std::format("Параметры 'command' и 'input' обязательны.")};
    }

    COMMAND_TYPE command;
    if (const auto& it = commandMapping_.find(vm.at("command").as<std::string>()); it != commandMapping_.end()) {
        command = it->second;
    }
    else {
        throw std::invalid_argument{std::format("Неизвестная команда: {}", vm.at("command").as<std::string>())};
    }

    if (command != COMMAND_TYPE::CHECKSUM && !vm.contains("password")) {
        throw std::invalid_argument{std::format("Параметр 'password' обязателен для этой команды.")};
    }

    po::notify(vm);
    command_ = command;
}

}  // namespace CryptoGuard
