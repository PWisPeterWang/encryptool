#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>
#include <iostream>
#include <encryptool.hh>

namespace po = boost::program_options;
namespace fs = boost::filesystem;

int main(int argc, const char *argv[])
{
    po::options_description desc("Allowed options");
    // clang-format off
    desc.add_options()
        ("help", "produce help message")
        ("key", po::value<std::string>(), "path to key")
        ("g", "generate keys")
        ("encrypt", po::value<std::string>(), "path to file to encrypt")
        ("decrypt", po::value<std::string>(), "path to file to decrypt")
        ("out", po::value<std::string>()->default_value("/tmp"), "path to file to decrypt");
    // clang-format on

    po::variables_map vm;

    try
    {
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);
    }
    catch (std::exception const &e)
    {
        std::cout << e.what() << std::endl;
        std::cout << desc << std::endl;
        return 1;
    }

    if (vm.count("help"))
    {
        std::cout << desc << std::endl;
        return 0;
    }

    if (vm.count("encrypt") && vm.count("decrypt"))
    {
        std::cout << "Cannot encrypt and decrypt at the same time" << std::endl;
        return 1;
    }

    Encryptool tool;

    if (!vm.count("key"))
    {
        std::cout << "No key specified" << std::endl;
        return 1;
    }
    else
    {
        if (vm.count("g"))
            tool.GenerateKeyPair(vm["key"].as<std::string>());
        else
            tool.LoadKeys(vm["key"].as<std::string>());
    }

    if (vm.count("encrypt"))
    {
        std::cout << "Encrypting " << vm["encrypt"].as<std::string>() << std::endl;

        if (!fs::exists(vm["encrypt"].as<std::string>()))
        {
            std::cout << "File does not exist" << std::endl;
            return 1;
        }

        tool.EncryptFile(vm["encrypt"].as<std::string>(), vm["out"].as<std::string>());
    }
    else if (vm.count("decrypt"))
    {
        std::cout << "Decrypting " << vm["decrypt"].as<std::string>() << std::endl;

        if (!fs::exists(vm["decrypt"].as<std::string>()))
        {
            std::cout << "File does not exist" << std::endl;
            return 1;
        }

        tool.DecryptFile(vm["decrypt"].as<std::string>(), vm["out"].as<std::string>());
    }

    return 0;
}
