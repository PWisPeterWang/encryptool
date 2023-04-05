#include <boost/program_options.hpp>
#include <boost/stacktrace.hpp>
#include <boost/exception/all.hpp>
#include <iostream>
#include "encryptool.hh"

namespace po = boost::program_options;

static bool VerifyPath(std::string const &keypath, std::string const &inpath)
{
    if (!fs::exists(inpath))
    {
        std::cout << "File does not exist" << std::endl;
        return false;
    }

    return true;
}

static void errexit(std::string const &msg)
{
    std::cerr << msg << std::endl;
    exit(1);
}

int main(int argc, const char *argv[])
{
    po::options_description desc("Allowed options");
    fs::path temp = fs::temp_directory_path() / "key";
    std::cout << "Temp dir: " << temp.string() << std::endl;
    // clang-format off
    desc.add_options()
        ("help", "produce help message")
        ("key,k", po::value<std::string>(), "path to key file, when encrypting or decrypting, give path to key file ;")
        ("generate,g", "generate key pairs and exit ;")
        ("encrypt,e", po::value<std::string>(), "path to file to encrypt, defaults to /tmp/<infile_name>.enc; require --key options given pubkey file;")
        ("decrypt,d", po::value<std::string>(), "path to file to decrypt, defaults to /tmp/<infile_name>.dec; require --key options given privkey file;")
        ("out,o", po::value<std::string>()->default_value(temp.string()), "path to output file. If not given, defaults to fs::temp_directory_path();");
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

    std::string outpath = vm["out"].as<std::string>();
    std::string keypath;
    std::string inpath;

    if (vm.count("generate"))
    {
        try
        {
            tool.GenerateKeyPair(vm["out"].as<std::string>());
        }
        catch (std::exception const &e)
        {
            std::cout << e.what() << std::endl;
            return 1;
        }
        return 0;
    }

    if (vm.count("key") == 0)
    {
        std::cerr << "Key path not given" << std::endl;
        return 1;
    }

    keypath = vm["key"].as<std::string>();
    if (!fs::exists(keypath) || !fs::is_regular_file(keypath))
    {
        std::cout << "key file: " << keypath << " does not exists" << std::endl;
        return 1;
    }

    int mode = 0;

    if (vm.count("encrypt"))
    {
        mode = 1;
        std::cout << "Encrypting " << vm["encrypt"].as<std::string>() << std::endl;

        inpath = vm["encrypt"].as<std::string>();

        if (fs::exists(outpath))
        {
            if (fs::is_directory(outpath))
            {
                outpath = outpath + "/" + fs::path(inpath).filename().string() + ".enc";
            }
            else
            {
                errexit("output file already exists");
            }
        }
    }
    else if (vm.count("decrypt"))
    {
        mode = 2;
        std::cout << "Decrypting " << vm["decrypt"].as<std::string>() << std::endl;
        inpath = vm["decrypt"].as<std::string>();

        if (fs::exists(outpath))
        {
            if (fs::is_directory(outpath))
            {
                outpath = outpath + "/" + fs::path(inpath).filename().string() + ".dec";
            }
            else
            {
                errexit("output file already exists");
            }
        }
    }

    if (mode == 0)
    {
        std::cout << "No mode <encrypt/decrypt> given" << std::endl;
        return 1;
    }

    try
    {
        if (mode == 1)
        {

            tool.EncryptFile(keypath, inpath, outpath);
        }
        else
        {

            tool.DecryptFile(keypath, inpath, outpath);
        }
    }
    catch (std::exception const &e)
    {
        std::cerr << e.what() << '\n';
        const boost::stacktrace::stacktrace *st = boost::get_error_info<traced>(e);
        if (st)
        {
            std::cerr << *st << '\n';
        }
        return 1;
    }

    return 0;
}
