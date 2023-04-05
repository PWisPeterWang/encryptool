#pragma once
#include <openssl/crypto.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <string>
#include <vector>
#include <memory>

#include <boost/stacktrace.hpp>
#include <boost/exception/all.hpp>

#ifdef USE_STD_FILESYSTEM
    #include <filesystem>
    namespace fs = std::filesystem;
#else
    #include <boost/filesystem.hpp>
    namespace fs = boost::filesystem;
#endif

using traced = boost::error_info<struct tag_stacktrace, boost::stacktrace::stacktrace>;

template<class E>
void throw_with_trace(E const &e)
{
    throw boost::enable_error_info(e) << traced(boost::stacktrace::stacktrace());
}

#define ERR(msg) throw_with_trace(std::runtime_error(msg))
class Encryptool
{
    enum {
        kRSA_KEYLEN = 2048,
    };
public:
    Encryptool() = default;

    void GenerateKeyPair(std::string const &keypath);

    void EncryptFile(std::string const &keypath, std::string const &inpath, std::string const &outpath);
    void DecryptFile(std::string const &keypath, std::string const &inpath, std::string const &outpath);

    struct FileDeleter
    {
        void operator()(FILE *f)
        {
            fclose(f);
        }
    };

    struct BIODeleter
    {
        void operator()(BIO *b)
        {
            BIO_free_all(b);
        }
    };

    struct RSADeleter
    {
        void operator()(RSA *r)
        {
            RSA_free(r);
        }
    };

    struct BIGNUMDeleter
    {
        void operator()(BIGNUM *b)
        {
            BN_free(b);
        }
    };

    using bioptr = std::unique_ptr<BIO, BIODeleter>;
    using rsaptr = std::unique_ptr<RSA, RSADeleter>;
    using fileptr = std::unique_ptr<FILE, FileDeleter>;
    using bnptr = std::unique_ptr<BIGNUM, BIGNUMDeleter>;

private:
    void LoadKey(std::string const &keypath);

    void GenerateKeyPairImpl(std::string const &pubfile, std::string const &privfile);

    void WriteFile(std::string const &filename, char const *data, size_t len);

    void ExportKey(std::string const &keypath, bioptr const &bio);

    static std::unique_ptr<BIO, BIODeleter> ReadBIO(std::string const &str);

private:
    bioptr m_rsa_key;
};