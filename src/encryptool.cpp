#include "encryptool.hh"
#include <openssl/err.h>
#include <cassert>
#include <iostream>
#include <boost/filesystem.hpp>

namespace fs = boost::filesystem;

void Encryptool::LoadKey(std::string const &keypath)
{
    m_rsa_key = ReadBIO(keypath);
    std::cout << "Using key: " << keypath << std::endl;
}

static void PrintFile(std::string const &path)
{
    std::vector<char> linebuf(1024);
    Encryptool::fileptr pubkey(fopen(path.c_str(), "rb"));

    std::cout << "Public key:\n";
    while (fgets(linebuf.data(), linebuf.size(), pubkey.get()) != nullptr)
    {
        std::cout << linebuf.data();
    }
    std::cout << std::endl;
}

void Encryptool::GenerateKeyPair(std::string const &keypath)
{
    fs::path outpath(keypath);

    if (!fs::exists(keypath))
    {
        fs::create_directory(keypath);
    }
    else if (fs::current_path() == outpath)
    {
        outpath = fs::current_path();
    }

    auto pubfile = outpath / "key.pub";
    auto privfile = outpath / "key.priv";

    if (fs::exists(pubfile))
    {
        ERR("pubic key file already exists");
    }

    if (fs::exists(privfile))
    {
        ERR("private key file already exists");
    }

    GenerateKeyPairImpl(pubfile.string(), privfile.string());

    PrintFile(pubfile.string());
    PrintFile(privfile.string());
}

std::unique_ptr<BIO, Encryptool::BIODeleter> Encryptool::ReadBIO(std::string const &filename)
{
    if (filename.empty())
    {
        ERR("filename is empty");
    }

    std::unique_ptr<BIO, BIODeleter> bio(BIO_new_file(filename.c_str(), "rb"));
    if (bio == nullptr)
    {
        ERR("BIO_new_file read failed");
    }

    return bio;
}

void Encryptool::GenerateKeyPairImpl(std::string const &pub_file, std::string const &priv_file)
{
    rsaptr rsa(RSA_new());
    if (rsa == nullptr)
    {
        ERR("RSA_new failed");
    }

    bnptr bn(BN_new());
    if (bn == nullptr || !BN_set_word(bn.get(), RSA_F4))
    {
        ERR("BN_new or BN_set_word failed");
    }

    if (!RSA_generate_key_ex(rsa.get(), kRSA_KEYLEN, bn.get(), NULL))
    {
        ERR("RSA_generate_key_ex failed");
    }

    // 打开公钥文件以写入
    m_rsa_key.reset(BIO_new_file(pub_file.c_str(), "wb"));

    // 将公钥转换为 PEM 格式
    if (PEM_write_bio_RSAPublicKey(m_rsa_key.get(), rsa.get()) != 1)
    {
        ERR("PEM_write_bio_RSAPublicKey failed");
    }

    // 打开私钥文件以写入
    m_rsa_key.reset(BIO_new_file(priv_file.c_str(), "wb"));
    // 将私钥转换为 PEM 格式
    if (PEM_write_bio_RSAPrivateKey(m_rsa_key.get(), rsa.get(), NULL, NULL, 0, NULL, NULL) == 0)
    {
        ERR_print_errors_fp(stderr);
        ERR("PEM_write_bio_RSAPrivateKey failed");
    }
}

void Encryptool::WriteFile(std::string const &path, char const *data, size_t size)
{
    std::unique_ptr<FILE, FileDeleter> fp(fopen(path.c_str(), "wb"));
    if (fp == nullptr)
    {
        ERR("fopen failed");
    }

    if (fwrite(data, 1, size, fp.get()) != size)
    {
        ERR("fwrite failed");
    }
}

void Encryptool::EncryptFile(std::string const &keypath, std::string const &inpath, std::string const &outpath)
{
    LoadKey(keypath);
    assert(m_rsa_key != nullptr);

    fileptr in(fopen(inpath.c_str(), "rb"));
    if (in == nullptr)
    {
        char msg[1024]{};
        snprintf(msg, sizeof(msg), "Could not open input file: %s", outpath.c_str());
        ERR("Could not open input file");
    }

    fileptr out(fopen(outpath.c_str(), "wb"));
    if (out == nullptr)
    {
        char msg[1024]{};
        snprintf(msg, sizeof(msg), "Could not open output file: %s", outpath.c_str());
        ERR(msg);
    }

    rsaptr rsa(PEM_read_bio_RSAPublicKey(m_rsa_key.get(), NULL, NULL, NULL));

    if (rsa == NULL)
    {
        ERR("Could not load public key");
    }

    int keylen = RSA_size(rsa.get());
    assert(keylen > 11);
    std::vector<char> buffer(keylen);
    std::vector<char> ciphertext(keylen);

    // 写入明文大小
    size_t plaintext_size = fs::file_size(inpath);

    size_t wrlen = fwrite(&plaintext_size, sizeof(plaintext_size), 1, out.get());

    size_t block_size = keylen - 11;

    for (size_t i = 0; i < plaintext_size; i += block_size)
    {
        size_t len = fread(buffer.data(), 1, block_size, in.get());
        if (len <= 0)
        {
            break;
        }
        memset(ciphertext.data(), 0, keylen);
        RSA_public_encrypt(len, (unsigned char *)buffer.data(), (unsigned char *)ciphertext.data(), rsa.get(), RSA_PKCS1_PADDING);

        size_t wrlen = fwrite(ciphertext.data(), 1, keylen, out.get());
        if (wrlen != keylen)
        {
            ERR("fwrite failed");
        }
    }
}

void Encryptool::DecryptFile(std::string const &keypath, std::string const &inpath, std::string const &outpath)
{
    LoadKey(keypath);
    assert(m_rsa_key != nullptr);

    fileptr in(fopen(inpath.c_str(), "rb"));
    if (in == nullptr)
    {
        char msg[1024]{};
        snprintf(msg, sizeof(msg), "Could not open input file: %s", outpath.c_str());
        ERR("Could not open input file");
    }

    fileptr out(fopen(outpath.c_str(), "wb"));

    if (out == nullptr)
    {
        char msg[1024]{};
        snprintf(msg, sizeof(msg), "Could not open output file: %s", outpath.c_str());
        ERR(msg);
    }

    rsaptr rsa(PEM_read_bio_RSAPrivateKey(m_rsa_key.get(), NULL, NULL, NULL));
    if (rsa == NULL)
    {
        ERR("Could not load private key");
    }

    int keylen = RSA_size(rsa.get());

    size_t ciphertext_size = fs::file_size(inpath) - sizeof(size_t);

    if (ciphertext_size == 0 || (ciphertext_size % keylen != 0))
    {
        ERR("ciphertext_size error");
    }

    // 读取明文大小
    size_t plaintext_size = 0;
    size_t rdlen = fread(&plaintext_size, sizeof(plaintext_size), 1, in.get());
    if (rdlen != 1)
    {
        ERR("fread failed");
    }

    if (plaintext_size == 0 || plaintext_size > ciphertext_size)
    {
        ERR("plaintext_size error");
    }

    size_t decrypted_size = 0;
    std::vector<char> buffer(keylen);
    std::vector<char> plaintext(keylen);

    for (size_t i = 0; i < ciphertext_size; i += keylen)
    {
        size_t len = fread(buffer.data(), 1, keylen, in.get());
        if (len <= 0)
        {
            printf("read finish\n");
            break;
        }

        size_t block_size = len;

        memset(plaintext.data(), 0, block_size);
        RSA_private_decrypt(block_size, (unsigned char *)buffer.data(), (unsigned char *)plaintext.data(), rsa.get(), RSA_PKCS1_PADDING);

        if (decrypted_size + block_size == plaintext_size)
        {
            size_t wrlen = fwrite(plaintext.data(), 1, plaintext_size - decrypted_size, out.get());
            if (wrlen != plaintext_size - decrypted_size)
            {
                ERR("fwrite failed");
            }
            decrypted_size += plaintext_size - decrypted_size;
            break;
        } // 最后一块
        else if (decrypted_size + keylen - 11 > plaintext_size)
        {
            printf("decrypted_size: %zu, plaintext_size: %zu, keylen:%d\n", decrypted_size, plaintext_size, keylen);
            ERR("decrypted_size error");
        } // 解密出错
        else
        {
            size_t wrlen = fwrite(plaintext.data(), 1, keylen - 11, out.get());
            if (wrlen != keylen - 11)
            {
                ERR("fwrite failed");
            }
            decrypted_size += wrlen;
        } // 正常解密
    }
    assert(decrypted_size == plaintext_size);
}