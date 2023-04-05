//          Copyright Peter Wang 2023 - 2023.
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          https://www.boost.org/LICENSE_1_0.txt)

#include "encryptool.hh"
#include <openssl/err.h>
#include <cassert>
#include <iostream>
#include <fstream>

void Encryptool::LoadKey(std::string const &keypath)
{
    m_rsa_key = ReadBIO(keypath);
    std::cout << "Using key: " << keypath << std::endl;
}

static void PrintFile(std::string const &path)
{
    std::cout << "file: " << path << ", size:" << fs::file_size(path) << std::endl;
    std::ifstream ifs(path);
    std::string line;
    while (std::getline(ifs, line))
    {
        std::cout << line << std::endl;
    }
}

void Encryptool::GenerateKeyPair(std::string const &keypath)
{
    fs::path outpath(keypath);

    if (!fs::exists(outpath))
    {
        fs::create_directory(outpath);
        std::cout << "creating:" << fs::absolute(outpath).string() << std::endl;
    }
    else if (fs::current_path() == outpath)
    {
        outpath = fs::current_path();
    }

    auto pubfile = outpath / "key.pub";
    auto privfile = outpath / "key.priv";

    if (fs::exists(pubfile))
    {
        std::cout << "public key file already exists, pubfile:" << fs::absolute(pubfile).string() << std::endl;
        ERR("pubic key file already exists");
    }

    if (fs::exists(privfile))
    {
        std::cout << "private key file already exists, pubfile:" << fs::absolute(privfile).string() << std::endl;
        ERR("private key file already exists");
    }

    GenerateKeyPairImpl(pubfile.string(), privfile.string());

    std::cout << "Pubkey file: " << pubfile.string() << std::endl;
    PrintFile(pubfile.string());
    std::cout << "Private key file: " << privfile.string() << std::endl;
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

    m_rsa_key.reset(BIO_new_file(pub_file.c_str(), "wb"));

    if (PEM_write_bio_RSAPublicKey(m_rsa_key.get(), rsa.get()) != 1)
    {
        ERR_print_errors_fp(stderr);
        ERR("PEM_write_bio_RSAPublicKey failed");
    }

    m_rsa_key.reset(BIO_new_file(priv_file.c_str(), "wb"));
    if (PEM_write_bio_RSAPrivateKey(m_rsa_key.get(), rsa.get(), NULL, NULL, 0, NULL, NULL) != 1)
    {
        ERR_print_errors_fp(stderr);
        ERR("PEM_write_bio_RSAPrivateKey failed");
    }
    BIO_flush(m_rsa_key.get());
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

    printf("before decrypt, ciphertext_size: %zu, plaintext_size: %zu\n", ciphertext_size, plaintext_size);

    size_t written_size = 0;
    for (; decrypted_size < ciphertext_size;)
    {
        size_t nread = fread(buffer.data(), 1, keylen, in.get());
        if (nread <= 0)
        {
            printf("read finish\n");
            break;
        }
        printf("block %zu, read %zu bytes\n", decrypted_size / keylen + 1, nread);

        memset(plaintext.data(), 0, nread);
        RSA_private_decrypt(nread, (unsigned char *)buffer.data(), (unsigned char *)plaintext.data(), rsa.get(), RSA_PKCS1_PADDING);

        if (decrypted_size + nread == ciphertext_size)
        {
            size_t last_part = plaintext_size - written_size;
            size_t wrlen = fwrite(plaintext.data(), 1, last_part, out.get());
            if (wrlen != last_part)
            {
                ERR("last block fwrite failed");
            }
            written_size += last_part;
        } // last block
        else if (decrypted_size + nread > ciphertext_size)
        {
            printf("decrypted_size: %zu, plaintext_size: %zu, nread:%zu\n", decrypted_size, plaintext_size, nread);
            ERR("decrypted_size error");
        } // decrypt error
        else
        {
            size_t wrlen = fwrite(plaintext.data(), 1, nread - 11, out.get());
            if (wrlen != nread - 11)
            {
                ERR("normal fwrite failed");
            }
            written_size += wrlen;
        } // normal block

        decrypted_size += nread;
    }
    assert(written_size == plaintext_size);
}