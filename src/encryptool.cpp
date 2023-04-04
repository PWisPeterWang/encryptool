#include "encryptool.hh"
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <cassert>
#include <boost/filesystem.hpp>

namespace fs = boost::filesystem;

Encryptool::Encryptool()
{}

void Encryptool::LoadKeys(std::string const &keypath)
{
    if (!fs::exists(keypath) || !fs::is_directory(keypath))
    {
        throw std::runtime_error("Key file does not exist");
    }

    for (auto &p : fs::directory_iterator(keypath))
    {
        if (p.path().extension() == ".pub")
        {
            LoadPubKey(p.path().string());
        }
        else if (p.path().extension() == ".priv")
        {
            LoadPrivKey(p.path().string());
        }
    }

    if (m_priv_key.empty() || m_pub_key.empty())
    {
        throw std::runtime_error("Key file does not exist");
    }
}

void Encryptool::LoadPrivKey(std::string const &keypath)
{
    BIO *key = BIO_new_file(keypath.c_str(), "r");
    RSA *rsa = PEM_read_bio_RSAPrivateKey(key, NULL, NULL, NULL);
    BIO_free_all(key);

    if (rsa == NULL)
    {
        throw std::runtime_error("Could not load private key");
    }

    int keylen = RSA_size(rsa);
    m_priv_key.resize(keylen);
    RSA_private_encrypt(keylen, (unsigned char *)rsa, (unsigned char *)m_priv_key.data(), rsa, RSA_PKCS1_PADDING);
    RSA_free(rsa);
}

void Encryptool::LoadPubKey(std::string const &keypath)
{
    BIO *key = BIO_new_file(keypath.c_str(), "r");
    RSA *rsa = PEM_read_bio_RSAPublicKey(key, NULL, NULL, NULL);
    BIO_free_all(key);

    if (rsa == NULL)
    {
        throw std::runtime_error("Could not load public key");
    }

    int keylen = RSA_size(rsa);
    m_pub_key.resize(keylen);
    RSA_public_encrypt(keylen, (unsigned char *)rsa, (unsigned char *)m_pub_key.data(), rsa, RSA_PKCS1_PADDING);
    RSA_free(rsa);
}

void Encryptool::GenerateKeyPair(std::string const &keypath)
{
    RSA *rsa = RSA_new();
    int ret = RSA_generate_key_ex(rsa, 2048, NULL, NULL);

    if (rsa == NULL)
    {
        throw std::runtime_error("Could not generate key pair");
    }
    BIO* priv = BIO_new_file((keypath + ".priv").c_str(), "w");
    BIO* pub = BIO_new_file((keypath + ".pub").c_str(), "w");

    PEM_write_bio_RSAPublicKey(pub, rsa);
    PEM_write_bio_RSAPrivateKey(priv, rsa, NULL, NULL, 0, NULL, NULL);

    BIO_free_all(pub);
    BIO_free_all(priv);
    RSA_free(rsa);
}

void Encryptool::EncryptFile(std::string const &inpath, std::string const &outpath)
{
    assert(!m_pub_key.empty());
    FILE* in = fopen(inpath.c_str(), "rb");
    FILE* out = fopen(outpath.c_str(), "wb");
    
    if (!in || !out)
    {
        throw std::runtime_error("Could not open files");
    }

    RSA *rsa = RSA_new();
    BIO *key = BIO_new_mem_buf(m_pub_key.data(), m_pub_key.size());
    rsa = PEM_read_bio_RSAPublicKey(key, NULL, NULL, NULL);
    BIO_free_all(key);

    if (rsa == NULL)
    {
        throw std::runtime_error("Could not load public key");
    }

    int keylen = RSA_size(rsa);
    char* buffer = new char[keylen];
    int read = 0;
    while ((read = fread(buffer, 1, keylen - 11, in)) > 0)
    {
        char* outbuffer = new char[keylen];
        RSA_public_encrypt(read, (unsigned char *)buffer, (unsigned char *)outbuffer, rsa, RSA_PKCS1_PADDING);
        fwrite(outbuffer, 1, keylen, out);
        delete[] outbuffer;
    }

    delete[] buffer;
    RSA_free(rsa);
    fclose(in);
    fclose(out);
}

void Encryptool::DecryptFile(std::string const &inpath, std::string const &outpath)
{
    assert(!m_priv_key.empty());
    FILE* in = fopen(inpath.c_str(), "rb");
    FILE* out = fopen(outpath.c_str(), "wb");

    if (!in || !out)
    {
        throw std::runtime_error("Could not open files");
    }

    RSA *rsa = RSA_new();
    BIO *key = BIO_new_mem_buf(m_priv_key.data(), m_priv_key.size());
    rsa = PEM_read_bio_RSAPrivateKey(key, NULL, NULL, NULL);
    BIO_free_all(key);

    if (rsa == NULL)
    {
        throw std::runtime_error("Could not load private key");
    }

    int keylen = RSA_size(rsa);
    char* buffer = new char[keylen];
    int read = 0;
    while ((read = fread(buffer, 1, keylen, in)) > 0)
    {
        char* outbuffer = new char[keylen];
        RSA_private_decrypt(read, (unsigned char *)buffer, (unsigned char *)outbuffer, rsa, RSA_PKCS1_PADDING);
        fwrite(outbuffer, 1, keylen, out);
        delete[] outbuffer;
    }

    delete[] buffer;
    RSA_free(rsa);
    fclose(in);
    fclose(out);
}