#pragma once
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <string>
#include <vector>

class Encryptool
{
public:
    Encryptool();

    void GenerateKeyPair(std::string const &keypath);
    void LoadKeys(std::string const &keypath);

    void EncryptFile(std::string const &inpath, std::string const &outpath);
    void DecryptFile(std::string const &inpath, std::string const &outpath);


private:
    void LoadPrivKey(std::string const &keypath);
    void LoadPubKey(std::string const &keypath);

    void WriteFile(std::string const& filename, char const* data, size_t len);

private:
    std::vector<char> m_priv_key;
    std::vector<char> m_pub_key;

};