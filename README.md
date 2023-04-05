# encryptool

`encryptool` is an easy to use encrypt/decrypt tool using rsa based on OpenSSL library.

The project is aimed to serve as an example of how to use Boost::program_options library and OpenSSL::crypto library.

While it does work, it's not recommended for production use.

# how to build

`encryptool` is configured with CMake. The CMakeLists.txt file has been modified for cross-platform usage.

## Linux

```bash
cd path/to/project
cmake -H. -Bbuild -G Ninja 
ninja -C build
```

## Windows

You can pretty much do the same, but it's encouraged to do it in vscode or other IDE that can provide fine-grained control over the build environment.

# how to use
```bash
C:\Users\wbval\source\repos\encryptool> .\build\encryptool.exe --help
Temp dir: C:\Users\wbval\AppData\Local\Temp\key
Allowed options:
  --help                                produce help message
  -k [ --key ] arg                      path to key file, when encrypting or
                                        decrypting, give path to key file ;
  -g [ --generate ]                     generate key pairs and exit ;
  -e [ --encrypt ] arg                  path to file to encrypt, defaults to
                                        /tmp/<infile_name>.enc; require --key
                                        options given pubkey file;
  -d [ --decrypt ] arg                  path to file to decrypt, defaults to
                                        /tmp/<infile_name>.dec; require --key
                                        options given privkey file;
  -o [ --out ] arg (=C:\Users\wbval\AppData\Local\Temp\key)
                                        path to output file. If not given,
                                        defaults to fs::temp_directory_path();
```
