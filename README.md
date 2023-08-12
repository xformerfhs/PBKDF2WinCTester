# PBKDF2WinCTester

> 💡 Originally, this repository was located in the [dbsystel](https://github.com/dbsystel) organization. With their kind permission, I moved it to my space in August 2023. The [original repository](https://github.com/dbsystel/PBKDF2WinCTester) is archived and no longer maintained.

This is an example program to test various PBKDF2 functions in C for Windows (Visual Studio). It was created to show 1. how to use the PBKDF2 functions in C to encode passwords and 2. to play with various parameters to see the result.

The program uses the Windows CNG Crypto API.

You need to add "bcrypt.lib" to the project properties under "Linker/Input/Additional Dependencies".

You can compile it as an ANSI or an UNICODE program. For this you need to set the character encoding under "General/Character Set" in the project properties. If it is set to "Not set" the ANSI version is compiled. If it is set to "Use Unicode Character Set" the UNICODE version is compiled.

The program is called with the following parameters:

```
PBKDF2.exe <hashType> <salt> <iterationCount> <password> [<doItRight>]
```
where the parameters have the following meanings:

| Parameter | Meaning |
| --------- | ------- |
| `hashType` | 1=SHA-1, 2=SHA-256, 3=SHA-384, 5=SHA-512 (Note: hashType 1 works on all Java versions. All other hashTypes are supported beginning with Java 8) |
| `salt` | The salt of the PBKDF2 function. The interpretation of this parameter depends on the presence of the `doItRight` parameter |
| `iterationCount` | The iteration count for the PBKDF2 function |
| `password` | The password that is used in the PBKDF2 function |
| `doItRight` | If there is any parameter following the password the salt is treated as a byte array. If there is nothing following the password the salt is treated as an integer |

The program has 2 modi. In the first modus (the "wrong" modus) it interprets the "salt" as an integer. This is a common misconception and found quite often on the internet. Also, the password is hashed with the current encoding, i.e. ANSI for the ANSI version and UTF-16 for the Unicode version.

In the second modus it interprets the "salt" as a byte array which is the correct way to handle it. Also, the passwod is converted to UTF-8 before it is hashed.

Here are some examples:

```
PBKDF2.exe 1 81726354 123456 Veyron
```

With the ANSI version this yields

```
HashType: SHA1, Salt: 81726354, IterationCount: 123456, Password: 'Veyron', PBKDF2: AA EE AF 51 9E B8 14 9C 40 1E F0 AF FC DB F4 D8 D0 E0 1B AD
Duration: 123 ms
```

With the UNICODE version this yields

```
HashType: SHA1, Salt: 81726354, IterationCount: 123456, Password: 'Veyron', PBKDF2: A6 C1 3A 24 9F 8C 05 8B E4 50 F9 EC 67 60 D5 51 51 42 E3 54
Duration: 126 ms
```

Note, that both calculations are wrong as the salt is interpreted as an integer and the password is hashed in the ANSI, or UNICODE encoding. Here is the correct version where the salt is interpreted as a byted array and the password is converted to UTF-8 before it is hashed:

```
PBKDF2.exe 1 04df0b92 123456 Veyron x
```

which yields

```
HashType: SHA1, Salt: 04 DF 0B 92, IterationCount: 123456, Password: 'Veyron', PBKDF2: 57 60 62 1F 2C 20 23 57 87 08 9D 40 4B 9D 26 EA B0 6B 9B C6
Duration: 127 ms
```

## Contributing

Feel free to submit a pull request with new features, improvements on tests or documentation and bug fixes.

## Contact

Frank Schwab ([Mail](mailto:frank.schwab@deutschebahn.com "Mail"))

## License

PBKDF2WinCTester is released under the 2-clause BSD license. See "LICENSE" for details.
