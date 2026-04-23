cmake_minimum_required(VERSION 3.20)

project(Mnemonic VERSION 1.0.0)

# OpenSSL paths are passed in from mnemonic.sh via -D flags
# Fallback to a common path if not provided
if(NOT OPENSSL_ROOT_DIR)
    include_directories(../../libs/openssl-1.1.1w/include)
    link_directories(../../libs/openssl-1.1.1w/lib)
else()
    include_directories(${OPENSSL_INCLUDE_DIR})
    link_directories(${OPENSSL_ROOT_DIR}/lib)
endif()

include_directories(include)

## Library — includes bip39_passphrase.cpp which adds mnemonicFromPassphrase
## and passphraseFromMnemonic to libbip39.a.
## Note: bip39_wallet.cpp is NOT included here because it depends on DigitalNote-2
## wallet headers (wallet.h, crypter.h, key.h) which are not available in this
## cmake build context. bip39_wallet.cpp is compiled directly into the wallet
## binary via the Qt .pro build system.
add_library(bip39
    src/database.cpp
    src/util.cpp
    src/bip39/entropy.cpp
    src/bip39/checksum.cpp
    src/bip39/mnemonic.cpp
    src/bip39/seed.cpp
    src/bip39_passphrase.cpp
)
set_property(TARGET bip39 PROPERTY CXX_STANDARD 17)
target_link_libraries(bip39 ssl crypto)
install(TARGETS bip39 DESTINATION lib)

INSTALL (
    DIRECTORY ${CMAKE_SOURCE_DIR}/include/
    DESTINATION include
    FILES_MATCHING PATTERN "*.h*")

## App
add_executable(Mnemonic src/main.cpp)
set_property(TARGET Mnemonic PROPERTY CXX_STANDARD 17)
if(CMAKE_SYSTEM_NAME MATCHES "MINGW")
    target_link_libraries(Mnemonic bip39 ssl crypto ws2_32 stdc++)
else()
    target_link_libraries(Mnemonic bip39)
endif()

install(TARGETS Mnemonic DESTINATION bin)
