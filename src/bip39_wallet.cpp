// Copyright (c) 2024-2025 DigitalNote XDN developers
// Distributed under the MIT software license.
// SPDX-License-Identifier: MIT
//
// bip39_wallet.cpp — Bridge between CWallet and BIP39-Mnemonic library.

#include "bip39/bip39_wallet.h"

// BIP39-Mnemonic library headers (from DigitalNoteXDN/BIP39-Mnemonic)
#include "bip39/entropy.h"
#include "bip39/checksum.h"
#include "bip39/mnemonic.h"
#include "bip39/seed.h"
#include "database.h"   // BIP39::WordList

// DigitalNote-2 wallet headers
#include "wallet.h"
#include "crypter.h"
#include "key.h"
#include "util.h"

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <algorithm>
#include <cassert>

namespace BIP39Wallet {

// ── Helpers ─────────────────────────────────────────────────────────────────

const char* resultToString(Result r) noexcept
{
    switch (r) {
    case Result::OK:                    return "Success";
    case Result::ERR_WALLET_LOCKED:     return "Wallet is locked — please enter your passphrase";
    case Result::ERR_NO_HD_SEED:        return "No HD seed found — this may be a legacy wallet";
    case Result::ERR_ENTROPY_TOO_SHORT: return "HD seed is shorter than the requested mnemonic entropy";
    case Result::ERR_MNEMONIC_INVALID:  return "Mnemonic is invalid (checksum or word-list error)";
    case Result::ERR_OPENSSL:           return "OpenSSL cryptographic error";
    case Result::ERR_INTERNAL:          return "Unexpected internal error";
    }
    return "Unknown error";
}

// Convert WordCount → entropy byte count
static int entropyBytes(WordCount wc) noexcept
{
    return entropyBits(wc) / 8;
}

// Zero-fill a vector of bytes (secure erase)
static void secureErase(std::vector<uint8_t>& v)
{
    if (!v.empty()) {
        OPENSSL_cleanse(v.data(), v.size());
        v.clear();
    }
}

// ── generateMnemonic ─────────────────────────────────────────────────────────

Result generateMnemonic(const CWallet& wallet,
                        WordCount wordCount,
                        SecureString& mnemonic)
{
    mnemonic.clear();

    // 1. Verify wallet is unlocked and has an HD seed
    if (wallet.IsLocked())
        return Result::ERR_WALLET_LOCKED;

    // Retrieve the raw HD seed bytes
    // CWallet stores the HD seed as the key material of the HD master key.
    CHDChain hdChain;
    {
        LOCK(wallet.cs_wallet);
        if (!wallet.GetHDChain(hdChain))
            return Result::ERR_NO_HD_SEED;
    }

    // Decrypt the seed
    CKeyingMaterial seedKey;
    {
        LOCK(wallet.cs_wallet);
        if (!wallet.GetDecryptedHDSeed(hdChain, seedKey))
            return Result::ERR_WALLET_LOCKED;
    }

    const int needed = entropyBytes(wordCount);

    if (static_cast<int>(seedKey.size()) < needed) {
        OPENSSL_cleanse(seedKey.data(), seedKey.size());
        return Result::ERR_ENTROPY_TOO_SHORT;
    }

    // 2. Take the first `needed` bytes as BIP39 entropy
    std::vector<uint8_t> entropy(seedKey.begin(), seedKey.begin() + needed);
    OPENSSL_cleanse(seedKey.data(), seedKey.size());

    // 3. Generate mnemonic via BIP39-Mnemonic library
    try {
        // BIP39::Checksum appends the checksum bits to the entropy
        BIP39::Entropy ent(entropy);
        BIP39::Checksum cs(ent);
        BIP39::Mnemonic mn(cs, BIP39::WordList::English);

        const std::string words = mn.toString();
        mnemonic.assign(words.begin(), words.end());

        secureErase(entropy);
        return Result::OK;

    } catch (const std::exception& e) {
        LogPrintf("BIP39Wallet::generateMnemonic: exception: %s\n", e.what());
        secureErase(entropy);
        return Result::ERR_INTERNAL;
    }
}

// ── validateMnemonic ─────────────────────────────────────────────────────────

bool validateMnemonic(const SecureString& mnemonic)
{
    try {
        std::string words(mnemonic.begin(), mnemonic.end());
        return BIP39::Mnemonic::validate(words, BIP39::WordList::English);
    } catch (...) {
        return false;
    }
}

// ── restoreFromMnemonic ──────────────────────────────────────────────────────

Result restoreFromMnemonic(CWallet& wallet,
                           const SecureString& mnemonic,
                           const SecureString& passphrase)
{
    if (wallet.IsLocked())
        return Result::ERR_WALLET_LOCKED;

    // 1. Validate mnemonic first
    if (!validateMnemonic(mnemonic))
        return Result::ERR_MNEMONIC_INVALID;

    try {
        std::string words(mnemonic.begin(), mnemonic.end());
        std::string pass(passphrase.begin(), passphrase.end());

        // 2. Derive 512-bit BIP39 seed via PBKDF2-HMAC-SHA512
        //    salt = "mnemonic" + passphrase, iterations = 2048
        BIP39::Mnemonic mn = BIP39::Mnemonic::fromString(words, BIP39::WordList::English);
        BIP39::Seed seed(mn, pass);

        const std::vector<uint8_t>& seedBytes = seed.bytes(); // 64 bytes

        // 3. Set as wallet HD seed — reuses existing DigitalNote-2 HD path
        CKey hdSeedKey;
        hdSeedKey.Set(seedBytes.data(),
                      seedBytes.data() + seedBytes.size(),
                      /*fCompressedIn=*/true);

        {
            LOCK(wallet.cs_wallet);
            if (!wallet.SetHDSeed(hdSeedKey))
                return Result::ERR_INTERNAL;
        }

        // Secure erase locals
        OPENSSL_cleanse(const_cast<char*>(words.data()), words.size());
        OPENSSL_cleanse(const_cast<char*>(pass.data()),  pass.size());

        return Result::OK;

    } catch (const std::exception& e) {
        LogPrintf("BIP39Wallet::restoreFromMnemonic: exception: %s\n", e.what());
        return Result::ERR_INTERNAL;
    }
}


// ── mnemonicFromPassphrase ────────────────────────────────────────────────────
// Salt is fixed so the same passphrase always yields the same mnemonic.
// Different from BIP39 seed derivation — this is purely for recovery.
static const char* RECOVERY_SALT = "XDN-wallet-recovery-v1";
static const int   RECOVERY_ITERS = 2048;
static const int   RECOVERY_BYTES = 32;   // 256 bits → 24-word mnemonic

Result mnemonicFromPassphrase(const SecureString& passphrase,
                               SecureString& mnemonic)
{
    mnemonic.clear();

    if (passphrase.empty())
        return Result::ERR_INTERNAL;

    // PBKDF2-HMAC-SHA512: passphrase → 32 entropy bytes
    std::vector<uint8_t> entropy(RECOVERY_BYTES);
    int rc = PKCS5_PBKDF2_HMAC(
        passphrase.data(),
        static_cast<int>(passphrase.size()),
        reinterpret_cast<const unsigned char*>(RECOVERY_SALT),
        static_cast<int>(strlen(RECOVERY_SALT)),
        RECOVERY_ITERS,
        EVP_sha512(),
        RECOVERY_BYTES,
        entropy.data()
    );

    if (rc != 1) {
        OPENSSL_cleanse(entropy.data(), entropy.size());
        return Result::ERR_OPENSSL;
    }

    try {
        BIP39::Entropy ent(entropy);
        BIP39::Checksum cs(ent);
        BIP39::Mnemonic mn(cs, BIP39::WordList::English);
        const std::string words = mn.toString();
        mnemonic.assign(words.begin(), words.end());
        secureErase(entropy);
        return Result::OK;
    } catch (const std::exception& e) {
        LogPrintf("BIP39Wallet::mnemonicFromPassphrase: %s\n", e.what());
        secureErase(entropy);
        return Result::ERR_INTERNAL;
    }
}

// ── passphraseFromMnemonic ────────────────────────────────────────────────────

Result passphraseFromMnemonic(const SecureString& mnemonic,
                               SecureString& passphrase)
{
    passphrase.clear();

    if (!validateMnemonic(mnemonic))
        return Result::ERR_MNEMONIC_INVALID;

    try {
        std::string words(mnemonic.begin(), mnemonic.end());
        BIP39::Mnemonic mn = BIP39::Mnemonic::fromString(words, BIP39::WordList::English);

        // Extract raw entropy bytes (first 32 bytes for a 24-word mnemonic)
        // These are the same bytes we derived from the passphrase originally
        const std::vector<uint8_t> entropyBytes = mn.entropy();

        if (static_cast<int>(entropyBytes.size()) < RECOVERY_BYTES)
            return Result::ERR_INTERNAL;

        // Encode as lowercase hex — this is the passphrase used to encrypt
        static const char* hex = "0123456789abcdef";
        std::string hexPass;
        hexPass.reserve(RECOVERY_BYTES * 2);
        for (int i = 0; i < RECOVERY_BYTES; ++i) {
            hexPass += hex[(entropyBytes[i] >> 4) & 0xf];
            hexPass += hex[ entropyBytes[i]       & 0xf];
        }
        passphrase.assign(hexPass.begin(), hexPass.end());

        OPENSSL_cleanse(const_cast<char*>(hexPass.data()), hexPass.size());
        return Result::OK;

    } catch (const std::exception& e) {
        LogPrintf("BIP39Wallet::passphraseFromMnemonic: %s\n", e.what());
        return Result::ERR_INTERNAL;
    }
}

} // namespace BIP39Wallet
