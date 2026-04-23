// Copyright (c) 2024-2025 DigitalNote XDN developers
// Distributed under the MIT software license.
// SPDX-License-Identifier: MIT
//
// bip39_wallet.h
// Bridge between DigitalNote-2's CWallet and the BIP39-Mnemonic library.
// Handles entropy extraction from the HD keychain seed, mnemonic generation,
// mnemonic validation, and seed restoration.
//
// Security contract
// -----------------
//  * Mnemonic strings are stored in SecureString (locked memory) and cleared
//    immediately after use.
//  * This class never writes the mnemonic to disk.
//  * The GUI must request wallet unlock before calling any method that touches
//    the private key material.

#pragma once

#include <string>
#include <vector>
#include <cstdint>

// Forward declarations — avoid including heavy wallet headers here
class CWallet;
class CKeyingMaterial;

// SecureString from Bitcoin — zero-fills on destruction
typedef std::basic_string<char,
    std::char_traits<char>,
    secure_allocator<char>> SecureString;

namespace BIP39Wallet {

/**
 * @brief Word-count options supported by BIP39.
 *
 * Maps directly to entropy bit sizes:
 *   Words12 → 128-bit entropy
 *   Words15 → 160-bit entropy
 *   Words18 → 192-bit entropy
 *   Words21 → 224-bit entropy
 *   Words24 → 256-bit entropy  ← recommended for maximum security
 */
enum class WordCount : int {
    Words12 = 12,
    Words15 = 15,
    Words18 = 18,
    Words21 = 21,
    Words24 = 24,
};

/**
 * @brief Result codes returned by BIP39Wallet functions.
 */
enum class Result {
    OK,
    ERR_WALLET_LOCKED,       ///< Wallet passphrase not entered
    ERR_NO_HD_SEED,          ///< Wallet has no HD seed (legacy wallet)
    ERR_ENTROPY_TOO_SHORT,   ///< HD seed shorter than requested mnemonic entropy
    ERR_MNEMONIC_INVALID,    ///< Mnemonic checksum or word-list validation failed
    ERR_OPENSSL,             ///< Underlying OpenSSL error
    ERR_INTERNAL,            ///< Unexpected internal error
};

/** Human-readable description of a Result code. */
const char* resultToString(Result r) noexcept;

/**
 * @brief Generate a BIP39 mnemonic from the wallet's HD seed.
 *
 * The wallet must be unlocked.  The first (entropyBits / 8) bytes of the
 * HD seed are used as entropy — identical to how Trezor/Ledger devices
 * derive their recovery phrase from a hardware-generated seed.
 *
 * @param wallet       Open, unlocked CWallet instance.
 * @param wordCount    Desired mnemonic length (default: Words24).
 * @param[out] mnemonic  Space-separated word list written here on success.
 *                       Cleared on failure.
 * @return Result::OK on success, error code otherwise.
 */
Result generateMnemonic(const CWallet& wallet,
                        WordCount wordCount,
                        SecureString& mnemonic);

/**
 * @brief Validate a BIP39 mnemonic (checksum + word-list check).
 *
 * Does not touch the wallet.  Safe to call without unlock.
 *
 * @param mnemonic   Space-separated word list to validate.
 * @return true if the mnemonic is valid according to BIP39.
 */
bool validateMnemonic(const SecureString& mnemonic);

/**
 * @brief Restore a wallet HD seed from a BIP39 mnemonic.
 *
 * Derives the 512-bit BIP39 seed via PBKDF2-HMAC-SHA512 with 2048 iterations,
 * then sets it as the wallet's HD seed using the existing SetHDSeed() path.
 *
 * @param wallet      Open, unlocked CWallet instance.
 * @param mnemonic    Valid BIP39 mnemonic (Words12–Words24).
 * @param passphrase  Optional BIP39 passphrase (empty string = no passphrase).
 * @return Result::OK on success, error code otherwise.
 */
Result restoreFromMnemonic(CWallet& wallet,
                           const SecureString& mnemonic,
                           const SecureString& passphrase = SecureString());

/**
 * @brief Return the entropy bit-count for a given word count.
 */
constexpr int entropyBits(WordCount wc) noexcept {
    return (static_cast<int>(wc) * 11 * 32) / 33;
    // Derivation: totalBits = words * 11; CS = totalBits / 33; ENT = totalBits - CS
}


/**
 * @brief Derive a 24-word BIP39 recovery mnemonic from a wallet passphrase.
 *
 * Uses PBKDF2-HMAC-SHA512 to derive 32 bytes of entropy from the passphrase,
 * then encodes those bytes as a 24-word BIP39 mnemonic.  The same passphrase
 * always produces the same mnemonic, so this can be reversed with
 * passphraseFromMnemonic().
 *
 * This does NOT touch the wallet or any key material.
 *
 * @param passphrase   The wallet encryption passphrase chosen by the user.
 * @param[out] mnemonic  The 24-word recovery phrase on success.
 * @return Result::OK on success, Result::ERR_OPENSSL on derivation failure.
 */
Result mnemonicFromPassphrase(const SecureString& passphrase,
                               SecureString& mnemonic);

/**
 * @brief Recover the wallet passphrase from a 24-word BIP39 recovery mnemonic.
 *
 * Reverses mnemonicFromPassphrase(): extracts the 32 entropy bytes from the
 * mnemonic and returns them encoded as a 64-char hex string — which is the
 * passphrase that was used to encrypt the wallet.
 *
 * @param mnemonic       The 24-word recovery phrase.
 * @param[out] passphrase  The recovered passphrase on success.
 * @return Result::OK on success, Result::ERR_MNEMONIC_INVALID if mnemonic
 *         is not a valid BIP39 phrase, Result::ERR_INTERNAL otherwise.
 */
Result passphraseFromMnemonic(const SecureString& mnemonic,
                               SecureString& passphrase);

} // namespace BIP39Wallet
