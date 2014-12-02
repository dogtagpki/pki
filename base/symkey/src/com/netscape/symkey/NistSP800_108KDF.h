/*
 * NistSP800_108KDF.H  -  Implements the new Key Diversification Function (KDF) as required
 *                        by the latest Department of Defense SIPRnet token interface
 *                        specification.  The functions in this file are internally called
 *                        by other functions in the Symkey library.  We have made patches
 *                        to these other Symkey functions to trigger this new KDF routine
 *                        at the appropriate times.
 *
 *                        Also provides a utility function for adding DES key parity.
 */

#ifndef NISTSP800_108KDF_H_
#define NISTSP800_108KDF_H_

//*******************************************************************************
//   Defines
//*******************************************************************************
// Debug Flag - Enabling this includes <iostream> and results in the  NIST SP800-108
//              KDF code printing out lots of stuff (including key material!) to stdout.
//#define NISTSP800_108_KDF_DEBUG 1

//*******************************************************************************
//   Includes
//*******************************************************************************
#include <cstddef>   // typedef size_t
#include <stdexcept> // std::runtime_error

#include "pk11pub.h"

#include "Base.h"    // typedef BYTE

//*******************************************************************************

namespace NistSP800_108KDF{

//*******************************************************************************
//   Constants
//*******************************************************************************

// might already be defined by NSS
#ifndef SHA256_LENGTH
#define SHA256_LENGTH 32
#endif

// AC: don't change any of these constants without validating the code that uses them
const size_t KDF_OUTPUT_SIZE_BITS = 384;
const size_t KDF_OUTPUT_SIZE_BYTES = KDF_OUTPUT_SIZE_BITS / 8;
const size_t KEY_DATA_SIZE_BYTES = KDF_OUTPUT_SIZE_BYTES / 3;

const size_t KDD_SIZE_BYTES = 10;   // expected KDD field length in bytes

const BYTE KDF_LABEL = 0x04; // arbitrary input to crypto routine (see documentation)

//*******************************************************************************
//   Function Headers
//*******************************************************************************

// Generates three PK11SymKey objects using the KDF_CM_SHA256HMAC_L384() function for key data.
// After calling KDF_CM_SHA256HMAC_L384, the function splits up the output, sets DES parity,
//   and imports the keys into the token.
//
// Careful:  This function currently generates the key data **IN RAM** using calls to NSS sha256.
//           The key data is then "unwrapped" (imported) to the NSS token and then erased from RAM.
//           (This means that a malicious actor on the box could steal the key data.)
//
// Note: Returned key material from the KDF is converted into keys according to the following:
//   * Bytes 0  - 15 : enc/auth key
//   * Bytes 16 - 31 : mac key
//   * Bytes 32 - 47 : kek key
//   We chose this order to conform with the key order used by the PUT KEY command.
void ComputeCardKeys(  PK11SymKey* masterKey,               // Key Derivation Key
                       const BYTE* context,                 // unique data passed to the kdf (kdd)
                       const size_t context_length,         // length of context
                       PK11SymKey** encKey,                 // output parameter: generated enc/auth key
                       PK11SymKey** macKey,                 // output parameter: generated mac key
                       PK11SymKey** kekKey);                // output parameter: generated kek key

// uses the specified temporary key to encrypt and then unwrap (decrypt) the specified binary data onto the specified token
// this has the net effect of copying the raw key data to the token
PK11SymKey* Copy2Key3DESKeyDataToToken( PK11SlotInfo* slot,      // slot to unwrap key onto
                                        PK11SymKey* tmpKey,      // temporary key to use (must already be on the slot)
                                        const BYTE* const data,  // pointer to array containing the key data to encrypt and then unwrap (decrypt) on the token
                                        const size_t data_len);  // length of data in above array

// calculates 384 bits of diversified output from the provided master key (K_I)
void KDF_CM_SHA256HMAC_L384(  PK11SymKey* K_I,                     // Key Derivation Key
                              const BYTE* context,                 // unique data passed to the kdf (kdd)
                              const size_t context_length,         // length of context
                              const BYTE label,                    // one BYTE label parameter
                              BYTE* const output,                  // output is a L-bit array of BYTEs
                              const size_t output_length);         // output length must be at least 48 bytes

void SHA256HMAC(     PK11SymKey* key,                     // HMAC Secret Key (K_I)
                     const BYTE* input,                   // HMAC Input (i||04||00||context||0180)
                     const size_t input_length,           // Input Length
                     BYTE* const output);                 // Output Buffer (32 BYTES written)

/* DES KEY Parity conversion table. Takes each byte >> 1 as an index, returns
 * that byte with the proper parity bit set*/
void set_des_parity(BYTE* const key, const size_t length);

#ifdef NISTSP800_108_KDF_DEBUG
void print_BYTE_array(const BYTE *array2, const size_t len);
#endif

// Returns true if the new KDF should be used, otherwise false.
bool useNistSP800_108KDF(BYTE nistSP800_108KDFonKeyVersion, BYTE requestedKeyVersion);

//*******************************************************************************

} // end namespace NistSP800_108KDF

//*******************************************************************************

#endif /* NISTSP800_108KDF_H_ */
