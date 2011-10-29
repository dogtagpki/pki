// --- BEGIN COPYRIGHT BLOCK ---
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation;
// version 2.1 of the License.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor,
// Boston, MA  02110-1301  USA 
// 
// Copyright (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

/* nscperrors.c
 * Very crude error handling for nspr and libsec.
 */

#include "prerror.h"

#define NSCP_NSPR_ERROR_BASE            (PR_NSPR_ERROR_BASE)
#define NSCP_NSPR_MAX_ERROR             ((PR_MAX_ERROR) - 1)
#define NSCP_LIBSEC_ERROR_BASE 		(-8192)
#define NSCP_LIBSEC_MAX_ERROR           (NSCP_LIBSEC_ERROR_BASE + 118)
#define NSCP_LIBSSL_ERROR_BASE 		(-12288)
#define NSCP_LIBSSL_MAX_ERROR           (NSCP_LIBSSL_ERROR_BASE + 89)

typedef struct nscp_error_t {
    int errorNumber;
    const char *errorString;
} nscp_error_t;

nscp_error_t nscp_nspr_errors[]  =  {
    {  0, "Out of memory" },
    {  1, "Bad file descriptor" },
    {  2, "Data temporarily not available" },
    {  3, "Access fault" },
    {  4, "Invalid method" },
    {  5, "Illegal access" },
    {  6, "Unknown error" },
    {  7, "Pending interrupt" },
    {  8, "Not implemented" },
    {  9, "IO error" },
    { 10, "IO timeout error" },
    { 11, "IO already pending error" },
    { 12, "Directory open error" },
    { 13, "Invalid Argument" },
    { 14, "Address not available" },
    { 15, "Address not supported" },
    { 16, "Already connected" },
    { 17, "Bad address" },
    { 18, "Address already in use" },
    { 19, "Connection refused" },
    { 20, "Network unreachable" },
    { 21, "Connection timed out" },
    { 22, "Not connected" },
    { 23, "Load library error" },
    { 24, "Unload library error" },
    { 25, "Find symbol error" },
    { 26, "Insufficient resources" },
    { 27, "Directory lookup error" },
    { 28, "Invalid thread private data key" },
    { 29, "PR_PROC_DESC_TABLE_FULL_ERROR" },
    { 30, "PR_SYS_DESC_TABLE_FULL_ERROR" },
    { 31, "Descriptor is not a socket" },
    { 32, "Descriptor is not a TCP socket" },
    { 33, "Socket address is already bound" },
    { 34, "No access rights" },
    { 35, "Operation not supported" },
    { 36, "Protocol not supported" },
    { 37, "Remote file error" },
    { 38, "Buffer overflow error" },
    { 39, "Connection reset by peer" },
    { 40, "Range error" },
    { 41, "Deadlock error" },
    { 42, "File is locked" },
    { 43, "File is too big" },
    { 44, "No space on device" },
    { 45, "Pipe error" },
    { 46, "No seek on device" },
    { 47, "File is a directory" },
    { 48, "Loop error" },
    { 49, "Name too long" },
    { 50, "File not found" },
    { 51, "File is not a directory" },
    { 52, "Read-only filesystem" },
    { 53, "Directory not empty" },
    { 54, "Filesystem mounted" },
    { 55, "Not same device" },
    { 56, "Directory corrupted" },
    { 57, "File exists" },
    { 58, "Maximum directory entries" },
    { 59, "Invalid device state" },
    { 60, "Device is locked" },
    { 61, "No more files" },
    { 62, "End of file" },
    { 63, "File seek error" },
    { 64, "File is busy" },
    { 65, "NSPR error 65" },
    { 66, "In progress error" },
    { 67, "Already initiated" },
    { 68, "Group empty" },
    { 69, "Invalid state" },
    { 70, "Network down" },
    { 71, "Socket shutdown" },
    { 72, "Connect aborted" },
    { 73, "Host unreachable" }
};

#if (PR_MAX_ERROR - PR_NSPR_ERROR_BASE) > 74
// cfu temporarily get rid of the "#error NSPR error table is too small" error
//#error NSPR error table is too small
#endif

nscp_error_t nscp_libsec_errors[] = {
    {  0, "SEC_ERROR_IO - I/O Error" },
    {  1, "SEC_ERROR_LIBRARY_FAILURE - Library Failure" },
    {  2, "SEC_ERROR_BAD_DATA - Bad data was received" },
    {  3, "SEC_ERROR_OUTPUT_LEN" },
    {  4, "SEC_ERROR_INPUT_LEN" },
    {  5, "SEC_ERROR_INVALID_ARGS" },
    {  6, "SEC_ERROR_INVALID_ALGORITHM - Certificate contains invalid encryption or signature algorithm" },
    {  7, "SEC_ERROR_INVALID_AVA" },
    {  8, "SEC_ERROR_INVALID_TIME - Certificate contains an invalid time value" },
    {  9, "SEC_ERROR_BAD_DER - Certificate is improperly DER encoded" },
    { 10, "SEC_ERROR_BAD_SIGNATURE - Certificate has invalid signature" },
    { 11, "SEC_ERROR_EXPIRED_CERTIFICATE - Certificate has expired" },
    { 12, "SEC_ERROR_REVOKED_CERTIFICATE - Certificate has been revoked" },
    { 13, "SEC_ERROR_UNKNOWN_ISSUER - Certificate is signed by an unknown issuer" },
    { 14, "SEC_ERROR_BAD_KEY - Invalid public key in certificate." },
    { 15, "SEC_ERROR_BAD_PASSWORD" },
    { 16, "SEC_ERROR_UNUSED" },
    { 17, "SEC_ERROR_NO_NODELOCK" },
    { 18, "SEC_ERROR_BAD_DATABASE - Problem using certificate or key database" },
    { 19, "SEC_ERROR_NO_MEMORY - Out of Memory" },
    { 20, "SEC_ERROR_UNTRUSTED_ISSUER - Certificate is signed by an untrusted issuer" },
    { 21, "SEC_ERROR_UNTRUSTED_CERT" },
    { 22, "SEC_ERROR_DUPLICATE_CERT" },
    { 23, "SEC_ERROR_DUPLICATE_CERT_TIME" },
    { 24, "SEC_ERROR_ADDING_CERT" },
    { 25, "SEC_ERROR_FILING_KEY" },
    { 26, "SEC_ERROR_NO_KEY" },
    { 27, "SEC_ERROR_CERT_VALID" },
    { 28, "SEC_ERROR_CERT_NOT_VALID" },
    { 29, "SEC_ERROR_CERT_NO_RESPONSE" },
    { 30, "SEC_ERROR_EXPIRED_ISSUER_CERTIFICATE" },
    { 31, "SEC_ERROR_CRL_EXPIRED" },
    { 32, "SEC_ERROR_CRL_BAD_SIGNATURE" },
    { 33, "SEC_ERROR_CRL_INVALID" },
    { 34, "SEC_ERROR_EXTENSION_VALUE_INVALID" },
    { 35, "SEC_ERROR_EXTENSION_NOT_FOUND" },
    { 36, "SEC_ERROR_CA_CERT_INVALID" },
    { 37, "SEC_ERROR_PATH_LEN_CONSTRAINT_INVALID" },
    { 38, "SEC_ERROR_CERT_USAGES_INVALID" },
    { 39, "SEC_INTERNAL_ONLY" },
    { 40, "SEC_ERROR_INVALID_KEY" },
    { 41, "SEC_ERROR_UNKNOWN_CRITICAL_EXTENSION" },
    { 42, "SEC_ERROR_OLD_CRL" },
    { 43, "SEC_ERROR_NO_EMAIL_CERT" },
    { 44, "SEC_ERROR_NO_RECIPIENT_CERTS_QUERY" },
    { 45, "SEC_ERROR_NOT_A_RECIPIENT" },
    { 46, "SEC_ERROR_PKCS7_KEYALG_MISMATCH" },
    { 47, "SEC_ERROR_PKCS7_BAD_SIGNATURE" },
    { 48, "SEC_ERROR_UNSUPPORTED_KEYALG" },
    { 49, "SEC_ERROR_DECRYPTION_DISALLOWED" },
    { 50, "XP_SEC_FORTEZZA_BAD_CARD" },
    { 51, "XP_SEC_FORTEZZA_NO_CARD" },
    { 52, "XP_SEC_FORTEZZA_NONE_SELECTED" },
    { 53, "XP_SEC_FORTEZZA_MORE_INFO" },
    { 54, "XP_SEC_FORTEZZA_PERSON_NOT_FOUND" },
    { 55, "XP_SEC_FORTEZZA_NO_MORE_INFO" },
    { 56, "XP_SEC_FORTEZZA_BAD_PIN" },
    { 57, "XP_SEC_FORTEZZA_PERSON_ERROR" },
    { 58, "SEC_ERROR_NO_KRL" },
    { 59, "SEC_ERROR_KRL_EXPIRED" },
    { 60, "SEC_ERROR_KRL_BAD_SIGNATURE" },
    { 61, "SEC_ERROR_REVOKED_KEY" },
    { 62, "SEC_ERROR_KRL_INVALID" },
    { 63, "SEC_ERROR_NEED_RANDOM" },
    { 64, "SEC_ERROR_NO_MODULE" },
    { 65, "SEC_ERROR_NO_TOKEN" },
    { 66, "SEC_ERROR_READ_ONLY" },
    { 67, "SEC_ERROR_NO_SLOT_SELECTED" },
    { 68, "SEC_ERROR_CERT_NICKNAME_COLLISION" },
    { 69, "SEC_ERROR_KEY_NICKNAME_COLLISION" },
    { 70, "SEC_ERROR_SAFE_NOT_CREATED" },
    { 71, "SEC_ERROR_BAGGAGE_NOT_CREATED" },
    { 72, "XP_JAVA_REMOVE_PRINCIPAL_ERROR" },
    { 73, "XP_JAVA_DELETE_PRIVILEGE_ERROR" },
    { 74, "XP_JAVA_CERT_NOT_EXISTS_ERROR" },
    { 75, "SEC_ERROR_BAD_EXPORT_ALGORITHM" },
    { 76, "SEC_ERROR_EXPORTING_CERTIFICATES" },
    { 77, "SEC_ERROR_IMPORTING_CERTIFICATES" },
    { 78, "SEC_ERROR_PKCS12_DECODING_PFX" },
    { 79, "SEC_ERROR_PKCS12_INVALID_MAC" },
    { 80, "SEC_ERROR_PKCS12_UNSUPPORTED_MAC_ALGORITHM" },
    { 81, "SEC_ERROR_PKCS12_UNSUPPORTED_TRANSPORT_MODE" },
    { 82, "SEC_ERROR_PKCS12_CORRUPT_PFX_STRUCTURE" },
    { 83, "SEC_ERROR_PKCS12_UNSUPPORTED_PBE_ALGORITHM" },
    { 84, "SEC_ERROR_PKCS12_UNSUPPORTED_VERSION" },
    { 85, "SEC_ERROR_PKCS12_PRIVACY_PASSWORD_INCORRECT" },
    { 86, "SEC_ERROR_PKCS12_CERT_COLLISION" },
    { 87, "SEC_ERROR_USER_CANCELLED" },
    { 88, "SEC_ERROR_PKCS12_DUPLICATE_DATA" },
    { 89, "SEC_ERROR_MESSAGE_SEND_ABORTED" },
    { 90, "SEC_ERROR_INADEQUATE_KEY_USAGE" },
    { 91, "SEC_ERROR_INADEQUATE_CERT_TYPE" },
    { 92, "SEC_ERROR_CERT_ADDR_MISMATCH" },
    { 93, "SEC_ERROR_PKCS12_UNABLE_TO_IMPORT_KEY" },
    { 94, "SEC_ERROR_PKCS12_IMPORTING_CERT_CHAIN" },
    { 95, "SEC_ERROR_PKCS12_UNABLE_TO_LOCATE_OBJECT_BY_NAME" },
    { 96, "SEC_ERROR_PKCS12_UNABLE_TO_EXPORT_KEY" },
    { 97, "SEC_ERROR_PKCS12_UNABLE_TO_WRITE" },
    { 98, "SEC_ERROR_PKCS12_UNABLE_TO_READ" },
    { 99, "SEC_ERROR_PKCS12_KEY_DATABASE_NOT_INITIALIZED" },
    { 100, "SEC_ERROR_KEYGEN_FAIL" },
    { 101, "SEC_ERROR_INVALID_PASSWORD" },
    { 102, "SEC_ERROR_RETRY_OLD_PASSWORD" },
    { 103, "SEC_ERROR_BAD_NICKNAME" },
    { 104, "SEC_ERROR_NOT_FORTEZZA_ISSUER" },
    { 105, "unused error" },
    { 106, "SEC_ERROR_JS_INVALID_MODULE_NAME" },
    { 107, "SEC_ERROR_JS_INVALID_DLL" },
    { 108, "SEC_ERROR_JS_ADD_MOD_FAILURE" },
    { 109, "SEC_ERROR_JS_DEL_MOD_FAILURE" },
    { 110, "SEC_ERROR_OLD_KRL" },
    { 111, "SEC_ERROR_CKL_CONFLICT" },
    { 112, "SEC_ERROR_CERT_NOT_IN_NAME_SPACE" },
    { 113, "SEC_ERROR_KRL_NOT_YET_VALID" },
    { 114, "SEC_ERROR_CRL_NOT_YET_VALID" },
    { 115, "SEC_ERROR_CERT_STATUS_SERVER_ERROR" },
    { 116, "SEC_ERROR_CERT_STATUS_UNKNOWN" },
    { 117, "SEC_ERROR_CERT_REVOKED_SINCE" },
    { 118, "SEC_ERROR_OCSP_UNKNOWN_RESPONSE_TYPE" }
};

nscp_error_t nscp_libssl_errors[] = {
    {  0, "SSL_ERROR_EXPORT_ONLY_SERVER - client does not support high-grade encryption." },
    {  1, "SSL_ERROR_US_ONLY_SERVER - client requires high-grade encryption which is not supported." },
    {  2, "SSL_ERROR_NO_CYPHER_OVERLAP - no common encryption algorithm(s) with client." },
    {  3, "SSL_ERROR_NO_CERTIFICATE - unable to find the certificate or key necessary for authentication." },
    {  4, "SSL_ERROR_BAD_CERTIFICATE - unable to communicate securely wih peer: peer's certificate was rejected." },
    {  5, "unused SSL error #5" },
    {  6, "SSL_ERROR_BAD_CLIENT - protocol error." },
    {  7, "SSL_ERROR_BAD_SERVER - protocol error." },
    {  8, "SSL_ERROR_UNSUPPORTED_CERTIFICATE_TYPE - unsupported certificate type." },
    {  9, "SSL_ERROR_UNSUPPORTED_VERSION - client is using unsupported SSL version." },
    { 10, "unused SSL error #10" },
    { 11, "SSL_ERROR_WRONG_CERTIFICATE - the public key in the server's own certificate does not match its private key" },
    { 12, "SSL_ERROR_BAD_CERT_DOMAIN - requested domain name does not match the server's certificate." },
    { 13, "SSL_ERROR_POST_WARNING" },
    { 14, "SSL_ERROR_SSL2_DISABLED - peer only supports SSL version 2, which is locally disabled" },
    { 15, "SSL_ERROR_BAD_MAC_READ - SSL has received a record with an incorrect Message Authentication Code." },
    { 16, "SSL_ERROR_BAD_MAC_ALERT - SSL has received an error indicating an incorrect Message Authentication Code." },
    { 17, "SSL_ERROR_BAD_CERT_ALERT - SSL client cannot verify your certificate." },
    { 18, "SSL_ERROR_REVOKED_CERT_ALERT - the server has rejected your certificate as revoked." },
    { 19, "SSL_ERROR_EXPIRED_CERT_ALERT - the server has rejected your certificate as expired." },
    { 20, "SSL_ERROR_SSL_DISABLED - cannot connect: SSL is disabled." },
    { 21, "SSL_ERROR_FORTEZZA_PQG - cannot connect: SSL peer is in another Fortezza domain" },
    { 22, "SSL_ERROR_UNKNOWN_CIPHER_SUITE - an unknown SSL cipher suite has been requested" },
    { 23, "SSL_ERROR_NO_CIPHERS_SUPPORTED - no cipher suites are present and enabled in this program" },
    { 24, "SSL_ERROR_BAD_BLOCK_PADDING" },
    { 25, "SSL_ERROR_RX_RECORD_TOO_LONG" },
    { 26, "SSL_ERROR_TX_RECORD_TOO_LONG" },
    { 27, "SSL_ERROR_RX_MALFORMED_HELLO_REQUEST" },
    { 28, "SSL_ERROR_RX_MALFORMED_CLIENT_HELLO" },
    { 29, "SSL_ERROR_RX_MALFORMED_SERVER_HELLO" },
    { 30, "SSL_ERROR_RX_MALFORMED_CERTIFICATE" },
    { 31, "SSL_ERROR_RX_MALFORMED_SERVER_KEY_EXCH" },
    { 32, "SSL_ERROR_RX_MALFORMED_CERT_REQUEST" },
    { 33, "SSL_ERROR_RX_MALFORMED_HELLO_DONE" },
    { 34, "SSL_ERROR_RX_MALFORMED_CERT_VERIFY" },
    { 35, "SSL_ERROR_RX_MALFORMED_CLIENT_KEY_EXCH" },
    { 36, "SSL_ERROR_RX_MALFORMED_FINISHED" },
    { 37, "SSL_ERROR_RX_MALFORMED_CHANGE_CIPHER" },
    { 38, "SSL_ERROR_RX_MALFORMED_ALERT" },
    { 39, "SSL_ERROR_RX_MALFORMED_HANDSHAKE" },
    { 40, "SSL_ERROR_RX_MALFORMED_APPLICATION_DATA" },
    { 41, "SSL_ERROR_RX_UNEXPECTED_HELLO_REQUEST" },
    { 42, "SSL_ERROR_RX_UNEXPECTED_CLIENT_HELLO" },
    { 43, "SSL_ERROR_RX_UNEXPECTED_SERVER_HELLO" },
    { 44, "SSL_ERROR_RX_UNEXPECTED_CERTIFICATE" },
    { 45, "SSL_ERROR_RX_UNEXPECTED_SERVER_KEY_EXCH" },
    { 46, "SSL_ERROR_RX_UNEXPECTED_CERT_REQUEST" },
    { 47, "SSL_ERROR_RX_UNEXPECTED_HELLO_DONE" },
    { 48, "SSL_ERROR_RX_UNEXPECTED_CERT_VERIFY" },
    { 49, "SSL_ERROR_RX_UNEXPECTED_CLIENT_KEY_EXCH" },
    { 50, "SSL_ERROR_RX_UNEXPECTED_FINISHED" },
    { 51, "SSL_ERROR_RX_UNEXPECTED_CHANGE_CIPHER" },
    { 52, "SSL_ERROR_RX_UNEXPECTED_ALERT" },
    { 53, "SSL_ERROR_RX_UNEXPECTED_HANDSHAKE" },
    { 54, "SSL_ERROR_RX_UNEXPECTED_APPLICATION_DATA" },
    { 55, "SSL_ERROR_RX_UNKNOWN_RECORD_TYPE" },
    { 56, "SSL_ERROR_RX_UNKNOWN_HANDSHAKE" },
    { 57, "SSL_ERROR_RX_UNKNOWN_ALERT" },
    { 58, "SSL_ERROR_CLOSE_NOTIFY_ALERT - SSL peer has closed the connection" },
    { 59, "SSL_ERROR_HANDSHAKE_UNEXPECTED_ALERT" },
    { 60, "SSL_ERROR_DECOMPRESSION_FAILURE_ALERT" },
    { 61, "SSL_ERROR_HANDSHAKE_FAILURE_ALERT" },
    { 62, "SSL_ERROR_ILLEGAL_PARAMETER_ALERT" },
    { 63, "SSL_ERROR_UNSUPPORTED_CERT_ALERT" },
    { 64, "SSL_ERROR_CERTIFICATE_UNKNOWN_ALERT" },
    { 65, "SSL_ERROR_GENERATE_RANDOM_FAILURE" },
    { 66, "SSL_ERROR_SIGN_HASHES_FAILURE" },
    { 67, "SSL_ERROR_EXTRACT_PUBLIC_KEY_FAILURE" },
    { 68, "SSL_ERROR_SERVER_KEY_EXCHANGE_FAILURE" },
    { 69, "SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE" },
    { 70, "SSL_ERROR_ENCRYPTION_FAILURE" },
    { 71, "SSL_ERROR_DECRYPTION_FAILURE" },
    { 72, "SSL_ERROR_SOCKET_WRITE_FAILURE" },
    { 73, "SSL_ERROR_MD5_DIGEST_FAILURE" },
    { 74, "SSL_ERROR_SHA_DIGEST_FAILURE" },
    { 75, "SSL_ERROR_MAC_COMPUTATION_FAILURE" },
    { 76, "SSL_ERROR_SYM_KEY_CONTEXT_FAILURE" },
    { 77, "SSL_ERROR_SYM_KEY_UNWRAP_FAILURE" },
    { 78, "SSL_ERROR_PUB_KEY_SIZE_LIMIT_EXCEEDED" },
    { 79, "SSL_ERROR_IV_PARAM_FAILURE" },
    { 80, "SSL_ERROR_INIT_CIPHER_SUITE_FAILURE" },
    { 81, "SSL_ERROR_SESSION_KEY_GEN_FAILURE" },
    { 82, "SSL_ERROR_NO_SERVER_KEY_FOR_ALG" },
    { 83, "SSL_ERROR_TOKEN_INSERTION_REMOVAL" },
    { 84, "SSL_ERROR_TOKEN_SLOT_NOT_FOUND" },
    { 85, "SSL_ERROR_NO_COMPRESSION_OVERLAP" },
    { 86, "SSL_ERROR_HANDSHAKE_NOT_COMPLETED" },
    { 87, "SSL_ERROR_BAD_HANDSHAKE_HASH_VALUE" },
    { 88, "SSL_ERROR_CERT_KEA_MISMATCH" },
    { 89, "SSL_ERROR_NO_TRUSTED_SSL_CLIENT_CA - the CA that signed the client certificate is not trusted locally" }
};

#ifdef WIN32
#define __EXPORT __declspec(dllexport)
#else
#define __EXPORT
#endif

__EXPORT const char* nscperror_lookup(int error)
{
    const char *errmsg;

    if ((error >= NSCP_NSPR_ERROR_BASE) && (error <= NSCP_NSPR_MAX_ERROR)) {
        errmsg = nscp_nspr_errors[error-NSCP_NSPR_ERROR_BASE].errorString;
        return errmsg;
    } else if ((error >= NSCP_LIBSEC_ERROR_BASE) &&
        (error <= NSCP_LIBSEC_MAX_ERROR)) {
        return nscp_libsec_errors[error-NSCP_LIBSEC_ERROR_BASE].errorString;
    } else if ((error >= NSCP_LIBSSL_ERROR_BASE) &&
        (error <= NSCP_LIBSSL_MAX_ERROR)) {
        return nscp_libssl_errors[error-NSCP_LIBSSL_ERROR_BASE].errorString;
    } else {
        return (const char *)NULL;
    }
}
