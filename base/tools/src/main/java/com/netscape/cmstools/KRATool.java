// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2011, 2026 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cmstools;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateFactory;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.spec.MGF1ParameterSpec;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Vector;
import java.util.regex.PatternSyntaxException;

import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import org.mozilla.jss.CertDatabaseException;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.KeyDatabaseException;
import org.mozilla.jss.crypto.AlreadyInitializedException;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.InvalidKeyFormatException;
import org.mozilla.jss.crypto.IVParameterSpec;
import org.mozilla.jss.crypto.KeyGenAlgorithm;
import org.mozilla.jss.crypto.KeyGenerator;
import org.mozilla.jss.crypto.KeyPairAlgorithm;
import org.mozilla.jss.crypto.KeyPairGenerator;
import org.mozilla.jss.crypto.KeyPairGeneratorSpi;
import org.mozilla.jss.crypto.KeyWrapAlgorithm;
import org.mozilla.jss.crypto.KeyWrapper;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.TokenCertificate;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.provider.RSAPublicKey;
import org.mozilla.jss.netscape.security.util.DerInputStream;
import org.mozilla.jss.netscape.security.util.DerOutputStream;
import org.mozilla.jss.netscape.security.util.DerValue;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509Key;
import org.mozilla.jss.pkcs11.PK11PubKey;
import org.mozilla.jss.util.Password;

import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * Note: See <b> Cross-Scheme Migration Support </b> below for new features
 *
 * The KRATool class is a utility program designed to operate on an LDIF file
 * to perform one or more of the following tasks:
 *
 * <PRE>
 *     (A) Use a new storage key (e. g. - a 2048-bit key to replace a
 *         1024-bit key) to rewrap the existing triple DES symmetric key
 *         that was used to wrap a user's private key.
 *
 *         STARTING INVENTORY:
 *
 *             (1) a KRATOOL configuration file containing KRA LDIF record
 *                 types and the processing status of their associated fields
 *
 *             (2) an LDIF file containing 'exported' KRA data
 *                 (referred to as the "source" KRA)
 *
 *                 NOTE:  If this LDIF file contains data that was originally
 *                        from a KRA instance that was prior to RHCS 8, it
 *                        must have previously undergone the appropriate
 *                        migration steps.
 *
 *             (3) the NSS security databases associated with the data
 *                 contained in the source LDIF file
 *
 *                 NOTE:  If the storage key was located on an HSM, then the
 *                        HSM must be available to the machine on which the
 *                        KRATool is being executed (since the RSA private
 *                        storage key is required for unwrapping the
 *                        symmetric triple DES key).  Additionally, a
 *                        password may be required to unlock access to
 *                        this key (e. g. - which may be located in
 *                        the source KRA's 'password.conf' file).
 *
 *             (4) a file containing the ASCII BASE-64 storage certificate
 *                 from the KRA instance for which the output LDIF file is
 *                 intended (referred to as the "target")
 *
 *         ENDING INVENTORY:
 *
 *             (1) all items listed in the STARTING INVENTORY (unchanged)
 *
 *             (2) a log file containing information suitable for audit
 *                 purposes
 *
 *             (3) an LDIF file containing the revised data suitable for
 *                 'import' into a new KRA (referred to as the "target" KRA)
 *
 *         KRATool PARAMETERS:
 *
 *             (1) the name of the KRATOOL configuration file containing
 *                 KRA LDIF record types and the processing status of their
 *                 associated fields
 *
 *             (2) the name of the input LDIF file containing data which was
 *                 'exported' from the source KRA instance
 *
 *             (3) the name of the output LDIF file intended to contain the
 *                 revised data suitable for 'import' to a target KRA instance
 *
 *             (4) the name of the log file that may be used for auditing
 *                 purposes
 *
 *             (5) the path to the security databases that were used by
 *                 the source KRA instance
 *
 *             (6) the name of the token that was used by
 *                 the source KRA instance
 *
 *             (7) the name of the storage certificate that was used by
 *                 the source KRA instance
 *
 *             (8) the name of the file containing the ASCII BASE-64 storage
 *                 certificate from the target KRA instance for which the
 *                 output LDIF file is intended
 *
 *             (9) OPTIONALLY, the name of a file which ONLY contains the
 *                 password needed to access the source KRA instance's
 *                 security databases
 *
 *            (10) OPTIONALLY, choose to change the specified source KRA naming
 *                 context to the specified target KRA naming context
 *
 *            (11) OPTIONALLY, choose to ONLY process CA enrollment requests,
 *                 CA recovery requests, CA key records, TPS netkeyKeygen
 *                 enrollment requests, TPS recovery requests, and
 *                 TPS key records
 *
 *         DATA FIELDS AFFECTED (using default config file values):
 *
 *             (1) CA KRA enrollment request
 *
 *                 (a) dateOfModify
 *                 (b) extdata-requestnotes
 *
 *             (2) CA KRA key record
 *
 *                 (a) dateOfModify
 *                 (b) privateKeyData
 *
 *             (3) CA KRA recovery request
 *
 *                 (a) dateOfModify
 *                 (b) extdata-requestnotes (NEW)
 *
 *             (4) TPS KRA netkeyKeygen (enrollment) request
 *
 *                 (a) dateOfModify
 *                 (b) extdata-requestnotes (NEW)
 *
 *             (5) TPS KRA key record
 *
 *                 (a) dateOfModify
 *                 (b) privateKeyData
 *
 *             (6) TPS KRA recovery request
 *
 *                 (a) dateOfModify
 *                 (b) extdata-requestnotes (NEW)
 *
 *     (B) Specify an ID offset to append to existing numeric data
 *         (e. g. - to renumber data for use in KRA consolidation efforts).
 *
 *         STARTING INVENTORY:
 *
 *             (1) a KRATOOL configuration file containing KRA LDIF record
 *                 types and the processing status of their associated fields
 *
 *             (2) an LDIF file containing 'exported' KRA data
 *                 (referred to as the "source" KRA)
 *
 *                 NOTE:  If this LDIF file contains data that was originally
 *                        from a KRA instance that was prior to RHCS 8, it
 *                        must have previously undergone the appropriate
 *                        migration steps.
 *
 *         ENDING INVENTORY:
 *
 *             (1) all items listed in the STARTING INVENTORY (unchanged)
 *
 *             (2) a log file containing information suitable for audit
 *                 purposes
 *
 *             (3) an LDIF file containing the revised data suitable for
 *                 'import' into a new KRA (referred to as the "target" KRA)
 *
 *         KRATool PARAMETERS:
 *
 *             (1) the name of the KRATOOL configuration file containing
 *                 KRA LDIF record types and the processing status of their
 *                 associated fields
 *
 *             (2) the name of the input LDIF file containing data which was
 *                 'exported' from the source KRA instance
 *
 *             (3) the name of the output LDIF file intended to contain the
 *                 revised data suitable for 'import' to a target KRA instance
 *
 *             (4) the name of the log file that may be used for auditing
 *                 purposes
 *
 *             (5) a large numeric ID offset (mask) to be appended to existing
 *                 numeric data in the source KRA instance's LDIF file
 *
 *             (6) OPTIONALLY, choose to change the specified source KRA naming
 *                 context to the specified target KRA naming context
 *
 *             (7) OPTIONALLY, choose to ONLY process CA enrollment requests,
 *                 CA recovery requests, CA key records, TPS netkeyKeygen
 *                 enrollment requests, TPS recovery requests, and
 *                 TPS key records
 *
 *         DATA FIELDS AFFECTED (using default config file values):
 *
 *             (1) CA KRA enrollment request
 *
 *                 (a) cn
 *                 (b) dateOfModify
 *                 (c) extdata-keyrecord
 *                 (d) extdata-requestnotes
 *                 (e) requestId
 *
 *             (2) CA KRA key record
 *
 *                 (a) cn
 *                 (b) dateOfModify
 *                 (c) serialno
 *
 *             (3) CA KRA recovery request
 *
 *                 (a) cn
 *                 (b) dateOfModify
 *                 (c) extdata-requestid
 *                 (d) extdata-requestnotes (NEW)
 *                 (e) extdata-serialnumber
 *                 (f) requestId
 *
 *             (4) TPS KRA netkeyKeygen (enrollment) request
 *
 *                 (a) cn
 *                 (b) dateOfModify
 *                 (c) extdata-keyrecord
 *                 (d) extdata-requestid
 *                 (e) extdata-requestnotes (NEW)
 *                 (f) requestId
 *
 *             (5) TPS KRA key record
 *
 *                 (a) cn
 *                 (b) dateOfModify
 *                 (c) serialno
 *
 *             (6) TPS KRA recovery request
 *
 *                 (a) cn
 *                 (b) dateOfModify
 *                 (c) extdata-requestid
 *                 (d) extdata-requestnotes (NEW)
 *                 (e) extdata-serialnumber
 *                 (f) requestId
 *
 *     (C) Specify an ID offset to be removed from existing numeric data
 *         (e. g. - to undo renumbering used in KRA consolidation efforts).
 *
 *         STARTING INVENTORY:
 *
 *             (1) a KRATOOL configuration file containing KRA LDIF record
 *                 types and the processing status of their associated fields
 *
 *             (2) an LDIF file containing 'exported' KRA data
 *                 (referred to as the "source" KRA)
 *
 *                 NOTE:  If this LDIF file contains data that was originally
 *                        from a KRA instance that was prior to RHCS 8, it
 *                        must have previously undergone the appropriate
 *                        migration steps.
 *
 *         ENDING INVENTORY:
 *
 *             (1) all items listed in the STARTING INVENTORY (unchanged)
 *
 *             (2) a log file containing information suitable for audit
 *                 purposes
 *
 *             (3) an LDIF file containing the revised data suitable for
 *                 'import' into a new KRA (referred to as the "target" KRA)
 *
 *         KRATool PARAMETERS:
 *
 *             (1) the name of the KRATOOL configuration file containing
 *                 KRA LDIF record types and the processing status of their
 *                 associated fields
 *
 *             (2) the name of the input LDIF file containing data which was
 *                 'exported' from the source KRA instance
 *
 *             (3) the name of the output LDIF file intended to contain the
 *                 revised data suitable for 'import' to a target KRA instance
 *
 *             (4) the name of the log file that may be used for auditing
 *                 purposes
 *
 *             (5) a large numeric ID offset (mask) to be removed from existing
 *                 numeric data in the source KRA instance's LDIF file
 *
 *             (6) OPTIONALLY, choose to change the specified source KRA naming
 *                 context to the specified target KRA naming context
 *
 *             (7) OPTIONALLY, choose to ONLY process CA enrollment requests,
 *                 CA recovery requests, CA key records, TPS netkeyKeygen
 *                 enrollment requests, TPS recovery requests, and
 *                 TPS key records
 *
 *         DATA FIELDS AFFECTED (using default config file values):
 *
 *             (1) CA KRA enrollment request
 *
 *                 (a) cn
 *                 (b) dateOfModify
 *                 (c) extdata-keyrecord
 *                 (d) extdata-requestnotes
 *                 (e) requestId
 *
 *             (2) CA KRA key record
 *
 *                 (a) cn
 *                 (b) dateOfModify
 *                 (c) serialno
 *
 *             (3) CA KRA recovery request
 *
 *                 (a) cn
 *                 (b) dateOfModify
 *                 (c) extdata-requestid
 *                 (d) extdata-requestnotes (NEW)
 *                 (e) extdata-serialnumber
 *                 (f) requestId
 *
 *             (4) TPS KRA netkeyKeygen (enrollment) request
 *
 *                 (a) cn
 *                 (b) dateOfModify
 *                 (c) extdata-keyrecord
 *                 (d) extdata-requestid
 *                 (e) extdata-requestnotes (NEW)
 *                 (f) requestId
 *
 *             (5) TPS KRA key record
 *
 *                 (a) cn
 *                 (b) dateOfModify
 *                 (c) serialno
 *
 *             (6) TPS KRA recovery request
 *
 *                 (a) cn
 *                 (b) dateOfModify
 *                 (c) extdata-requestid
 *                 (d) extdata-requestnotes (NEW)
 *                 (e) extdata-serialnumber
 *                 (f) requestId
 *
 * </PRE>
 *
 * <P>
 * KRATool may be invoked as follows:
 *
 * <PRE>
 *
 *    KRATool
 *    -kratool_config_file &lt;path + kratool config file&gt;
 *    -source_ldif_file &lt;path + source ldif file&gt;
 *    -target_ldif_file &lt;path + target ldif file&gt;
 *    -log_file &lt;path + log file&gt;
 *    [-source_pki_security_database_path &lt;path to PKI source database&gt;]
 *    [-source_storage_token_name '&lt;source token&gt;']
 *    [-source_storage_certificate_nickname '&lt;source nickname&gt;']
 *    [-target_storage_certificate_file &lt;path to target certificate file&gt;]
 *    [-source_pki_security_database_pwdfile &lt;path to PKI password file&gt;]
 *    [-append_id_offset &lt;numeric offset&gt;]
 *    [-remove_id_offset &lt;numeric offset&gt;]
 *    [-source_kra_naming_context '&lt;original source KRA naming context&gt;']
 *    [-target_kra_naming_context '&lt;renamed target KRA naming context&gt;']
 *    [-process_requests_and_key_records_only]
 *
 *    where the following options are 'Mandatory':
 *
 *    -kratool_config_file &lt;path + kratool config file&gt;
 *    -source_ldif_file &lt;path + source ldif file&gt;
 *    -target_ldif_file &lt;path + target ldif file&gt;
 *    -log_file &lt;path + log file&gt;
 *
 *    AND at least ONE of the following are a 'Mandatory' set of options:
 *
 *        (a) options for using a new storage key for rewrapping:
 *
 *            [-source_pki_security_database_path
 *             &lt;path to PKI source database&gt;]
 *            [-source_storage_token_name '&lt;source token&gt;']
 *            [-source_storage_certificate_nickname '&lt;source nickname&gt;']
 *            [-target_storage_certificate_file
 *             &lt;path to target certificate file&gt;]
 *
 *            AND OPTIONALLY, specify the name of a file which ONLY contains
 *            the password needed to access the source KRA instance's
 *            security databases:
 *
 *            [-source_pki_security_database_pwdfile
 *             &lt;path to PKI password file&gt;]
 *
 *            AND OPTIONALLY, rename source KRA naming context --&gt; target
 *            KRA naming context:
 *
 *            [-source_kra_naming_context '&lt;source KRA naming context&gt;']
 *            [-target_kra_naming_context '&lt;target KRA naming context&gt;']
 *
 *            AND OPTIONALLY, process requests and key records ONLY:
 *
 *            [-process_requests_and_key_records_only]
 *
 *        (b) option for appending the specified numeric ID offset
 *            to existing numerical data:
 *
 *            [-append_id_offset &lt;numeric offset&gt;]
 *
 *            AND OPTIONALLY, rename source KRA naming context --&gt; target
 *            KRA naming context:
 *
 *            [-source_kra_naming_context '&lt;source KRA naming context&gt;']
 *            [-target_kra_naming_context '&lt;target KRA naming context&gt;']
 *
 *            AND OPTIONALLY, process requests and key records ONLY:
 *
 *            [-process_requests_and_key_records_only]
 *
 *        (c) option for removing the specified numeric ID offset
 *            from existing numerical data:
 *
 *            AND OPTIONALLY, rename source KRA naming context --&gt; target
 *            KRA naming context:
 *
 *            [-source_kra_naming_context '&lt;source KRA naming context&gt;']
 *            [-target_kra_naming_context '&lt;target KRA naming context&gt;']
 *
 *            [-remove_id_offset &lt;numeric offset&gt;]
 *
 *            AND OPTIONALLY, process requests and key records ONLY:
 *
 *            [-process_requests_and_key_records_only]
 *
 *        (d) (a) rewrap AND (b) append ID offset
 *            [AND OPTIONALLY, rename source KRA naming context --&gt; target
 *            KRA naming context]
 *            [AND OPTIONALLY process requests and key records ONLY]
 *
 *        (e) (a) rewrap AND (c) remove ID offset
 *            [AND OPTIONALLY, rename source KRA naming context --&gt; target
 *            KRA naming context]
 *            [AND OPTIONALLY process requests and key records ONLY]
 *
 *        NOTE:  Options (b) and (c) are mutually exclusive!
 *
 * </PRE>
 *
 * <h3>Cross-Scheme Migration Support</h3>
 *
 * <p>
 * KRATool supports cross-scheme migration, enabling secure migration of archived
 * keys between KRA instances using different cryptographic schemes (e.g., from
 * RSA+AES/CBC to RSA-OAEP+AES-KWP for FIPS-mode HSMs).
 * </p>
 *
 * <p><b>Key Features:</b></p>
 * <ul>
 * <li><b>Secure rewrap flow:</b> Private keys remain wrapped in tokens throughout
 *     the migration process.</li>
 * <li><b>Order-independent LDIF parsing:</b> Extracts privateKeyData and publicKeyData
 *     fields independently, regardless of their order in LDIF records.</li>
 * <li><b>Algorithm auto-detection:</b> Automatically regenerates session keys only
 *     when source and target algorithms or key sizes differ.</li>
 * <li><b>HSM compatibility:</b> Supports private key payload processing in NSS DB
 *     (software token) via -use_nss_for_payload_processing flag when HSM lacks
 *     support for source or target algorithms.</li>
 * <li><b>Pure Java implementation:</b> When -use_nss_for_payload_processing is used,
 *     the importSessionKeyToToken() method implements JSS_KeyExchange mechanism in pure
 *     Java with automatic fallback to temporary RSA keypair approach.</li>
 * </ul>
 *
 * <p><b>Supported Algorithms:</b></p>
 * <ul>
 * <li>Session key wrap: RSA, RSA-OAEP</li>
 * <li>Payload wrap: AES KeyWrap/Wrapped (CKM_AES_KEY_WRAP_KWP, recommended for HSM/FIPS),
 *     AES KeyWrap/Padding (CKM_AES_KEY_WRAP_PAD), AES KeyWrap/NoPadding (CKM_AES_KEY_WRAP),
 *     AES/CBC/PKCS5Padding, DES3/CBC/Padding</li>
 * </ul>
 *
 * <p><b>Cross-Scheme Command-Line Options:</b></p>
 * <pre>
 *   -source_rsa_wrap_algorithm &lt;RSA|RSA-OAEP&gt;
 *       Source session key wrap algorithm (default: RSA)
 *
 *   -target_rsa_wrap_algorithm &lt;RSA|RSA-OAEP&gt;
 *       Target session key wrap algorithm (default: RSA-OAEP, recommended for HSM/FIPS)
 *
 *   -source_payload_wrap_algorithm &lt;algorithm&gt;
 *       Source payload wrap algorithm (must match source KRA's payloadWrapAlgorithm)
 *       Supported: "AES KeyWrap/Wrapped"   - CKM_AES_KEY_WRAP_KWP (0x210B) (recommended)
 *                  "AES KeyWrap/Padding"   - CKM_AES_KEY_WRAP_PAD (0x210A)
 *                  "AES KeyWrap/NoPadding" - CKM_AES_KEY_WRAP (0x2109)
 *                  "AES/CBC/PKCS5Padding", "DES3/CBC/Padding"
 *
 *   -target_payload_wrap_algorithm &lt;algorithm&gt;
 *       Target payload wrap algorithm (must match target KRA's configured algorithm)
 *       Supported: "AES KeyWrap/Wrapped"   - CKM_AES_KEY_WRAP_KWP (0x210B) (recommended)
 *                  "AES KeyWrap/Padding"   - CKM_AES_KEY_WRAP_PAD (0x210A)
 *                  "AES KeyWrap/NoPadding" - CKM_AES_KEY_WRAP (0x2109)
 *                  "AES/CBC/PKCS5Padding", "DES3/CBC/Padding"
 *
 *   -source_payload_wrap_keysize &lt;128|192|256&gt;
 *       Source payload wrapping key size in bits (default: 128)
 *
 *   -target_payload_wrap_keysize &lt;128|192|256&gt;
 *       Target payload wrapping key size in bits (default: 128)
 *
 *   -use_nss_for_payload_processing
 *       Perform payload unwrap/rewrap in NSS DB (software token) when HSM lacks
 *       support for target algorithms
 *
 *   -regenerate_session_key
 *       Force regeneration of session key even when algorithms match
 *
 *   -split_target_ldif_per_records &lt;N&gt;
 *       Split output into multiple LDIF files, each containing N records
 *
 *   -verbose
 *       Enable detailed per-record logging (useful for debugging)
 *
 *   -use_oaep_rsa_key_wrap
 *       Use RSA-OAEP instead of RSA PKCS#1 v1.5 (legacy flag)
 * </pre>
 *
 * @author mharmsen
 * @author cfu (added cross-scheme migration support)
 *
 */
public class KRATool {
    /*************/
    /* Constants */
    /*************/

    // Constants:  Miscellaneous
    private static final boolean FAILURE = false;
    private static final boolean SUCCESS = true;
    private static final String COLON = ":";
    private static final String COMMA = ",";
    private static final String DOT = ".";
    private static final String EQUAL_SIGN = "=";
    private static final String LEFT_BRACE = "[";
    private static final String NEWLINE = "\n";
    private static final String PLUS = "+";
    private static final String RIGHT_BRACE = "]";
    private static final String SPACE = " ";
    private static final String TIC = "'";

    // Constants:  Calendar
    private static final String DATE_OF_MODIFY_PATTERN = "yyyyMMddHHmmss'Z'";
    private static final String LOGGING_DATE_PATTERN = "dd/MMM/yyyy:HH:mm:ss z";

    // Constants:  Command-line Options
    private static final int ID_OFFSET_NAME_VALUE_PAIRS = 1;
    private static final int PWDFILE_NAME_VALUE_PAIRS = 1;
    private static final int NAMING_CONTEXT_NAME_VALUE_PAIRS = 2;
    private static final int MANDATORY_NAME_VALUE_PAIRS = 4;
    private static final int REWRAP_NAME_VALUE_PAIRS = 4;
    private static final int REWRAP_ARGS = 16;

    // Constants:  Command-line Options (Mandatory)
    private static final String KRA_TOOL = "KRATool";

    private static final String KRATOOL_CFG_FILE = "-kratool_config_file";

    private static final String KRATOOL_CFG_DESCRIPTION = " <complete path to the kratool config file"
                            + NEWLINE
                            + "        "
                            + "  ending with the kratool config file name>";

    private static final String KRATOOL_CFG_FILE_EXAMPLE = KRATOOL_CFG_FILE
                             + " "
                             + "/usr/share/pki/tools/KRATool.cfg";

    private static final String SOURCE_LDIF_FILE = "-source_ldif_file";

    private static final String SOURCE_LDIF_DESCRIPTION = " <complete path to the source LDIF input file"
                            + NEWLINE
                            + "        "
                            + "  ending with the source LDIF file name>";

    private static final String SOURCE_LDIF_FILE_EXAMPLE = SOURCE_LDIF_FILE
                             + " "
                             + "/export/pki/source.ldif";

    private static final String TARGET_LDIF_FILE = "-target_ldif_file";

    private static final String TARGET_LDIF_DESCRIPTION = " <complete path to the target LDIF output file"
                            + NEWLINE
                            + "        "
                            + "  ending with the target LDIF file name>";

    private static final String TARGET_LDIF_FILE_EXAMPLE = TARGET_LDIF_FILE
                             + " "
                             + "/export/pki/target.ldif";

    private static final String LOG_FILE = "-log_file";

    private static final String LOG_DESCRIPTION = " <complete path to the log file"
                    + NEWLINE
                    + "        "
                    + "  ending with the log file name>";

    private static final String LOG_FILE_EXAMPLE = LOG_FILE
                     + " "
                     + "/export/pki/KRATool.log";

    // Constants:  Command-line Options (Rewrap)
    private static final String SOURCE_NSS_DB_PATH = "-source_pki_security_database_path";

    private static final String SOURCE_NSS_DB_DESCRIPTION = "  <complete path to the "
                              + "source security databases"
                              + NEWLINE
                              + "        "
                              + "   used by data in the source LDIF file>";

    private static final String SOURCE_NSS_DB_PATH_EXAMPLE = SOURCE_NSS_DB_PATH
                               + " "
                               + "/export/pki";

    private static final String SOURCE_STORAGE_TOKEN_NAME = "-source_storage_token_name";

    private static final String SOURCE_STORAGE_TOKEN_DESCRIPTION = "  <name of the token containing "
                                     + "the source storage token>";

    private static final String SOURCE_STORAGE_TOKEN_NAME_EXAMPLE = SOURCE_STORAGE_TOKEN_NAME
                                      + " "
                                      + TIC
                                      + "SourceHSM"
                                      + TIC;

    private static final String SOURCE_STORAGE_CERT_NICKNAME = "-source_storage_certificate_nickname";

    private static final String SOURCE_STORAGE_CERT_NICKNAME_DESCRIPTION = "  <nickname of the source "
                                             + "storage certificate>";

    private static final String SOURCE_STORAGE_CERT_NICKNAME_EXAMPLE = SOURCE_STORAGE_CERT_NICKNAME
                                         + " "
                                         + TIC
                                         + "storageCert cert-pki-kra"
                                         + TIC;

    private static final String TARGET_STORAGE_CERTIFICATE_FILE = "-target_storage_certificate_file";

    private static final String TARGET_STORAGE_CERTIFICATE_DESCRIPTION = "  <complete path to the target "
                                           + "storage certificate file"
                                           + NEWLINE
                                           + "        "
                                           + "   ending with the target "
                                           + "storage certificate file name;"
                                           + NEWLINE
                                           + "        "
                                           + "   the target storage "
                                           + "certificate is stored in"
                                           + NEWLINE
                                           + "        "
                                           + "   an ASCII format between a "
                                           + "header and footer>";

    private static final String TARGET_STORAGE_CERTIFICATE_FILE_EXAMPLE = TARGET_STORAGE_CERTIFICATE_FILE
                                            + " "
                                            + "/export/pki/target_storage.cert";

    private static final String SOURCE_NSS_DB_PWDFILE = "-source_pki_security_database_pwdfile";

    private static final String SOURCE_NSS_DB_PWDFILE_DESCRIPTION = "  <complete path to the password "
                                      + "file which ONLY contains the"
                                      + NEWLINE
                                      + "        "
                                      + "   password used to access the "
                                      + "source security databases>";

    private static final String SOURCE_NSS_DB_PWDFILE_EXAMPLE = SOURCE_NSS_DB_PWDFILE
                                  + " "
                                  + "/export/pki/pwdfile";

    private static final String SOURCE_HSM_TOKEN_PWDFILE = "-source_hsm_token_pwdfile";

    private static final String SOURCE_HSM_TOKEN_PWDFILE_DESCRIPTION = "  <complete path to the password "
                                      + "file which ONLY contains the"
                                      + NEWLINE
                                      + "        "
                                      + "   password used to access the "
                                      + "source HSM token>";

    private static final String SOURCE_HSM_TOKEN_PWDFILE_EXAMPLE = SOURCE_HSM_TOKEN_PWDFILE
                                  + " "
                                  + "/export/pki/hsm-pwdfile";

    // Constants:  Command-line Options (ID Offset)
    private static final String APPEND_ID_OFFSET = "-append_id_offset";

    private static final String APPEND_ID_OFFSET_DESCRIPTION = "  <ID offset that is appended to "
                                 + "each record's source ID>";

    private static final String APPEND_ID_OFFSET_EXAMPLE = APPEND_ID_OFFSET
                             + " "
                             + "100000000000";

    private static final String REMOVE_ID_OFFSET = "-remove_id_offset";

    private static final String REMOVE_ID_OFFSET_DESCRIPTION = "  <ID offset that is removed from "
                                 + "each record's source ID>";

    private static final String REMOVE_ID_OFFSET_EXAMPLE = REMOVE_ID_OFFSET
                             + " "
                             + "100000000000";

    // Constants:  Command-line Options
    private static final String USE_OAEP_RSA_KEY_WRAP = "-use_rsa_oaep_keywrap";

    // New flags for cross-scheme migration support
    private static final String USE_CROSS_SCHEME = "-use_cross_scheme";
    private static final String USE_CROSS_SCHEME_DESCRIPTION = "  Enable cross-scheme migration mode (entry-based processing)" + NEWLINE +
                                                                "        " + "   Required for migrating between different wrapping algorithms";

    private static final String SOURCE_RSA_WRAP_ALGORITHM = "-source_rsa_wrap_algorithm";
    private static final String SOURCE_RSA_WRAP_ALGORITHM_DESCRIPTION = "  <RSA|RSA-OAEP> Source session key wrap algorithm (default: RSA)";

    private static final String TARGET_RSA_WRAP_ALGORITHM = "-target_rsa_wrap_algorithm";
    private static final String TARGET_RSA_WRAP_ALGORITHM_DESCRIPTION = "  <RSA|RSA-OAEP> Target session key wrap algorithm (default: RSA-OAEP, recommended for HSM/FIPS)";

    private static final String SOURCE_PAYLOAD_WRAP_ALGORITHM = "-source_payload_wrap_algorithm";
    private static final String SOURCE_PAYLOAD_WRAP_ALGORITHM_DESCRIPTION = "  <algorithm> Source payload wrap algorithm" + NEWLINE +
                                                                             "        " + "   Supported:" + NEWLINE +
                                                                             "        " + "     \"AES KeyWrap/Wrapped\"   - uses CKM_AES_KEY_WRAP_KWP (0x210B) (recommended for HSM/FIPS)" + NEWLINE +
                                                                             "        " + "     \"AES KeyWrap/Padding\"   - uses CKM_AES_KEY_WRAP_PAD (0x210A)" + NEWLINE +
                                                                             "        " + "     \"AES KeyWrap/NoPadding\" - uses CKM_AES_KEY_WRAP (0x2109)" + NEWLINE +
                                                                             "        " + "     \"AES/CBC/PKCS5Padding\"  - uses CKM_AES_CBC_PAD (0x1085)" + NEWLINE +
                                                                             "        " + "     \"DES3/CBC/Padding\"      - uses CKM_DES3_CBC_PAD" + NEWLINE +
                                                                             "        " + "   Note: Use the quoted strings above, not the CKM_* mechanism names" + NEWLINE +
                                                                             "        " + "   (must match source KRA's payloadWrapAlgorithm metaInfo)";

    private static final String TARGET_PAYLOAD_WRAP_ALGORITHM = "-target_payload_wrap_algorithm";
    private static final String TARGET_PAYLOAD_WRAP_ALGORITHM_DESCRIPTION = "  <algorithm> Target payload wrap algorithm (without key size)" + NEWLINE +
                                                                             "        " + "   Supported:" + NEWLINE +
                                                                             "        " + "     \"AES KeyWrap/Wrapped\"   - uses CKM_AES_KEY_WRAP_KWP (0x210B) (recommended for HSM/FIPS)" + NEWLINE +
                                                                             "        " + "     \"AES KeyWrap/Padding\"   - uses CKM_AES_KEY_WRAP_PAD (0x210A)" + NEWLINE +
                                                                             "        " + "     \"AES KeyWrap/NoPadding\" - uses CKM_AES_KEY_WRAP (0x2109)" + NEWLINE +
                                                                             "        " + "     \"AES/CBC/PKCS5Padding\"  - uses CKM_AES_CBC_PAD (0x1085)" + NEWLINE +
                                                                             "        " + "     \"DES3/CBC/Padding\"      - uses CKM_DES3_CBC_PAD" + NEWLINE +
                                                                             "        " + "   Note: Use the quoted strings above, not the CKM_* mechanism names" + NEWLINE +
                                                                             "        " + "   Note: Key size is specified separately with -target_payload_wrap_key_size" + NEWLINE +
                                                                             "        " + "   (must match target KRA's configured algorithm)";

    private static final String SOURCE_PAYLOAD_WRAP_KEYSIZE = "-source_payload_wrap_keysize";
    private static final String SOURCE_PAYLOAD_WRAP_KEYSIZE_DESCRIPTION = "  <128|192|256> Source payload wrapping key size in bits (default: 128)";

    private static final String TARGET_PAYLOAD_WRAP_KEYSIZE = "-target_payload_wrap_keysize";
    private static final String TARGET_PAYLOAD_WRAP_KEYSIZE_DESCRIPTION = "  <128|192|256> Target payload wrapping key size in bits (default: 128)";

    private static final String USE_NSS_FOR_PAYLOAD_PROCESSING = "-use_nss_for_payload_processing";
    private static final String USE_NSS_FOR_PAYLOAD_PROCESSING_DESCRIPTION = "  Use NSS DB (software token) for payload unwrap/rewrap" + NEWLINE +
                                                                               "        " + "   operations (useful when HSM doesn't support target algorithms)";

    private static final String REGENERATE_SESSION_KEY = "-regenerate_session_key";
    private static final String REGENERATE_SESSION_KEY_DESCRIPTION = "  Force generation of new session key during rewrap" + NEWLINE +
                                                                      "        " + "   Note: Tool auto-detects when regeneration is needed and prompts user" + NEWLINE +
                                                                      "        " + "   Use this flag to skip prompt and force regeneration";

    // **TEST ONLY** Skip cryptographic rewrap operations, copy key data as-is
    // Use for testing LDIF transformations without HSM access
    private static final String SKIP_REWRAP = "-skip_rewrap";

    // **TEST ONLY** Force RSA keypair transfer method (skip Stage 1 cloneKey attempt)
    // Use for testing the JSS_KeyExchange-style approach
    // Must be used with -use_nss_for_payload_processing to test
    private static final String FORCE_RSA_KEYPAIR_TRANSFER = "-force_rsa_keypair_transfer";

    private static final String SPLIT_TARGET_LDIF_PER_RECORDS = "-split_target_ldif_per_records";
    private static final String SPLIT_TARGET_LDIF_PER_RECORDS_DESCRIPTION = "  <number> Split target LDIF into multiple files after every N records" + NEWLINE +
                                                                             "        " + "   Creates files: targetfile-1.ldif, targetfile-2.ldif, etc.";

    private static final String SOURCE_KRA_NAMING_CONTEXT = "-source_kra_naming_context";

    private static final String SOURCE_KRA_NAMING_CONTEXT_DESCRIPTION = "  <source KRA naming context>";

    private static final String SOURCE_KRA_NAMING_CONTEXT_EXAMPLE = SOURCE_KRA_NAMING_CONTEXT
                                      + " "
                                      + TIC
                                      + "alpha.example.com-pki-kra"
                                      + TIC;

    private static final String TARGET_KRA_NAMING_CONTEXT = "-target_kra_naming_context";

    private static final String TARGET_KRA_NAMING_CONTEXT_DESCRIPTION = "  <target KRA naming context>";

    private static final String TARGET_KRA_NAMING_CONTEXT_EXAMPLE = TARGET_KRA_NAMING_CONTEXT
                                      + " "
                                      + TIC
                                      + "omega.example.com-pki-kra"
                                      + TIC;

    private static final String PROCESS_REQUESTS_AND_KEY_RECORDS_ONLY =
            "-process_requests_and_key_records_only";

    private static final String VERBOSE = "-verbose";

    private static final String VERBOSE_DESCRIPTION = "  Enable detailed per-record logging (useful for debugging)";

    private static final String KEY_UNWRAP_ALGORITHM = "-unwrap_algorithm";

    private static final String KEY_UNWRAP_ALGORITHM_DESCRIPTION = "  <key unwrap algorithm> (default: DES3)";

    // Constants:  KRATOOL Config File
    private static final String KRATOOL_CFG_PREFIX = "kratool.ldif";
    private static final String KRATOOL_CFG_ENROLLMENT = "caEnrollmentRequest";
    private static final String KRATOOL_CFG_CA_KEY_RECORD = "caKeyRecord";
    private static final String KRATOOL_CFG_RECOVERY = "recoveryRequest";
    private static final String KRATOOL_CFG_TPS_KEY_RECORD = "tpsKeyRecord";
    private static final String KRATOOL_CFG_KEYGEN = "tpsNetkeyKeygenRequest";
    private static final String KRATOOL_CFG_KEYRECOVERY = "tpsNetkeyKeyRecoveryRequest";

    // Constants:  KRATOOL Config File (KRA CA Enrollment Request Fields)
    private static final String KRATOOL_CFG_ENROLLMENT_CN = KRATOOL_CFG_PREFIX
                                  + DOT
                                  + KRATOOL_CFG_ENROLLMENT
                                  + DOT
                                  + "cn";
    private static final String KRATOOL_CFG_ENROLLMENT_DATE_OF_MODIFY = KRATOOL_CFG_PREFIX
                                              + DOT
                                              + KRATOOL_CFG_ENROLLMENT
                                              + DOT
                                              + "dateOfModify";
    private static final String KRATOOL_CFG_ENROLLMENT_DN = KRATOOL_CFG_PREFIX
                                  + DOT
                                  + KRATOOL_CFG_ENROLLMENT
                                  + DOT
                                  + "dn";
    private static final String KRATOOL_CFG_ENROLLMENT_EXTDATA_KEY_RECORD = KRATOOL_CFG_PREFIX
                                                  + DOT
                                                  + KRATOOL_CFG_ENROLLMENT
                                                  + DOT
                                                  + "extdata.keyRecord";
    private static final String KRATOOL_CFG_ENROLLMENT_EXTDATA_REQUEST_NOTES = KRATOOL_CFG_PREFIX
                                                     + DOT
                                                     + KRATOOL_CFG_ENROLLMENT
                                                     + DOT
                                                     + "extdata.requestNotes";
    private static final String KRATOOL_CFG_ENROLLMENT_REQUEST_ID = KRATOOL_CFG_PREFIX
                                          + DOT
                                          + KRATOOL_CFG_ENROLLMENT
                                          + DOT
                                          + "requestId";

    // Constants:  KRATOOL Config File (KRA CA Key Record Fields)
    private static final String KRATOOL_CFG_CA_KEY_RECORD_CN = KRATOOL_CFG_PREFIX
                                     + DOT
                                     + KRATOOL_CFG_CA_KEY_RECORD
                                     + DOT
                                     + "cn";
    private static final String KRATOOL_CFG_CA_KEY_RECORD_DATE_OF_MODIFY = KRATOOL_CFG_PREFIX
                                                 + DOT
                                                 + KRATOOL_CFG_CA_KEY_RECORD
                                                 + DOT
                                                 + "dateOfModify";
    private static final String KRATOOL_CFG_CA_KEY_RECORD_DN = KRATOOL_CFG_PREFIX
                                     + DOT
                                     + KRATOOL_CFG_ENROLLMENT
                                     + DOT
                                     + "dn";
    private static final String KRATOOL_CFG_CA_KEY_RECORD_PRIVATE_KEY_DATA = KRATOOL_CFG_PREFIX
                                                   + DOT
                                                   + KRATOOL_CFG_CA_KEY_RECORD
                                                   + DOT
                                                   + "privateKeyData";
    private static final String KRATOOL_CFG_CA_KEY_RECORD_SERIAL_NO = KRATOOL_CFG_PREFIX
                                            + DOT
                                            + KRATOOL_CFG_CA_KEY_RECORD
                                            + DOT
                                            + "serialno";

    // Constants:  KRATOOL Config File (KRA CA / TPS Recovery Request Fields)
    private static final String KRATOOL_CFG_RECOVERY_CN = KRATOOL_CFG_PREFIX
                                + DOT
                                + KRATOOL_CFG_RECOVERY
                                + DOT
                                + "cn";
    private static final String KRATOOL_CFG_RECOVERY_DATE_OF_MODIFY = KRATOOL_CFG_PREFIX
                                            + DOT
                                            + KRATOOL_CFG_RECOVERY
                                            + DOT
                                            + "dateOfModify";
    private static final String KRATOOL_CFG_RECOVERY_DN = KRATOOL_CFG_PREFIX
                                + DOT
                                + KRATOOL_CFG_RECOVERY
                                + DOT
                                + "dn";
    private static final String KRATOOL_CFG_RECOVERY_EXTDATA_REQUEST_ID = KRATOOL_CFG_PREFIX
                                                + DOT
                                                + KRATOOL_CFG_RECOVERY
                                                + DOT
                                                + "extdata.requestId";
    private static final String KRATOOL_CFG_RECOVERY_EXTDATA_REQUEST_NOTES = KRATOOL_CFG_PREFIX
                                                   + DOT
                                                   + KRATOOL_CFG_RECOVERY
                                                   + DOT
                                                   + "extdata.requestNotes";
    private static final String KRATOOL_CFG_RECOVERY_EXTDATA_SERIAL_NUMBER = KRATOOL_CFG_PREFIX
                                                   + DOT
                                                   + KRATOOL_CFG_RECOVERY
                                                   + DOT
                                                   + "extdata.serialnumber";
    private static final String KRATOOL_CFG_RECOVERY_REQUEST_ID = KRATOOL_CFG_PREFIX
                                        + DOT
                                        + KRATOOL_CFG_RECOVERY
                                        + DOT
                                        + "requestId";

    // Constants:  KRATOOL Config File (KRA TPS Key Record Fields)
    private static final String KRATOOL_CFG_TPS_KEY_RECORD_CN = KRATOOL_CFG_PREFIX
                                      + DOT
                                      + KRATOOL_CFG_TPS_KEY_RECORD
                                      + DOT
                                      + "cn";
    private static final String KRATOOL_CFG_TPS_KEY_RECORD_DATE_OF_MODIFY = KRATOOL_CFG_PREFIX
                                                  + DOT
                                                  + KRATOOL_CFG_TPS_KEY_RECORD
                                                  + DOT
                                                  + "dateOfModify";
    private static final String KRATOOL_CFG_TPS_KEY_RECORD_DN = KRATOOL_CFG_PREFIX
                                      + DOT
                                      + KRATOOL_CFG_TPS_KEY_RECORD
                                      + DOT
                                      + "dn";
    private static final String KRATOOL_CFG_TPS_KEY_RECORD_PRIVATE_KEY_DATA = KRATOOL_CFG_PREFIX
                                                    + DOT
                                                    + KRATOOL_CFG_TPS_KEY_RECORD
                                                    + DOT
                                                    + "privateKeyData";
    private static final String KRATOOL_CFG_TPS_KEY_RECORD_SERIAL_NO = KRATOOL_CFG_PREFIX
                                             + DOT
                                             + KRATOOL_CFG_TPS_KEY_RECORD
                                             + DOT
                                             + "serialno";

    // Constants:  KRATOOL Config File (KRA TPS Netkey Keygen Request Fields)
    private static final String KRATOOL_CFG_KEYGEN_CN = KRATOOL_CFG_PREFIX
                              + DOT
                              + KRATOOL_CFG_KEYGEN
                              + DOT
                              + "cn";
    private static final String KRATOOL_CFG_KEYGEN_DATE_OF_MODIFY = KRATOOL_CFG_PREFIX
                                          + DOT
                                          + KRATOOL_CFG_KEYGEN
                                          + DOT
                                          + "dateOfModify";
    private static final String KRATOOL_CFG_KEYGEN_DN = KRATOOL_CFG_PREFIX
                              + DOT
                              + KRATOOL_CFG_KEYGEN
                              + DOT
                              + "dn";
    private static final String KRATOOL_CFG_KEYGEN_EXTDATA_KEY_RECORD = KRATOOL_CFG_PREFIX
                                              + DOT
                                              + KRATOOL_CFG_KEYGEN
                                              + DOT
                                              + "extdata.keyRecord";
    private static final String KRATOOL_CFG_KEYGEN_EXTDATA_REQUEST_ID = KRATOOL_CFG_PREFIX
                                              + DOT
                                              + KRATOOL_CFG_KEYGEN
                                              + DOT
                                              + "extdata.requestId";
    private static final String KRATOOL_CFG_KEYGEN_EXTDATA_REQUEST_NOTES = KRATOOL_CFG_PREFIX
                                                 + DOT
                                                 + KRATOOL_CFG_KEYGEN
                                                 + DOT
                                                 + "extdata.requestNotes";
    private static final String KRATOOL_CFG_KEYGEN_REQUEST_ID = KRATOOL_CFG_PREFIX
                                      + DOT
                                      + KRATOOL_CFG_KEYGEN
                                      + DOT
                                      + "requestId";

    private static final String KRATOOL_CFG_KEYRECOVERY_REQUEST_ID = KRATOOL_CFG_PREFIX
            + DOT
            + KRATOOL_CFG_KEYRECOVERY
            + DOT
            + "requestId";

    private static final String KRATOOL_CFG_KEYRECOVERY_DN = KRATOOL_CFG_PREFIX
            + DOT
            + KRATOOL_CFG_KEYRECOVERY
            + DOT
            + "dn";

    private static final String KRATOOL_CFG_KEYRECOVERY_DATE_OF_MODIFY = KRATOOL_CFG_PREFIX
            + DOT
            + KRATOOL_CFG_KEYRECOVERY
            + DOT
            + "dateOfModify";

    private static final String KRATOOL_CFG_KEYRECOVERY_EXTDATA_REQUEST_ID = KRATOOL_CFG_PREFIX
            + DOT
            + KRATOOL_CFG_KEYRECOVERY
            + DOT
            + "extdata.requestId";

    private static final String KRATOOL_CFG_KEYRECOVERY_CN = KRATOOL_CFG_PREFIX
            + DOT
            + KRATOOL_CFG_KEYRECOVERY
            + DOT
            + "cn";

    private static final String KRATOOL_CFG_KEYRECOVERY_EXTDATA_REQUEST_NOTES = KRATOOL_CFG_PREFIX
            + DOT
            + KRATOOL_CFG_KEYRECOVERY
            + DOT
            + "extdata.requestNotes";



    // Constants:  Target Certificate Information
    private static final String HEADER = "-----BEGIN";
    private static final String TRAILER = "-----END";

    // Constants:  KRA LDIF Record Fields
    private static final String KRA_LDIF_ARCHIVED_BY = "archivedBy:";
    private static final String KRA_LDIF_CN = "cn:";
    private static final String KRA_LDIF_DATE_OF_MODIFY = "dateOfModify:";
    private static final String KRA_LDIF_DN = "dn:";
    private static final String KRA_LDIF_DN_EMBEDDED_CN_DATA = "dn: cn";
    private static final String KRA_LDIF_EXTDATA_AUTH_TOKEN_USER = "extdata-auth--005ftoken;user:";
    private static final String KRA_LDIF_EXTDATA_AUTH_TOKEN_USER_DN = "extdata-auth--005ftoken;userdn:";
    private static final String KRA_LDIF_EXTDATA_KEY_RECORD = "extdata-keyrecord:";
    private static final String KRA_LDIF_EXTDATA_REQUEST_ID = "extdata-requestid:";
    private static final String KRA_LDIF_EXTDATA_REQUEST_NOTES = "extdata-requestnotes:";
    private static final String KRA_LDIF_EXTDATA_REQUEST_TYPE = "extdata-requesttype:";
    private static final String KRA_LDIF_EXTDATA_SERIAL_NUMBER = "extdata-serialnumber:";
    private static final String KRA_LDIF_PRIVATE_KEY_DATA = "privateKeyData::";
    private static final String KRA_LDIF_PUBLIC_KEY_DATA = "publicKeyData::";  // cross-scheme
    private static final String KRA_LDIF_REQUEST_ID = "requestId:";
    private static final String KRA_LDIF_REQUEST_TYPE = "requestType:";
    private static final String KRA_LDIF_SERIAL_NO = "serialno:";

    // Constants:  KRA LDIF Record Values
    private static final int INITIAL_LDIF_RECORD_CAPACITY = 0;
    private static final int EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH = 56;
    private static final int PRIVATE_KEY_DATA_FIRST_LINE_DATA_LENGTH = 60;
    private static final String KRA_LDIF_RECORD = "Generic";
    private static final String KRA_LDIF_CA_KEY_RECORD = "CA";
    private static final String KRA_LDIF_ENROLLMENT = "enrollment";
    private static final String KRA_LDIF_KEYGEN = "netkeyKeygen";
    private static final String KRA_LDIF_RECOVERY = "recovery";
    private static final String KRA_LDIF_TPS_KEY_RECORD = "TPS";
    private static final String KRA_LDIF_KEYRECOVERY = "netkeyKeyRecovery";

    // Constants:  KRA LDIF Record Messages
    private static final String KRA_LDIF_REWRAP_MESSAGE = "REWRAPPED the '"
                                                         + "existing "
                                                         + "symmetric "
                                                         + "session key"
                                                         + "' with the '";
    private static final String KRA_LDIF_RSA_MESSAGE = "-bit RSA public key' "
                                                     + "obtained from the "
                                                     + "target storage "
                                                     + "certificate";
    private static final String KRA_LDIF_USED_PWDFILE_MESSAGE =
                                    "USED source PKI security database "
                                            + "password file";
    private static final String KRA_LDIF_APPENDED_ID_OFFSET_MESSAGE =
                                    "APPENDED ID offset";
    private static final String KRA_LDIF_REMOVED_ID_OFFSET_MESSAGE =
                                    "REMOVED ID offset";
    private static final String KRA_LDIF_SOURCE_NAME_CONTEXT_MESSAGE =
                                    "RENAMED source KRA naming context '";
    private static final String KRA_LDIF_TARGET_NAME_CONTEXT_MESSAGE =
                                    "' to target KRA naming context '";
    private static final String KRA_LDIF_PROCESS_REQUESTS_AND_KEY_RECORDS_ONLY_MESSAGE =
            "PROCESSED requests and key records ONLY!";

    /*************/
    /* Variables */
    /*************/

    // Variables:  Calendar
    private static String mDateOfModify = null;

    // Variables: Command-Line Options
    private static boolean mRewrapFlag = false;
    private static boolean mPwdfileFlag = false;
    private static boolean mAppendIdOffsetFlag = false;
    private static boolean mRemoveIdOffsetFlag = false;
    private static boolean mKraNamingContextsFlag = false;
    private static boolean mProcessRequestsAndKeyRecordsOnlyFlag = false;
    private static boolean mUseOAEPKeyWrapAlg = false;
    private static boolean mVerboseFlag = false;

    // cross-scheme
    private static boolean mUseCrossSchemeFlag = false;
    private static boolean mUseNssForPayloadProcessing = false;
    private static boolean mRegenerateSessionKey = false;
    private static boolean mSkipRewrap = false;  // TEST ONLY - for validating LDIF transformations
    private static boolean mForceRSAKeypairTransfer = false;  // TEST ONLY - force Stage 2 RSA keypair method
    private static Boolean mSessionKeyDecisionMade = null;  // Cache user's regeneration decision
    private static int mSplitTargetLdifPerRecords = 0;  // Split output into multiple files after N records
    private static int mCurrentFileNumber = 1;  // Current output file number (for split mode)
    private static int mRecordsInCurrentFile = 0;  // Records written to current output file
    private static int mMandatoryNameValuePairs = 0;
    private static int mRewrapNameValuePairs = 0;
    private static int mPKISecurityDatabasePwdfileNameValuePairs = 0;
    private static int mAppendIdOffsetNameValuePairs = 0;
    private static int mRemoveIdOffsetNameValuePairs = 0;
    private static int mKraNamingContextNameValuePairs = 0;

    // Record processing counters
    private static int mProcessedKeyRecords = 0;
    private static int mFailedKeyRecords = 0;
    private static int mProcessedEntries = 0;  // cross-scheme: total entries written (for blank line logic)

    // Variables: Command-Line Values (Mandatory)
    private static String mKratoolCfgFilename = null;
    private static String mSourceLdifFilename = null;
    private static String mTargetLdifFilename = null;
    private static String mLogFilename = null;

    // Variables: Command-Line Values (Rewrap)
    private static String mSourcePKISecurityDatabasePath = null;
    private static String mSourceStorageTokenName = null;
    private static String mSourceStorageCertNickname = null;
    private static String mTargetStorageCertificateFilename = null;

    // Variables: Command-Line Values (Rewrap Password File)
    private static String mSourcePKISecurityDatabasePwdfile = null;
    private static String mSourceHsmTokenPwdfile = null;
    private static boolean mHsmPwdfileFlag = false;

    // Variables: Command-Line Values (ID Offset)
    private static BigInteger mAppendIdOffset = null;
    private static BigInteger mRemoveIdOffset = null;

    // Variables: Command-Line Values (KRA Naming Contexts)
    private static String mSourceKraNamingContext = null;
    private static String mTargetKraNamingContext = null;

    // Variables:  KRATOOL Config File Parameters of Interest
    private static Hashtable<String, Boolean> kratoolCfg = null;

    // Variables:  KRATOOL LDIF File Parameters of Interest
    private static Vector<String> record = null;
    private static Iterator<String> ldif_record = null;

    // Variables:  Logging
    private static boolean mDebug = false; // set 'true' for debug messages
    private static PrintWriter logger = null;
    private static String current_date_and_time = null;

    // Variables:  PKCS #11 Information
    private static CryptoToken mSourceToken = null;
    private static X509Certificate mUnwrapCert = null;
    private static PrivateKey mUnwrapPrivateKey = null;
    private static PublicKey mWrapPublicKey = null;
    private static int mPublicKeySize = 0;
    private static SymmetricKey.Type keyUnwrapAlgorithm = SymmetricKey.DES3;

    // Variables: Cross-scheme migration support
    private static String mSourceRSAWrapAlgName = null;  // User-specified source RSA algorithm
    private static String mTargetRSAWrapAlgName = null;  // User-specified target RSA algorithm
    private static String mSourcePayloadWrapAlgName = null;  // User-specified source payload algorithm (no size)
    private static String mTargetPayloadWrapAlgName = null;  // User-specified target payload algorithm (no size)
    private static int mSourcePayloadWrapKeySize = 128;  // Source payload key size (default: 128)
    private static int mTargetPayloadWrapKeySize = 128;  // Target payload key size (default: 128)
    private static KeyWrapAlgorithm mSourceRSAWrapAlg = KeyWrapAlgorithm.RSA;  // Actual source RSA algorithm (default: RSA)
    private static KeyWrapAlgorithm mTargetRSAWrapAlg = KeyWrapAlgorithm.RSA_OAEP;  // Actual target RSA algorithm (default: RSA_OAEP)
    private static IVParameterSpec mSourcePayloadWrappingIV = null;

    // cross-scheme: Temporary RSA keypair for session key transfer (performance optimization)
    // Generated once at startup and reused across all LDIF entries to avoid repeated keypair generation
    private static java.security.KeyPair mTempRSAKeyPair = null;  // Temporary RSA keypair for JSS_KeyExchange-style transfer
    private static boolean mTempRSAKeyPairInitialized = false;  // Track initialization status

    // cross-scheme: Cache for cloneKey capability (performance optimization)
    // Avoids millions of failed cloneKey attempts when HSM doesn't support extractable keys
    private enum CloneKeyCapability {
        UNTESTED,   // Not yet tested (first record)
        SUPPORTED,  // cloneKey works - use direct clone method
        UNSUPPORTED // cloneKey fails - use RSA keypair method
    }
    private static CloneKeyCapability mCloneKeyCapability = CloneKeyCapability.UNTESTED;

    // cross-scheme: Reusable SecureRandom instance (performance optimization)
    // SecureRandom initialization is expensive, so reuse across all IV generations
    private static final SecureRandom mSecureRandom = new SecureRandom();

    // cross-scheme: Reusable OAEP parameter spec for RSA-OAEP operations
    // Standard configuration: SHA-256 with MGF1-SHA256
    private static final OAEPParameterSpec OAEP_PARAMS = new OAEPParameterSpec(
        "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT
    );

    // cross-scheme: Cached payload algorithm objects and IV requirements (performance optimization)
    // Computed once at startup from mSourcePayloadWrapAlgName/mTargetPayloadWrapAlgName to avoid
    // repeated algorithm lookups and IV checks for every key record
    private static KeyWrapAlgorithm mSourcePayloadWrapAlg = null;
    private static KeyWrapAlgorithm mTargetPayloadWrapAlg = null;
    private static boolean mSourcePayloadNeedsIV = false;
    private static boolean mTargetPayloadNeedsIV = false;

    // Variables:  KRA LDIF Record Messages
    private static String mSourcePKISecurityDatabasePwdfileMessage = null;
    private static String mKraNamingContextMessage = null;
    private static String mProcessRequestsAndKeyRecordsOnlyMessage = null;

    /********************/
    /* Calendar Methods */
    /********************/

    /**
     * This method is used to get the current date and time.
     * <P>
     *
     * @param pattern string containing desired format of date and time
     * @return a formatted string containing the current date and time
     */
    private static String now(String pattern) {
        Calendar cal = Calendar.getInstance();
        SimpleDateFormat sdf = new SimpleDateFormat(pattern);
        return sdf.format(cal.getTime());
    }

    /*****************/
    /* Usage Methods */
    /*****************/

    /**
     * This method prints out the proper command-line usage required to
     * execute KRATool.
     */
    private static void printUsage() {
        System.out.println("Usage:  "
                          + KRA_TOOL
                          + NEWLINE
                          + "        "
                          + KRATOOL_CFG_FILE
                          + NEWLINE
                          + "        "
                          + KRATOOL_CFG_DESCRIPTION
                          + NEWLINE
                          + "        "
                          + SOURCE_LDIF_FILE
                          + NEWLINE
                          + "        "
                          + SOURCE_LDIF_DESCRIPTION
                          + NEWLINE
                          + "        "
                          + TARGET_LDIF_FILE
                          + NEWLINE
                          + "        "
                          + TARGET_LDIF_DESCRIPTION
                          + NEWLINE
                          + "        "
                          + LOG_FILE
                          + NEWLINE
                          + "        "
                          + LOG_DESCRIPTION
                          + NEWLINE
                          + "        "
                          + "["
                          + SOURCE_NSS_DB_PATH
                          + NEWLINE
                          + "        "
                          + SOURCE_NSS_DB_DESCRIPTION
                          + "]"
                          + NEWLINE
                          + "        "
                          + "["
                          + SOURCE_STORAGE_TOKEN_NAME
                          + NEWLINE
                          + "        "
                          + SOURCE_STORAGE_TOKEN_DESCRIPTION
                          + "]"
                          + NEWLINE
                          + "        "
                          + "["
                          + SOURCE_STORAGE_CERT_NICKNAME
                          + NEWLINE
                          + "        "
                          + SOURCE_STORAGE_CERT_NICKNAME_DESCRIPTION
                          + "]"
                          + NEWLINE
                          + "        "
                          + "["
                          + TARGET_STORAGE_CERTIFICATE_FILE
                          + NEWLINE
                          + "        "
                          + TARGET_STORAGE_CERTIFICATE_DESCRIPTION
                          + "]"
                          + NEWLINE
                          + "        "
                          + "["
                          + SOURCE_NSS_DB_PWDFILE
                          + NEWLINE
                          + "        "
                          + SOURCE_NSS_DB_PWDFILE_DESCRIPTION
                          + "]"
                          + NEWLINE
                          + "        "
                          + "["
                          + SOURCE_HSM_TOKEN_PWDFILE
                          + NEWLINE
                          + "        "
                          + SOURCE_HSM_TOKEN_PWDFILE_DESCRIPTION
                          + "]"
                          + NEWLINE
                          + "        "
                          + "["
                          + APPEND_ID_OFFSET
                          + NEWLINE
                          + "        "
                          + APPEND_ID_OFFSET_DESCRIPTION
                          + "]"
                          + NEWLINE
                          + "        "
                          + "["
                          + REMOVE_ID_OFFSET
                          + NEWLINE
                          + "        "
                          + REMOVE_ID_OFFSET_DESCRIPTION
                          + "]"
                          + NEWLINE
                          + "        "
                          + "["
                          + SOURCE_KRA_NAMING_CONTEXT
                          + NEWLINE
                          + "        "
                          + SOURCE_KRA_NAMING_CONTEXT_DESCRIPTION
                          + "]"
                          + NEWLINE
                          + "        "
                          + "["
                          + TARGET_KRA_NAMING_CONTEXT
                          + NEWLINE
                          + "        "
                          + TARGET_KRA_NAMING_CONTEXT_DESCRIPTION
                          + "]"
                          + NEWLINE
                          + "        "
                          + "["
                          + KEY_UNWRAP_ALGORITHM
                          + NEWLINE
                          + "        "
                          + KEY_UNWRAP_ALGORITHM_DESCRIPTION
                          + "]"
                          + NEWLINE
                          + "        "
                          + "["
                          + PROCESS_REQUESTS_AND_KEY_RECORDS_ONLY
                          + "]"
                          + NEWLINE
                          + "        "
                          + "["
                          + VERBOSE
                          + NEWLINE
                          + "        "
                          + VERBOSE_DESCRIPTION
                          + "]"
                          + NEWLINE
                          + NEWLINE
                          + "    --- Cross-Scheme Migration Options ---"
                          + NEWLINE
                          + "        "
                          + "["
                          + USE_CROSS_SCHEME
                          + NEWLINE
                          + "        "
                          + USE_CROSS_SCHEME_DESCRIPTION
                          + "]"
                          + NEWLINE
                          + "        "
                          + "["
                          + SOURCE_RSA_WRAP_ALGORITHM
                          + NEWLINE
                          + "        "
                          + SOURCE_RSA_WRAP_ALGORITHM_DESCRIPTION
                          + "]"
                          + NEWLINE
                          + "        "
                          + "["
                          + TARGET_RSA_WRAP_ALGORITHM
                          + NEWLINE
                          + "        "
                          + TARGET_RSA_WRAP_ALGORITHM_DESCRIPTION
                          + "]"
                          + NEWLINE
                          + "        "
                          + "["
                          + SOURCE_PAYLOAD_WRAP_ALGORITHM
                          + NEWLINE
                          + "        "
                          + SOURCE_PAYLOAD_WRAP_ALGORITHM_DESCRIPTION
                          + "]"
                          + NEWLINE
                          + "        "
                          + "["
                          + TARGET_PAYLOAD_WRAP_ALGORITHM
                          + NEWLINE
                          + "        "
                          + TARGET_PAYLOAD_WRAP_ALGORITHM_DESCRIPTION
                          + "]"
                          + NEWLINE
                          + "        "
                          + "["
                          + SOURCE_PAYLOAD_WRAP_KEYSIZE
                          + NEWLINE
                          + "        "
                          + SOURCE_PAYLOAD_WRAP_KEYSIZE_DESCRIPTION
                          + "]"
                          + NEWLINE
                          + "        "
                          + "["
                          + TARGET_PAYLOAD_WRAP_KEYSIZE
                          + NEWLINE
                          + "        "
                          + TARGET_PAYLOAD_WRAP_KEYSIZE_DESCRIPTION
                          + "]"
                          + NEWLINE
                          + "        "
                          + "["
                          + USE_NSS_FOR_PAYLOAD_PROCESSING
                          + NEWLINE
                          + "        "
                          + USE_NSS_FOR_PAYLOAD_PROCESSING_DESCRIPTION
                          + "]"
                          + NEWLINE
                          + "        "
                          + "["
                          + REGENERATE_SESSION_KEY
                          + NEWLINE
                          + "        "
                          + REGENERATE_SESSION_KEY_DESCRIPTION
                          + "]"
                          + NEWLINE
                          + "        "
                          + "["
                          + SPLIT_TARGET_LDIF_PER_RECORDS
                          + NEWLINE
                          + "        "
                          + SPLIT_TARGET_LDIF_PER_RECORDS_DESCRIPTION
                          + "]"
                          + NEWLINE
                          // Hidden from usage - internal testing only
                          // + "        "
                          // + "["
                          // + SKIP_REWRAP
                          // + NEWLINE
                          // + "        "
                          // + SKIP_REWRAP_DESCRIPTION
                          // + "]"
                          // + NEWLINE
                          );

        System.out.println("Example of 'Rewrap and Append ID Offset':"
                          + NEWLINE
                          + NEWLINE
                          + "        "
                          + KRA_TOOL
                          + NEWLINE
                          + "        "
                          + KRATOOL_CFG_FILE_EXAMPLE
                          + NEWLINE
                          + "        "
                          + SOURCE_LDIF_FILE_EXAMPLE
                          + NEWLINE
                          + "        "
                          + TARGET_LDIF_FILE_EXAMPLE
                          + NEWLINE
                          + "        "
                          + LOG_FILE_EXAMPLE
                          + NEWLINE
                          + "        "
                          + SOURCE_NSS_DB_PATH_EXAMPLE
                          + NEWLINE
                          + "        "
                          + SOURCE_STORAGE_TOKEN_NAME_EXAMPLE
                          + NEWLINE
                          + "        "
                          + SOURCE_STORAGE_CERT_NICKNAME_EXAMPLE
                          + NEWLINE
                          + "        "
                          + TARGET_STORAGE_CERTIFICATE_FILE_EXAMPLE
                          + NEWLINE
                          + "        "
                          + SOURCE_NSS_DB_PWDFILE_EXAMPLE
                          + NEWLINE
                          + "        "
                          + SOURCE_HSM_TOKEN_PWDFILE_EXAMPLE
                          + NEWLINE
                          + "        "
                          + APPEND_ID_OFFSET_EXAMPLE
                          + NEWLINE
                          + "        "
                          + SOURCE_KRA_NAMING_CONTEXT_EXAMPLE
                          + NEWLINE
                          + "        "
                          + TARGET_KRA_NAMING_CONTEXT_EXAMPLE
                          + NEWLINE
                          + "        "
                          + PROCESS_REQUESTS_AND_KEY_RECORDS_ONLY
                          + NEWLINE);

        System.out.println("Example of 'Rewrap and Remove ID Offset':"
                          + NEWLINE
                          + NEWLINE
                          + "        "
                          + KRA_TOOL
                          + NEWLINE
                          + "        "
                          + KRATOOL_CFG_FILE_EXAMPLE
                          + NEWLINE
                          + "        "
                          + SOURCE_LDIF_FILE_EXAMPLE
                          + NEWLINE
                          + "        "
                          + TARGET_LDIF_FILE_EXAMPLE
                          + NEWLINE
                          + "        "
                          + LOG_FILE_EXAMPLE
                          + NEWLINE
                          + "        "
                          + SOURCE_NSS_DB_PATH_EXAMPLE
                          + NEWLINE
                          + "        "
                          + SOURCE_STORAGE_TOKEN_NAME_EXAMPLE
                          + NEWLINE
                          + "        "
                          + SOURCE_STORAGE_CERT_NICKNAME_EXAMPLE
                          + NEWLINE
                          + "        "
                          + TARGET_STORAGE_CERTIFICATE_FILE_EXAMPLE
                          + NEWLINE
                          + "        "
                          + SOURCE_NSS_DB_PWDFILE_EXAMPLE
                          + NEWLINE
                          + "        "
                          + REMOVE_ID_OFFSET_EXAMPLE
                          + NEWLINE
                          + "        "
                          + SOURCE_KRA_NAMING_CONTEXT_EXAMPLE
                          + NEWLINE
                          + "        "
                          + TARGET_KRA_NAMING_CONTEXT_EXAMPLE
                          + NEWLINE
                          + "        "
                          + PROCESS_REQUESTS_AND_KEY_RECORDS_ONLY
                          + NEWLINE);

        System.out.println("Example of 'Rewrap':"
                          + NEWLINE
                          + NEWLINE
                          + "        "
                          + KRA_TOOL
                          + NEWLINE
                          + "        "
                          + KRATOOL_CFG_FILE_EXAMPLE
                          + NEWLINE
                          + "        "
                          + SOURCE_LDIF_FILE_EXAMPLE
                          + NEWLINE
                          + "        "
                          + TARGET_LDIF_FILE_EXAMPLE
                          + NEWLINE
                          + "        "
                          + LOG_FILE_EXAMPLE
                          + NEWLINE
                          + "        "
                          + SOURCE_NSS_DB_PATH_EXAMPLE
                          + NEWLINE
                          + "        "
                          + SOURCE_STORAGE_TOKEN_NAME_EXAMPLE
                          + NEWLINE
                          + "        "
                          + SOURCE_STORAGE_CERT_NICKNAME_EXAMPLE
                          + NEWLINE
                          + "        "
                          + TARGET_STORAGE_CERTIFICATE_FILE_EXAMPLE
                          + NEWLINE
                          + "        "
                          + SOURCE_NSS_DB_PWDFILE_EXAMPLE
                          + NEWLINE
                          + "        "
                          + SOURCE_KRA_NAMING_CONTEXT_EXAMPLE
                          + NEWLINE
                          + "        "
                          + TARGET_KRA_NAMING_CONTEXT_EXAMPLE
                          + NEWLINE
                          + "        "
                          + PROCESS_REQUESTS_AND_KEY_RECORDS_ONLY
                          + NEWLINE);

        System.out.println("Example of 'Append ID Offset':"
                          + NEWLINE
                          + NEWLINE
                          + "        "
                          + KRA_TOOL
                          + NEWLINE
                          + "        "
                          + KRATOOL_CFG_FILE_EXAMPLE
                          + NEWLINE
                          + "        "
                          + SOURCE_LDIF_FILE_EXAMPLE
                          + NEWLINE
                          + "        "
                          + TARGET_LDIF_FILE_EXAMPLE
                          + NEWLINE
                          + "        "
                          + LOG_FILE_EXAMPLE
                          + NEWLINE
                          + "        "
                          + APPEND_ID_OFFSET_EXAMPLE
                          + NEWLINE
                          + "        "
                          + SOURCE_KRA_NAMING_CONTEXT_EXAMPLE
                          + NEWLINE
                          + "        "
                          + TARGET_KRA_NAMING_CONTEXT_EXAMPLE
                          + NEWLINE
                          + "        "
                          + PROCESS_REQUESTS_AND_KEY_RECORDS_ONLY
                          + NEWLINE);

        System.out.println("Example of 'Remove ID Offset':"
                          + NEWLINE
                          + NEWLINE
                          + "        "
                          + KRA_TOOL
                          + NEWLINE
                          + "        "
                          + KRATOOL_CFG_FILE_EXAMPLE
                          + NEWLINE
                          + "        "
                          + SOURCE_LDIF_FILE_EXAMPLE
                          + NEWLINE
                          + "        "
                          + TARGET_LDIF_FILE_EXAMPLE
                          + NEWLINE
                          + "        "
                          + LOG_FILE_EXAMPLE
                          + NEWLINE
                          + "        "
                          + REMOVE_ID_OFFSET_EXAMPLE
                          + NEWLINE
                          + "        "
                          + SOURCE_KRA_NAMING_CONTEXT_EXAMPLE
                          + NEWLINE
                          + "        "
                          + TARGET_KRA_NAMING_CONTEXT_EXAMPLE
                          + NEWLINE
                          + "        "
                          + PROCESS_REQUESTS_AND_KEY_RECORDS_ONLY
                          + NEWLINE);

        System.out.println("Example of 'Cross-Scheme Migration with Session Key Regeneration':"
                          + NEWLINE
                          + NEWLINE
                          + "        "
                          + KRA_TOOL
                          + NEWLINE
                          + "        "
                          + KRATOOL_CFG_FILE_EXAMPLE
                          + NEWLINE
                          + "        "
                          + SOURCE_LDIF_FILE_EXAMPLE
                          + NEWLINE
                          + "        "
                          + TARGET_LDIF_FILE_EXAMPLE
                          + NEWLINE
                          + "        "
                          + LOG_FILE_EXAMPLE
                          + NEWLINE
                          + "        "
                          + SOURCE_NSS_DB_PATH_EXAMPLE
                          + NEWLINE
                          + "        "
                          + SOURCE_STORAGE_TOKEN_NAME_EXAMPLE
                          + NEWLINE
                          + "        "
                          + SOURCE_STORAGE_CERT_NICKNAME_EXAMPLE
                          + NEWLINE
                          + "        "
                          + TARGET_STORAGE_CERTIFICATE_FILE_EXAMPLE
                          + NEWLINE
                          + "        "
                          + SOURCE_NSS_DB_PWDFILE_EXAMPLE
                          + NEWLINE
                          + "        "
                          + USE_CROSS_SCHEME
                          + NEWLINE
                          + "        "
                          + SOURCE_RSA_WRAP_ALGORITHM + " RSA-OAEP"
                          + NEWLINE
                          + "        "
                          + TARGET_RSA_WRAP_ALGORITHM + " RSA-OAEP"
                          + NEWLINE
                          + "        "
                          + SOURCE_PAYLOAD_WRAP_ALGORITHM + " \"AES KeyWrap/Wrapped\""
                          + NEWLINE
                          + "        "
                          + TARGET_PAYLOAD_WRAP_ALGORITHM + " \"AES KeyWrap/Wrapped\""
                          + NEWLINE
                          + "        "
                          + REGENERATE_SESSION_KEY
                          + NEWLINE
                          + "        "
                          + SPLIT_TARGET_LDIF_PER_RECORDS + " 1000"
                          + NEWLINE
                          + NEWLINE
                          + "        "
                          + "NOTE: This example regenerates session keys with the same key size."
                          + NEWLINE
                          + "        "
                          + "      The -regenerate_session_key flag forces regeneration without prompt."
                          + NEWLINE
                          + "        "
                          + "      The -split_target_ldif_per_records creates separate files every 1000 records."
                          + NEWLINE);

        System.out.println("Example of 'Cross-Scheme Migration' (RSA+AES/CBC to RSA-OAEP+AES-KWP):"
                          + NEWLINE
                          + NEWLINE
                          + "        "
                          + KRA_TOOL
                          + NEWLINE
                          + "        "
                          + KRATOOL_CFG_FILE_EXAMPLE
                          + NEWLINE
                          + "        "
                          + SOURCE_LDIF_FILE_EXAMPLE
                          + NEWLINE
                          + "        "
                          + TARGET_LDIF_FILE_EXAMPLE
                          + NEWLINE
                          + "        "
                          + LOG_FILE_EXAMPLE
                          + NEWLINE
                          + "        "
                          + SOURCE_NSS_DB_PATH_EXAMPLE
                          + NEWLINE
                          + "        "
                          + SOURCE_STORAGE_TOKEN_NAME_EXAMPLE
                          + NEWLINE
                          + "        "
                          + SOURCE_STORAGE_CERT_NICKNAME_EXAMPLE
                          + NEWLINE
                          + "        "
                          + TARGET_STORAGE_CERTIFICATE_FILE_EXAMPLE
                          + NEWLINE
                          + "        "
                          + SOURCE_NSS_DB_PWDFILE_EXAMPLE
                          + NEWLINE
                          + "        "
                          + SOURCE_HSM_TOKEN_PWDFILE_EXAMPLE
                          + NEWLINE
                          + "        "
                          + USE_CROSS_SCHEME
                          + NEWLINE
                          + "        "
                          + SOURCE_RSA_WRAP_ALGORITHM + " RSA"
                          + NEWLINE
                          + "        "
                          + TARGET_RSA_WRAP_ALGORITHM + " RSA-OAEP"
                          + NEWLINE
                          + "        "
                          + SOURCE_PAYLOAD_WRAP_ALGORITHM + " \"AES/CBC/PKCS5Padding\""
                          + NEWLINE
                          + "        "
                          + TARGET_PAYLOAD_WRAP_ALGORITHM + " \"AES KeyWrap/Wrapped\""
                          + NEWLINE
                          + "        "
                          + SPLIT_TARGET_LDIF_PER_RECORDS + " 1000"
                          + NEWLINE
                          + NEWLINE
                          + "        "
                          + "NOTE: If the command fails during payload unwrap/rewrap with an error"
                          + NEWLINE
                          + "        "
                          + "      about unsupported algorithms, add the " + USE_NSS_FOR_PAYLOAD_PROCESSING
                          + NEWLINE
                          + "        "
                          + "      flag to perform payload operations in NSS DB (software token)."
                          + NEWLINE
                          + "        "
                          + "      The -split_target_ldif_per_records creates separate files every 1000 records."
                          + NEWLINE);

        System.out.println("Example of 'Cross-Scheme Migration with Software Token Fallback':"
                          + NEWLINE
                          + NEWLINE
                          + "        "
                          + KRA_TOOL
                          + NEWLINE
                          + "        "
                          + KRATOOL_CFG_FILE_EXAMPLE
                          + NEWLINE
                          + "        "
                          + SOURCE_LDIF_FILE_EXAMPLE
                          + NEWLINE
                          + "        "
                          + TARGET_LDIF_FILE_EXAMPLE
                          + NEWLINE
                          + "        "
                          + LOG_FILE_EXAMPLE
                          + NEWLINE
                          + "        "
                          + SOURCE_NSS_DB_PATH_EXAMPLE
                          + NEWLINE
                          + "        "
                          + SOURCE_STORAGE_TOKEN_NAME_EXAMPLE
                          + NEWLINE
                          + "        "
                          + SOURCE_STORAGE_CERT_NICKNAME_EXAMPLE
                          + NEWLINE
                          + "        "
                          + TARGET_STORAGE_CERTIFICATE_FILE_EXAMPLE
                          + NEWLINE
                          + "        "
                          + SOURCE_NSS_DB_PWDFILE_EXAMPLE
                          + NEWLINE
                          + "        "
                          + SOURCE_HSM_TOKEN_PWDFILE_EXAMPLE
                          + NEWLINE
                          + "        "
                          + USE_CROSS_SCHEME
                          + NEWLINE
                          + "        "
                          + SOURCE_RSA_WRAP_ALGORITHM + " RSA"
                          + NEWLINE
                          + "        "
                          + TARGET_RSA_WRAP_ALGORITHM + " RSA-OAEP"
                          + NEWLINE
                          + "        "
                          + SOURCE_PAYLOAD_WRAP_ALGORITHM + " \"AES/CBC/PKCS5Padding\""
                          + NEWLINE
                          + "        "
                          + TARGET_PAYLOAD_WRAP_ALGORITHM + " \"AES KeyWrap/Wrapped\""
                          + NEWLINE
                          + "        "
                          + SOURCE_PAYLOAD_WRAP_KEYSIZE + " 128"
                          + NEWLINE
                          + "        "
                          + TARGET_PAYLOAD_WRAP_KEYSIZE + " 256"
                          + NEWLINE
                          + "        "
                          + USE_NSS_FOR_PAYLOAD_PROCESSING
                          + NEWLINE
                          + NEWLINE
                          + "        "
                          + "NOTE: Use this option when the HSM does not support the target payload"
                          + NEWLINE
                          + "        "
                          + "      wrap algorithm (e.g., AES KeyWrap/Wrapped). Payload unwrap/rewrap will"
                          + NEWLINE
                          + "        "
                          + "      be performed in NSS DB (software token). Session key operations"
                          + NEWLINE
                          + "        "
                          + "      still use the HSM."
                          + NEWLINE
                          + "        "
                          + "      This example also demonstrates key size change (without specification of \"-regenerate_session_key\")"
                          + NEWLINE
                          + "        "
                          + "      from 128-bit to 256-bit, which will trigger automatic session key"
                          + NEWLINE
                          + "        "
                          + "      regeneration with user confirmation."
                          + NEWLINE);
    }

    /*******************/
    /* Logging Methods */
    /*******************/

    /**
     * This method opens a new log file for writing.
     * <P>
     *
     * @param logfile string containing the name of the log file to be opened
     */
    private static void open_log(String logfile) {
        try {
            logger = new PrintWriter(
                         new BufferedWriter(
                                 new FileWriter(logfile)));
        } catch (IOException eFile) {
            System.err.println("ERROR:  Unable to open file '"
                              + logfile
                              + "' for writing: '"
                              + eFile.toString()
                              + "'"
                              + NEWLINE);
            System.exit(0);
        }
    }

    /**
     * This method closes the specified log file.
     * <P>
     *
     * @param logfile string containing the name of the log file to be closed
     */
    private static void close_log(String logfile) {
        logger.close();
    }

    /**
     * This method writes the specified message to the log file, and also
     * to 'stderr' if the boolean flag is set to 'true'.
     * <P>
     *
     * @param msg string containing the message to be written to the log file
     * @param stderr boolean which also writes the message to 'stderr' if 'true'
     */
    private static void log(String msg, boolean stderr) {
        current_date_and_time = now(LOGGING_DATE_PATTERN);
        if (stderr) {
            System.err.println(msg);
        }
        logger.write("["
                    + current_date_and_time
                    + "]:  "
                    + msg);
        logger.flush();
    }

    /*********************************************/
    /* PKCS #11:  Rewrap RSA Storage Key Methods */
    /*********************************************/

    /**
     * Helper method to determine if two arrays contain the same values.
     *
     * This method is based upon code from 'com.netscape.kra.StorageKeyUnit'.
     * <P>
     *
     * @param bytes first array of bytes
     * @param ints second array of bytes
     * @return true if the two arrays are identical
     */
    private static boolean arraysEqual(byte[] bytes, byte[] ints) {
        if (bytes == null || ints == null) {
            return false;
        }

        if (bytes.length != ints.length) {
            return false;
        }

        for (int i = 0; i < bytes.length; i++) {
            if (bytes[i] != ints[i]) {
                return false;
            }
        }

        return true;
    }

    /**
     * This method is used to obtain the private RSA storage key from
     * the "source" KRA instance's crypto token.
     * This key is used to unwrap session keys from archived data.
     *
     * This method is based upon code from 'com.netscape.kra.StorageKeyUnit'.
     * <P>
     *
     * @return the private RSA storage key from the "source" KRA
     */
    private static PrivateKey getStoragePrivateKey() {
        try {
            PrivateKey pk[] = mSourceToken.getCryptoStore().getPrivateKeys();

            for (int i = 0; i < pk.length; i++) {
                if (arraysEqual(pk[i].getUniqueID(),
                                  ((TokenCertificate)
                                    mUnwrapCert).getUniqueID())) {
                    return pk[i];
                }
            }
        } catch (TokenException exToken) {
            log("ERROR:  Getting storage private key - "
                    + "TokenException: '"
                    + exToken.toString()
                    + "'"
                    + NEWLINE, true);
            System.exit(0);
        }

        return null;
    }

    /**
     * Gets the target KRA storage public key from the certificate file.
     * This key is used to unwrap session keys for the target KRA.
     * Also obtains the keysize of this RSA key.
     *
     * This method is based upon code from
     * 'com.netscape.cmstools.PrettyPrintCert'.
     * <P>
     *
     * @return the public RSA storage key from the "target" KRA
     */
    private static PublicKey getStoragePublicKey() {
        BufferedReader inputCert = null;
        String encodedBASE64CertChunk;
        StringBuilder encodedBASE64Cert = new StringBuilder();
        byte decodedBASE64Cert[] = null;
        X509CertImpl cert = null;
        PublicKey key = null;
        RSAPublicKey rsakey = null;

        // Create a DataInputStream() object to the BASE 64
        // encoded certificate contained within the file
        // specified on the command line
        try {
            inputCert = new BufferedReader(
                            new InputStreamReader(
                                    new BufferedInputStream(
                                            new FileInputStream(
                                                    mTargetStorageCertificateFilename
                                            ))));
        } catch (FileNotFoundException exWrapFileNotFound) {
            log("ERROR:  No target storage "
                    + "certificate file named '"
                    + mTargetStorageCertificateFilename
                    + "' exists!  FileNotFoundException: '"
                    + exWrapFileNotFound.toString()
                    + "'"
                    + NEWLINE, true);
            System.exit(0);
        }

        // Read the entire contents of the specified BASE 64 encoded
        // certificate into a String() object throwing away any
        // headers beginning with HEADER and any trailers beginning
        // with TRAILER
        try {
            while ((encodedBASE64CertChunk = inputCert.readLine()) != null) {
                if (!(encodedBASE64CertChunk.startsWith(HEADER)) &&
                        !(encodedBASE64CertChunk.startsWith(TRAILER))) {
                    encodedBASE64Cert.append(encodedBASE64CertChunk.trim());
                }
            }
        } catch (IOException exWrapReadLineIO) {
            log("ERROR:  Unexpected BASE64 "
                    + "encoded error encountered while reading '"
                    + mTargetStorageCertificateFilename
                    + "'!  IOException: '"
                    + exWrapReadLineIO.toString()
                    + "'"
                    + NEWLINE, true);
            System.exit(0);
        }

        // Close the DataInputStream() object
        try {
            inputCert.close();
        } catch (IOException exWrapCloseIO) {
            log("ERROR:  Unexpected BASE64 "
                    + "encoded error encountered in closing '"
                    + mTargetStorageCertificateFilename
                    + "'!  IOException: '"
                    + exWrapCloseIO.toString()
                    + "'"
                    + NEWLINE, true);
            System.exit(0);
        }

        // Decode the ASCII BASE 64 certificate enclosed in the
        // String() object into a BINARY BASE 64 byte[] object
        decodedBASE64Cert = Utils.base64decode(
                                encodedBASE64Cert.toString());

        // Create an X509CertImpl() object from
        // the BINARY BASE 64 byte[] object
        try {
            cert = new X509CertImpl(decodedBASE64Cert);
        } catch (CertificateException exWrapCertificate) {
            log("ERROR:  Error encountered "
                    + "in parsing certificate in '"
                    + mTargetStorageCertificateFilename
                    + "'  CertificateException: '"
                    + exWrapCertificate.toString()
                    + "'"
                    + NEWLINE, true);
            System.exit(0);
        }

        // Extract the Public Key
        key = cert.getPublicKey();
        if (key == null) {
            log("ERROR:  Unable to extract public key "
                    + "from certificate that was stored in '"
                    + mTargetStorageCertificateFilename
                    + "'."
                    + NEWLINE, true);
            System.exit(0);
        }

        // Convert this X.509 public key --> RSA public key
        try {
            rsakey = new RSAPublicKey(key.getEncoded());
        } catch (InvalidKeyException exInvalidKey) {
            log("ERROR:  Converting X.509 public key --> RSA public key - "
                    + "InvalidKeyException: '"
                    + exInvalidKey.toString()
                    + "'"
                    + NEWLINE, true);
            System.exit(0);
        }

        // Obtain the Public Key's keysize
        mPublicKeySize = rsakey.getKeySize();

        return key;
    }

    /**
     * This method is used to obtain the private RSA storage key
     * from the "source" KRA instance's crypto token and
     * the public RSA storage key from the certificate stored in
     * the "target" KRA storage certificate file.
     * <P>
     *
     * @return true if successfully able to obtain both keys
     */
    private static boolean obtain_RSA_rewrapping_keys() {
        CryptoManager cm = null;

        // Initialize the source security databases
        try {
            log("Initializing source PKI security databases in '"
                    + mSourcePKISecurityDatabasePath + "'."
                    + NEWLINE, true);

            CryptoManager.initialize(mSourcePKISecurityDatabasePath);

        } catch (KeyDatabaseException exKey) {
            log("ERROR:  source_pki_security_database_path='"
                    + mSourcePKISecurityDatabasePath
                    + "' KeyDatabaseException: '"
                    + exKey.toString()
                    + "'"
                    + NEWLINE, true);
            System.exit(0);
        } catch (CertDatabaseException exCert) {
            log("ERROR:  source_pki_security_database_path='"
                    + mSourcePKISecurityDatabasePath
                    + "' CertDatabaseException: '"
                    + exCert.toString()
                    + "'"
                    + NEWLINE, true);
            System.exit(0);
        } catch (AlreadyInitializedException exAlreadyInitialized) {
            log("ERROR:  source_pki_security_database_path='"
                    + mSourcePKISecurityDatabasePath
                    + "' AlreadyInitializedException: '"
                    + exAlreadyInitialized.toString()
                    + "'"
                    + NEWLINE, true);
            System.exit(0);
        } catch (GeneralSecurityException exSecurity) {
            log("ERROR:  source_pki_security_database_path='"
                    + mSourcePKISecurityDatabasePath
                    + "' GeneralSecurityException: '"
                    + exSecurity.toString()
                    + "'"
                    + NEWLINE, true);
            System.exit(0);
        }

        // Retrieve the source storage token by its name
        try {
            log("Retrieving token from CryptoManager."
                    + NEWLINE, true);
            if (cm == null) {
                cm = CryptoManager.getInstance();
            }

            log("Retrieving source storage token called '"
                    + mSourceStorageTokenName
                    + "'."
                    + NEWLINE, true);

            mSourceToken = CryptoUtil.getKeyStorageToken(mSourceStorageTokenName);

            if (mSourceToken == null) {
                return FAILURE;
            }

            // Login to token with appropriate password
            if (mPwdfileFlag || mHsmPwdfileFlag) {
                BufferedReader in = null;
                String pwd = null;
                String pwdfile = null;

                try {
                    // Use HSM password file if provided, otherwise use NSS DB password file
                    if (mHsmPwdfileFlag) {
                        pwdfile = mSourceHsmTokenPwdfile;
                    } else {
                        pwdfile = mSourcePKISecurityDatabasePwdfile;
                    }

                    in = new BufferedReader(
                             new FileReader(pwdfile));
                    pwd = in.readLine();
                    if (pwd == null) {
                        pwd = "";
                    }

                    Password mPwd = new Password(pwd.toCharArray());
                    try {
                        mSourceToken.login(mPwd);
                    } finally {
                        mPwd.clear();
                    }
                } catch (Exception exReadPwd) {
                    log("ERROR:  Failed to read the keydb password from "
                            + "the file '"
                            + pwdfile
                            + "'.  Exception: '"
                            + exReadPwd.toString()
                            + "'"
                            + NEWLINE, true);
                    System.exit(0);
                } finally {
                    if (in != null) {
                        try {
                            in.close();
                        } catch (IOException e) {
                            log("Error closing input stream: " + e.getMessage(), true);
                            if (mVerboseFlag) {
                                e.printStackTrace();
                            }
                        }
                    }
                }
            }
        } catch (Exception exUninitialized) {
            log("ERROR:  Uninitialized CryptoManager - '"
                    + exUninitialized.toString()
                    + "'"
                    + NEWLINE, true);
            System.exit(0);
        }

        // Retrieve the source storage cert by its nickname
        try {
            if (mSourceStorageTokenName.equals(CryptoUtil.INTERNAL_TOKEN_FULL_NAME)) {
                log("Retrieving source storage cert with nickname of '"
                        + mSourceStorageCertNickname
                        + "'."
                        + NEWLINE, true);

                mUnwrapCert = cm.findCertByNickname(mSourceStorageCertNickname);
            } else {
                log("Retrieving source storage cert with nickname of '"
                        + mSourceStorageTokenName
                        + ":"
                        + mSourceStorageCertNickname
                        + "'. "
                        + NEWLINE, true);
                mUnwrapCert = cm.findCertByNickname(mSourceStorageTokenName
                                                   + ":"
                                                   + mSourceStorageCertNickname
                                                   );
            }

            if (mUnwrapCert == null) {
                return FAILURE;
            }
        } catch (ObjectNotFoundException exUnwrapObjectNotFound) {
            if (mSourceStorageTokenName.equals(CryptoUtil.INTERNAL_TOKEN_FULL_NAME)) {
                log("ERROR:  No internal "
                        + "source storage cert named '"
                        + mSourceStorageCertNickname
                        + "' exists!  ObjectNotFoundException: '"
                        + exUnwrapObjectNotFound.toString()
                        + "'"
                        + NEWLINE, true);
            } else {
                log("ERROR:  No "
                        + "source storage cert named '"
                        + mSourceStorageTokenName
                        + ":"
                        + mSourceStorageCertNickname
                        + "' exists!  ObjectNotFoundException: '"
                        + exUnwrapObjectNotFound
                        + "'"
                        + NEWLINE, true);
            }
            System.exit(0);
        } catch (TokenException exUnwrapToken) {
            if (mSourceStorageTokenName.equals(CryptoUtil.INTERNAL_TOKEN_FULL_NAME)) {
                log("ERROR:  No internal "
                        + "source storage cert named '"
                        + mSourceStorageCertNickname
                        + "' exists!  TokenException: '"
                        + exUnwrapToken.toString()
                        + "'"
                        + NEWLINE, true);
            } else {
                log("ERROR:  No "
                        + "source storage cert named '"
                        + mSourceStorageTokenName
                        + ":"
                        + mSourceStorageCertNickname
                        + "' exists!  TokenException: '"
                        + exUnwrapToken
                        + "'"
                        + NEWLINE, true);
            }
            System.exit(0);
        }

        // Extract the private key from the source storage token
        log("BEGIN: Obtaining the private key from "
                + "the source storage token . . ."
                + NEWLINE, true);

        mUnwrapPrivateKey = getStoragePrivateKey();

        if (mUnwrapPrivateKey == null) {
            log("ERROR:  Failed extracting "
                    + "private key from the source storage token."
                    + NEWLINE, true);
            System.exit(0);
        }

        log("FINISHED: Obtaining the private key from "
                + "the source storage token."
                + NEWLINE, true);

        // Extract the public key from the target storage certificate
        try {
            log("BEGIN: Obtaining the public key from "
                    + "the target storage certificate . . ."
                    + NEWLINE, true);

            mWrapPublicKey = PK11PubKey.fromSPKI(
                     getStoragePublicKey().getEncoded());

            if (mWrapPublicKey == null) {
                log("ERROR:  Failed extracting "
                        + "public key from target storage certificate stored in '"
                        + mTargetStorageCertificateFilename
                        + "'"
                        + NEWLINE, true);
                System.exit(0);
            }

            log("FINISHED: Obtaining the public key from "
                    + "the target storage certificate."
                    + NEWLINE, true);
        } catch (InvalidKeyFormatException exInvalidPublicKey) {
            log("ERROR:  Failed extracting "
                    + "public key from target storage certificate stored in '"
                    + mTargetStorageCertificateFilename
                    + "' InvalidKeyFormatException '"
                    + exInvalidPublicKey.toString()
                    + "'"
                    + NEWLINE, true);
            System.exit(0);
        }

        return SUCCESS;
    }

    /**
     * cross-scheme support: Extract the base algorithm family from a full algorithm specification.
     * Strips key size and wrapping mechanism to get just the algorithm family.
     * E.g., "AES/CBC/PKCS5Padding" -> "AES"
     *       "AES128/CBC/PKCS5Padding" -> "AES"
     *       "AES256 KeyWrap/Wrapped" -> "AES"
     *       "AES KeyWrap/Wrapped" -> "AES"
     *       "DES3/CBC/PKCS5Padding" -> "DES3"
     */
    private static String getBaseAlgorithm(String fullAlgorithm) {
        if (fullAlgorithm == null) return null;

        // First extract everything before the first '/' (if any)
        int slashIndex = fullAlgorithm.indexOf('/');
        String base = slashIndex > 0 ? fullAlgorithm.substring(0, slashIndex) : fullAlgorithm;

        // Now strip key size and wrapping mechanism keywords
        // Remove key sizes (128, 192, 256)
        base = base.replaceAll("128|192|256", "");

        // Remove wrapping mechanism keywords (KeyWrap, KWP, etc.)
        // Use simple string replacements to avoid regex backtracking vulnerabilities
        base = base.replace("KeyWrap", "").replace("KWP", "");

        // Trim any remaining whitespace
        base = base.trim();

        return base;
    }

    /**
     * cross-scheme support: Get key size for payload wrap algorithm.
     * For source/target algorithms, uses the explicit size parameters.
     * For other algorithms, returns default of 128 for AES.
     */
    private static int getKeySizeFromAlgorithm(String algorithm) {
        if (algorithm == null) return 128;

        // For source/target payload algorithms, use explicit size parameters
        if (algorithm.equals(mSourcePayloadWrapAlgName)) {
            return mSourcePayloadWrapKeySize;
        }
        if (algorithm.equals(mTargetPayloadWrapAlgName)) {
            return mTargetPayloadWrapKeySize;
        }

        // Default to 128 for AES (all algorithms are just names like "AES KeyWrap/Wrapped", no embedded sizes)
        return 128;
    }

    /**
     * cross-scheme support: Convert payload algorithm string to JSS KeyWrapAlgorithm.
     * E.g., "AES/CBC/PKCS5Padding" -> KeyWrapAlgorithm.AES_CBC_PAD
     *       "AES KeyWrap/Wrapped" -> KeyWrapAlgorithm.AES_KEY_WRAP_PAD_KWP
     *       "AES KeyWrap/Padding" -> KeyWrapAlgorithm.AES_KEY_WRAP_PAD
     *       "AES KeyWrap/NoPadding" -> KeyWrapAlgorithm.AES_KEY_WRAP
     */
    private static KeyWrapAlgorithm getPayloadWrapAlgorithm(String algName) throws Exception {
        if (algName == null) {
            throw new Exception("Payload wrap algorithm name is null");
        }

        // Map algorithm strings to JSS KeyWrapAlgorithm
        if (algName.contains("AES") && algName.contains("CBC")) {
            // AES/CBC/PKCS5Padding
            return KeyWrapAlgorithm.AES_CBC_PAD;
        } else if (algName.contains("AES") && algName.contains("KeyWrap")) {
            // Distinguish between different AES KeyWrap variants
            if (algName.contains("Wrapped") || algName.contains("KWP")) {
                // "AES KeyWrap/Wrapped" -> CKM_AES_KEY_WRAP_KWP (0x210B)
                return KeyWrapAlgorithm.AES_KEY_WRAP_PAD_KWP;
            } else if (algName.contains("Padding")) {
                // "AES KeyWrap/Padding" -> CKM_AES_KEY_WRAP_PAD (0x210A)
                return KeyWrapAlgorithm.AES_KEY_WRAP_PAD;
            } else if (algName.contains("NoPadding")) {
                // "AES KeyWrap/NoPadding" -> CKM_AES_KEY_WRAP (0x2109)
                return KeyWrapAlgorithm.AES_KEY_WRAP;
            } else {
                // Default to PAD for backward compatibility
                return KeyWrapAlgorithm.AES_KEY_WRAP_PAD;
            }
        } else if (algName.contains("DES3") || algName.contains("DESede")) {
            return KeyWrapAlgorithm.DES3_CBC_PAD;
        }

        throw new Exception("Unsupported payload wrap algorithm: " + algName);
    }

    /**
     * cross-scheme support: Determine if IV is needed for the given algorithm.
     * Uses JSS API to check if algorithm accepts IVParameterSpec parameters.
     * Returns true for CBC modes, false for KeyWrap modes.
     */
    private static boolean needsIV(KeyWrapAlgorithm alg) {
        if (alg == null) return false;

        // Query the algorithm's parameter classes
        Class<?>[] paramClasses = alg.getParameterClasses();
        if (paramClasses == null || paramClasses.length == 0) {
            return false;  // No parameters = no IV needed (e.g., KeyWrap modes)
        }

        // Check if any parameter class is IVParameterSpec
        for (Class<?> paramClass : paramClasses) {
            if (IVParameterSpec.class.isAssignableFrom(paramClass)) {
                return true;  // Algorithm accepts IV (e.g., CBC modes)
            }
        }

        return false;
    }

    /**
     * cross-scheme support: Parses a PublicKey from LDIF publicKeyData field.
     *
     * @param publicKeyData X.509 SubjectPublicKeyInfo DER bytes
     * @return PublicKey object
     */
    private static PublicKey parsePublicKeyFromLDIF(byte[] publicKeyData) throws Exception {
        if (publicKeyData == null || publicKeyData.length == 0) {
            throw new Exception("publicKeyData is null or empty");
        }

        try {
            // Parse X.509 SubjectPublicKeyInfo format and convert to PK11PubKey
            // HSM operations require PKCS#11 format (PK11PubKey), not generic X509Key
            // This is essential for both RSA and ECC keys when unwrapping on HSM
            X509Key x509Key = new X509Key();
            x509Key.decode(publicKeyData);

            // Convert to PK11PubKey for HSM compatibility
            PK11PubKey pk11Key = PK11PubKey.fromSPKI(publicKeyData);
            return pk11Key;
        } catch (Exception e) {
            System.err.println("ERROR: Failed to parse public key: " + e.getMessage());
            throw new Exception("Failed to parse publicKeyData from LDIF", e);
        }
    }

    /**
     * cross-scheme support: Generates a random IV for the given wrap algorithm.
     *
     * @param wrapAlg Key wrap algorithm
     * @return IV parameter spec
     */
    private static IVParameterSpec generateIV(KeyWrapAlgorithm wrapAlg) throws Exception {
        int ivLength;

        // Determine IV length based on algorithm
        if (wrapAlg == KeyWrapAlgorithm.AES_CBC_PAD) {
            ivLength = 16;  // AES block size
        } else if (wrapAlg == KeyWrapAlgorithm.DES3_CBC_PAD) {
            ivLength = 8;   // DES block size
        } else {
            throw new Exception("Cannot generate IV for algorithm: " + wrapAlg);
        }

        // Generate random IV using reusable SecureRandom instance
        byte[] iv = new byte[ivLength];
        mSecureRandom.nextBytes(iv);

        return new IVParameterSpec(iv);
    }

    /**
     * cross-scheme support: Converts session key wrap algorithm name to KeyWrapAlgorithm.
     *
     * @param algName Algorithm name (e.g., "RSA", "RSA-OAEP")
     * @return KeyWrapAlgorithm constant
     */
    private static KeyWrapAlgorithm getSessionKeyWrapAlgorithm(String algName) throws Exception {
        if (algName == null) {
            throw new Exception("Session key wrap algorithm name is null");
        }

        if (algName.equalsIgnoreCase("RSA")) {
            return KeyWrapAlgorithm.RSA;
        } else if (algName.equalsIgnoreCase("RSA-OAEP") ||
                   algName.equalsIgnoreCase("RSA_OAEP") ||
                   algName.equalsIgnoreCase("RSAES-OAEP") ||
                   algName.contains("OAEP")) {
            return KeyWrapAlgorithm.RSA_OAEP;
        }

        throw new Exception("Unsupported session key wrap algorithm: " + algName);
    }
    /**
     * cross-scheme support: Determines whether a new session key needs to be generated.
     * Returns true if:
     * - User explicitly requested regeneration (-regenerate_session_key flag)
     * - Algorithm family changed (e.g., DES3 -> AES) AND user confirms
     * - Key size changed (e.g., 128-bit -> 256-bit) AND user confirms
     *
     * @return true if new session key needed, false otherwise
     */
    private static boolean needNewSessionKey() throws Exception {
        // If user explicitly set the flag, always regenerate
        if (mRegenerateSessionKey) {
            if (mSessionKeyDecisionMade == null) {
                log("User requested session key regeneration" + NEWLINE, false);
                mSessionKeyDecisionMade = true;
            }
            return true;
        }

        // If we already made the decision (prompted user), return cached result
        if (mSessionKeyDecisionMade != null) {
            return mSessionKeyDecisionMade;
        }

        // First time checking - analyze algorithms
        String sourceBase = getBaseAlgorithm(mSourcePayloadWrapAlgName);
        String targetBase = getBaseAlgorithm(mTargetPayloadWrapAlgName);

        // Use explicit key size parameters (default to 128 if not specified)
        int sourceWrapKeySize = mSourcePayloadWrapKeySize;
        int targetWrapKeySize = mTargetPayloadWrapKeySize;

        // Determine the change type and prompt accordingly
        boolean isRequired = false;
        String message;

        if (!sourceBase.equals(targetBase)) {
            // Algorithm family changed - regeneration required
            isRequired = true;
            message = "Algorithm family is changing from " + sourceBase + " to " + targetBase + ".";
        } else if (sourceWrapKeySize != targetWrapKeySize) {
            // Key size changed - regeneration required
            isRequired = true;
            message = "Key size is changing from " + sourceWrapKeySize + "-bit to " + targetWrapKeySize + "-bit " + sourceBase + ".";
        } else {
            // Nothing changed - offer optional regeneration
            message = "Key type and size remain the same: " + sourceWrapKeySize + "-bit " + sourceBase + ".";
        }

        boolean decision = promptUserForSessionKeyRegeneration(message, isRequired);
        mSessionKeyDecisionMade = decision;  // Cache decision

        if (decision) {
            log("User chose to regenerate session key" + NEWLINE, false);
        } else {
            log("User chose to reuse existing session key" + NEWLINE, false);
        }

        return decision;
    }

    /**
     * cross-scheme support: Prompts user to confirm session key regeneration.
     *
     * @param message The message explaining the situation
     * @param isRequired Whether regeneration is required (true) or optional (false)
     * @return true if user confirms, false otherwise
     */
    private static boolean promptUserForSessionKeyRegeneration(String message, boolean isRequired) throws Exception {
        System.out.println();
        System.out.println(message);

        if (isRequired) {
            System.out.println("Session key regeneration is REQUIRED.");
            System.out.println();
            System.out.print("Proceed with key regeneration for all session keys? (y/n): ");
        } else {
            System.out.println("Would you like to regenerate all session keys anyway (for security/compliance)?");
            System.out.println();
            System.out.print("Regenerate session keys? (y/n): ");
        }
        System.out.flush();

        try {
            java.io.BufferedReader reader = new java.io.BufferedReader(
                new java.io.InputStreamReader(System.in));
            String response = reader.readLine();

            if (response != null && (response.equalsIgnoreCase("y") || response.equalsIgnoreCase("yes"))) {
                return true;
            }
            return false;
        } catch (Exception e) {
            throw new Exception("Failed to read user input: " + e.getMessage(), e);
        }
    }

    /**
     * cross-scheme support: Initializes the temporary RSA keypair used for session key transfer.
     *
     * This temporary keypair is generated ONCE and reused across all LDIF entries for performance.
     *
     * Based on JSS_KeyExchange mechanism (jssutil.c:1146-1241):
     * - Generates 2048-bit RSA keypair on processing token
     * - Marked as temporary (session-based) - auto-deleted when token closes
     * - Used to wrap/unwrap session keys between source HSM and processing token
     *
     * @param processingToken Token where keypair will be generated (HSM or NSS DB)
     */
    private static void initTempRSAKeyPair(CryptoToken processingToken) throws Exception {
        if (mTempRSAKeyPairInitialized) {
            log("Temporary RSA keypair already initialized" + NEWLINE, false);
            return;
        }

        log("Generating temporary 2048-bit RSA keypair on processing token for session key transfer" + NEWLINE, false);
        log("This keypair will be reused across all LDIF entries (performance optimization)" + NEWLINE, false);

        try {
            KeyPairGenerator kpg = processingToken.getKeyPairGenerator(KeyPairAlgorithm.RSA);
            kpg.initialize(2048);
            kpg.temporaryPairs(true);  // Session-based, auto-deleted
            kpg.sensitivePairs(true);  // Sensitive private key (matches JSS_KeyExchange)

            // Set operation flags to match JSS_KeyExchange: CKF_WRAP | CKF_UNWRAP | CKF_DECRYPT | CKF_ENCRYPT
            // This is required for some HSMs that strictly enforce operation flags
            KeyPairGeneratorSpi.Usage[] usages = new KeyPairGeneratorSpi.Usage[] {
                KeyPairGeneratorSpi.Usage.WRAP,
                KeyPairGeneratorSpi.Usage.UNWRAP,
                KeyPairGeneratorSpi.Usage.DECRYPT,
                KeyPairGeneratorSpi.Usage.ENCRYPT
            };
            kpg.setKeyPairUsages(usages, usages);

            mTempRSAKeyPair = kpg.genKeyPair();
            mTempRSAKeyPairInitialized = true;

            log("Temporary RSA keypair generated successfully" + NEWLINE, false);
        } catch (Exception e) {
            log("ERROR: Failed to generate temporary RSA keypair: " + e.getMessage() + NEWLINE, true);
            throw new Exception("Failed to initialize temporary RSA keypair for session key transfer", e);
        }
    }

    /**
     * cross-scheme support: Imports a session key from one token to another.
     *
     * This method implements the complete JSS_KeyExchange mechanism in pure Java using
     * existing JSS APIs, avoiding the need to modify JSS or expose internal C functions.
     *
     * Two-stage approach:
     * 1. First, attempt direct cloneKey() (requires extractable session key)
     * 2. If that fails, use JSS_KeyExchange-style temporary RSA keypair approach
     *
     * JSS_KeyExchange mechanism (implemented in pure Java):
     * 1. Generate temporary RSA keypair on processing token (done once at startup)
     * 2. Wrap session key with temp RSA public key on source token (using RSA-OAEP)
     * 3. Unwrap session key with temp RSA private key on processing token
     * 4. Temp keypair auto-deleted (marked temporary/session-based)
     *
     * Reference: JSS_ExportEncryptedPrivKeyInfoV2 -> JSS_KeyExchange in jssutil.c:1146-1241
     *
     * @param sessionKey Session key to import (from source token)
     * @param processingToken Token for processing (HSM or NSS DB)
     * @return Session key in processing token
     */
    private static SymmetricKey importSessionKeyToToken(
            SymmetricKey sessionKey,
            CryptoToken processingToken) throws Exception {

        if (mVerboseFlag) {
            log("Importing session key to processing token" + NEWLINE, false);
        }

        // cross-scheme: If same token, just return the original key
        if (sessionKey.getOwningToken() == processingToken) {
            if (mVerboseFlag) {
                log("Session key already on processing token" + NEWLINE, false);
            }
            return sessionKey;
        }

        // cross-scheme: Stage 1 - Try direct cloneKey() first (fast path)
        // Performance optimization: Only attempt cloneKey if not already known to fail
        // TEST ONLY: Skip Stage 1 if -force_rsa_keypair_transfer flag is set
        if (!mForceRSAKeypairTransfer && mCloneKeyCapability != CloneKeyCapability.UNSUPPORTED) {
            try {
                if (mVerboseFlag) {
                    if (mCloneKeyCapability == CloneKeyCapability.UNTESTED) {
                        log("Stage 1: Testing cloneKey capability (first record)..." + NEWLINE, false);
                    } else {
                        log("Stage 1: Using cloneKey (known to work)..." + NEWLINE, false);
                    }
                }
                SymmetricKey importedKey = processingToken.cloneKey(sessionKey);

                // Success! Cache this result for all future records
                if (mCloneKeyCapability == CloneKeyCapability.UNTESTED) {
                    mCloneKeyCapability = CloneKeyCapability.SUPPORTED;
                    if (mVerboseFlag) {
                        log("cloneKey works - will use direct clone for all subsequent records" + NEWLINE, false);
                    }
                }

                if (mVerboseFlag) {
                    log("Session key successfully cloned to processing token (direct method)" + NEWLINE, false);
                }
                return importedKey;

            } catch (SymmetricKey.NotExtractableException e) {
                // Cache the failure - don't try cloneKey again for remaining records
                mCloneKeyCapability = CloneKeyCapability.UNSUPPORTED;

                if (mVerboseFlag) {
                    log("Direct clone failed - session key not extractable from source HSM" + NEWLINE, false);
                    log("HSM security policy prevents PK11_ExtractKeyValue" + NEWLINE, false);
                    log("Will use RSA keypair method for all subsequent records" + NEWLINE, false);
                    log("Stage 2: Falling back to JSS_KeyExchange-style temporary RSA keypair approach..." + NEWLINE, false);
                } else {
                    // Important: Log this once even without verbose, as it affects performance
                    log("Note: HSM does not support extractable session keys - using RSA keypair transfer method for all records" + NEWLINE, false);
                }

                // Fall through to Stage 2
            } catch (Exception e) {
                log("ERROR: Unexpected error during direct clone: " + e.getMessage() + NEWLINE, true);
                throw new Exception("Failed to clone session key", e);
            }
        } else {
            // mCloneKeyCapability == UNSUPPORTED OR mForceRSAKeypairTransfer == true: Skip Stage 1 entirely
            if (mVerboseFlag) {
                if (mForceRSAKeypairTransfer) {
                    log("TEST MODE: -force_rsa_keypair_transfer enabled - skipping cloneKey, using RSA keypair method" + NEWLINE, false);
                } else {
                    log("Skipping cloneKey attempt (known to fail) - using RSA keypair method" + NEWLINE, false);
                }
            }
        }

        // cross-scheme: Stage 2 - JSS_KeyExchange-style approach using temporary RSA keypair
        try {
            // Initialize temp RSA keypair if not already done (only happens once)
            initTempRSAKeyPair(processingToken);

            // Get session key parameters
            int sessionKeyLength = sessionKey.getLength();  // Key length in bytes
            if (mVerboseFlag) {
                log("Session key length: " + sessionKeyLength + " bytes" + NEWLINE, false);
            }

            // Step 1: Wrap session key with temporary RSA public key on source token
            CryptoToken sourceToken = sessionKey.getOwningToken();
            if (mVerboseFlag) {
                log("Wrapping session key with temporary RSA public key on source token..." + NEWLINE, false);
            }

            // Use source RSA wrap algorithm (respects -source_rsa_wrap_algorithm flag)
            KeyWrapper sourceWrapper = sourceToken.getKeyWrapper(mSourceRSAWrapAlg);
            AlgorithmParameterSpec rsaParams = (mSourceRSAWrapAlg == KeyWrapAlgorithm.RSA_OAEP) ? OAEP_PARAMS : null;
            sourceWrapper.initWrap(mTempRSAKeyPair.getPublic(), rsaParams);
            byte[] wrappedSessionKey = sourceWrapper.wrap(sessionKey);

            if (mVerboseFlag) {
                log("Session key wrapped with temporary RSA public key (" + wrappedSessionKey.length + " bytes)" + NEWLINE, false);
            }

            // Step 2: Unwrap session key with temporary RSA private key on processing token
            if (mVerboseFlag) {
                log("Unwrapping session key with temporary RSA private key on processing token..." + NEWLINE, false);
            }

            // Note: sessionKeyLength is in bytes, CryptoUtil.unwrap expects bits
            // Use same RSA algorithm as the wrap operation
            SymmetricKey importedKey = CryptoUtil.unwrap(
                processingToken,
                SymmetricKey.AES,
                sessionKeyLength * 8,  // Convert bytes to bits
                SymmetricKey.Usage.UNWRAP,
                (PrivateKey)mTempRSAKeyPair.getPrivate(),
                wrappedSessionKey,
                mSourceRSAWrapAlg  // Use source RSA algorithm (not hardcoded OAEP)
            );

            if (mVerboseFlag) {
                log("Session key successfully transferred to processing token using temporary RSA keypair" + NEWLINE, false);
            }

            return importedKey;

        } catch (Exception e) {
            log("ERROR: Failed to import session key using temporary RSA keypair: " + e.getMessage() + NEWLINE, true);
            throw new Exception("Failed to import session key to processing token (both direct and RSA keypair methods failed)", e);
        }
    }


    /**
     * Baseline rewrap: Simple session key rewrap without algorithm changes.
     *
     * This is the original baseline rewrap method from legacy KRATool.
     * (with just the OAEP_PARAMS change)
     *
     * This method basically rewraps the "wrappedKeyData" by implementiing
     * "mStorageUnit.decryptInternalPrivate( byte wrappedKeyData[] )" and
     * "mStorageUnit.encryptInternalPrivate( byte priKey[] )", where
     * "wrappedKeyData" uses the following structure:
     *
     * SEQUENCE {
     * encryptedSession OCTET STRING,
     * encryptedPrivate OCTET STRING
     * }
     *
     * This method is based upon code from
     * 'com.netscape.kra.EncryptionUnit'.
     * <P>
     *
     * @return a byte[] containing the rewrappedKeyData
     */
    private static byte[] rewrap_wrapped_key_data(byte[] wrappedKeyData)
            throws Exception {
        DerValue val = null;
        DerInputStream in = null;
        DerValue dSession = null;
        byte source_session[] = null;
        DerValue dPri = null;
        byte pri[] = null;
        KeyWrapper source_rsaWrap = null;
        SymmetricKey sk = null;
        KeyWrapper target_rsaWrap = null;
        byte target_session[] = null;
        DerOutputStream tmp = null;
        byte[] rewrappedKeyData = null;

        // public byte[]
        // mStorageUnit.decryptInternalPrivate( byte wrappedKeyData[] );
        // throws EBaseException
        try {
            val = new DerValue(wrappedKeyData);
            in = val.data;
            dSession = in.getDerValue();
            source_session = dSession.getOctetString();
            dPri = in.getDerValue();
            pri = dPri.getOctetString();

            KeyWrapAlgorithm wrapAlg = KeyWrapAlgorithm.RSA;

            if(mUseOAEPKeyWrapAlg == true) {
                wrapAlg = KeyWrapAlgorithm.RSA_OAEP;
            }

            source_rsaWrap = mSourceToken.getKeyWrapper(
                                 wrapAlg);
            AlgorithmParameterSpec rsaParams = (mUseOAEPKeyWrapAlg == true) ? OAEP_PARAMS : null;
            source_rsaWrap.initUnwrap(mUnwrapPrivateKey, rsaParams);
            sk = source_rsaWrap.unwrapSymmetric(source_session,
                                                 keyUnwrapAlgorithm,
                                                 SymmetricKey.Usage.DECRYPT,
                                                 0);
            if (mDebug) {
                log("DEBUG: sk = '"
                        + Utils.base64encode(sk.getEncoded(), true)
                        + "' length = '"
                        + sk.getEncoded().length
                        + "'"
                        + NEWLINE, false);
                log("DEBUG: pri = '"
                        + Utils.base64encode(pri, true)
                        + "' length = '"
                        + pri.length
                        + "'"
                        + NEWLINE, false);
            }
        } catch (IOException exUnwrapIO) {
            log("ERROR:  Unwrapping key data - "
                    + "IOException: '"
                    + exUnwrapIO.toString()
                    + "'"
                    + NEWLINE, true);
            System.exit(0);
        } catch (NoSuchAlgorithmException exUnwrapAlgorithm) {
            log("ERROR:  Unwrapping key data - "
                    + "NoSuchAlgorithmException: '"
                    + exUnwrapAlgorithm.toString()
                    + "'"
                    + NEWLINE, true);
            System.exit(0);
        } catch (TokenException exUnwrapToken) {
            log("ERROR:  Unwrapping key data - "
                    + "TokenException: '"
                    + exUnwrapToken.toString()
                    + "'"
                    + NEWLINE, true);
            System.exit(0);
        } catch (InvalidKeyException exUnwrapInvalidKey) {
            log("ERROR:  Unwrapping key data - "
                    + "InvalidKeyException: '"
                    + exUnwrapInvalidKey.toString()
                    + "'"
                    + NEWLINE, true);
            System.exit(0);
        } catch (InvalidAlgorithmParameterException exUnwrapInvalidAlgorithm) {
            log("ERROR:  Unwrapping key data - "
                    + "InvalidAlgorithmParameterException: '"
                    + exUnwrapInvalidAlgorithm.toString()
                    + "'"
                    + NEWLINE, true);
            System.exit(0);
        } catch (IllegalStateException exUnwrapState) {
            log("ERROR:  Unwrapping key data - "
                    + "InvalidStateException: '"
                    + exUnwrapState.toString()
                    + "'"
                    + NEWLINE, true);
            System.exit(0);
        }

        // public byte[]
        // mStorageUnit.encryptInternalPrivate( byte priKey[] )
        // throws EBaseException
        KeyWrapAlgorithm wrapAlg = KeyWrapAlgorithm.RSA;
        if(mUseOAEPKeyWrapAlg == true) {
            wrapAlg = KeyWrapAlgorithm.RSA_OAEP;
        }
        try (DerOutputStream out = new DerOutputStream()) {
            // Use "mSourceToken" to get "KeyWrapAlgorithm.RSA"
            target_rsaWrap = mSourceToken.getKeyWrapper(
                                 wrapAlg);
            AlgorithmParameterSpec rsaParams = (mUseOAEPKeyWrapAlg == true) ? OAEP_PARAMS : null;
            target_rsaWrap.initWrap(mWrapPublicKey, rsaParams);
            target_session = target_rsaWrap.wrap(sk);

            tmp = new DerOutputStream();

            tmp.putOctetString(target_session);
            tmp.putOctetString(pri);
            out.write(DerValue.tag_Sequence, tmp);

            rewrappedKeyData = out.toByteArray();
        } catch (NoSuchAlgorithmException exWrapAlgorithm) {
            log("ERROR:  Wrapping key data - "
                    + "NoSuchAlgorithmException: '"
                    + exWrapAlgorithm.toString()
                    + "'"
                    + NEWLINE, true);
            System.exit(0);
        } catch (TokenException exWrapToken) {
            log("ERROR:  Wrapping key data - "
                    + "TokenException: '"
                    + exWrapToken.toString()
                    + "'"
                    + NEWLINE, true);
            System.exit(0);
        } catch (InvalidKeyException exWrapInvalidKey) {
            log("ERROR:  Wrapping key data - "
                    + "InvalidKeyException: '"
                    + exWrapInvalidKey.toString()
                    + "'"
                    + NEWLINE, true);
            System.exit(0);
        } catch (InvalidAlgorithmParameterException exWrapInvalidAlgorithm) {
            log("ERROR:  Wrapping key data - "
                    + "InvalidAlgorithmParameterException: '"
                    + exWrapInvalidAlgorithm.toString()
                    + "'"
                    + NEWLINE, true);
            System.exit(0);
        } catch (IllegalStateException exWrapState) {
            log("ERROR:  Wrapping key data - "
                    + "InvalidStateException: '"
                    + exWrapState.toString()
                    + "'"
                    + NEWLINE, true);
            System.exit(0);
        } catch (IOException exWrapIO) {
            log("ERROR:  Wrapping key data - "
                    + "IOException: '"
                    + exWrapIO.toString()
                    + "'"
                    + NEWLINE, true);
            System.exit(0);
        }

        return rewrappedKeyData;
    }

    /**
     * cross-scheme support: Rewraps private key data for cross-scheme migration.
     *
     * NOTE: This migration tool is designed to run in a secure, isolated environment.
     *
     * Migration flow (with payloadEncrypted:false - using key wrapping):
     * 1. Unwrap session key from source HSM with source RSA algorithm
     * 2. Import session key into processing token (NSS DB when using -use_nss_for_payload_processing)
     * 3. Unwrap private key using session key and publicKeyData
     * 4. [Optional] Generate new session key based on algorithm compatibility
     * 5. Wrap private key with session key using target payload wrap algorithm
     * 6. Wrap session key with target storage cert public key using target RSA algorithm
     *
     * Input DER structure (from LDIF privateKeyData):
     * SEQUENCE {
     *   encryptedSession OCTET STRING  (session key wrapped with source storage private key)
     *   encryptedPrivate OCTET STRING  (private key wrapped with session key)
     * }
     *
     * Based on: com.netscape.kra.StorageKeyUnit.unwrap() and wrap()
     *
     * @param wrappedKeyData The wrapped private key data from LDIF
     * @param publicKeyData The public key data from LDIF (needed for unwrapping)
     * @param ivData The IV from metaInfo (for AES/CBC payload encryption, null for KeyWrap algorithms)
     * @return rewrapped private key data for target LDIF
     */
    private static byte[] rewrap_wrapped_key_data(byte[] wrappedKeyData, byte[] publicKeyData, byte[] ivData)
            throws Exception {

        // cross-scheme: Step 1 - Parse Input DER Structure
        byte[] wrappedSessionKey;
        byte[] wrappedPrivateKey;

        try {
            DerValue val = new DerValue(wrappedKeyData);
            DerInputStream in = val.data;

            // Extract wrapped session key
            DerValue dSession = in.getDerValue();
            wrappedSessionKey = dSession.getOctetString();

            // Extract wrapped private key
            DerValue dPri = in.getDerValue();
            wrappedPrivateKey = dPri.getOctetString();

            log("Parsed DER structure: session key " + wrappedSessionKey.length +
                       " bytes, private key " + wrappedPrivateKey.length + " bytes" + NEWLINE, false);
        } catch (IOException e) {
            log("ERROR: Failed to parse DER structure: " + e.getMessage() + NEWLINE, true);
            throw new Exception("Failed to parse input DER structure", e);
        }

        // cross-scheme: Step 2 - Unwrap Session Key from Source HSM
        // Note: We request the session key to be TEMPORARY and EXTRACTABLE so it can be
        // cloned to the processing token (software token when using -use_nss_for_payload_processing).
        // If the HSM doesn't allow extractable session keys, the importSessionKeyToToken() method
        // in Step 3 will automatically fall back to using a temporary RSA keypair approach.
        SymmetricKey sessionKey;

        try {
            CryptoToken sourceToken = mSourceToken;
            if (mVerboseFlag) {
                log("Unwrapping session key from source HSM using " + mSourceRSAWrapAlgName +
                    " (enum: " + mSourceRSAWrapAlg + ")" + NEWLINE, false);

                // Debug: Log private key information
                log("DEBUG: Private key owner token: " + mUnwrapPrivateKey.getOwningToken().getName() + NEWLINE, false);
                log("DEBUG: Private key algorithm: " + mUnwrapPrivateKey.getAlgorithm() + NEWLINE, false);
                byte[] keyID = mUnwrapPrivateKey.getUniqueID();
                StringBuilder hexString = new StringBuilder();
                for (byte b : keyID) {
                    hexString.append(String.format("%02X", b));
                }
                log("DEBUG: Private key ID: " + hexString.toString() + NEWLINE, false);
            }

            // Note: strength parameter is in BITS (128), CryptoUtil divides by 8 internally
            sessionKey = CryptoUtil.unwrap(
                sourceToken,              // CryptoToken
                SymmetricKey.AES,         // key type
                128,                      // key strength in BITS
                SymmetricKey.Usage.UNWRAP,  // usage
                mUnwrapPrivateKey,        // unwrapping key (PrivateKey)
                wrappedSessionKey,        // wrapped data
                mSourceRSAWrapAlg         // KeyWrapAlgorithm (RSA_OAEP or RSA)
            );

            log("Session key unwrapped from source HSM" + NEWLINE, false);
        } catch (Exception e) {
            log("ERROR: Failed to unwrap session key: " + e.getMessage() + NEWLINE, true);
            throw new Exception("Failed to unwrap session key from source HSM", e);
        }

        // cross-scheme: Step 3 - Import Session Key to Target Token
        CryptoToken processingToken;
        SymmetricKey targetSessionKey;

        try {
            if (mUseNssForPayloadProcessing) {
                // Use NSS DB (software token) for payload unwrap/rewrap operations
                processingToken = CryptoManager.getInstance().getInternalKeyStorageToken();

                // Login to Internal Key Storage Token if not already logged in
                if (processingToken.isLoggedIn() == false && processingToken.passwordIsInitialized()) {
                    BufferedReader in = null;
                    String pwd = null;
                    try {
                        in = new BufferedReader(new FileReader(mSourcePKISecurityDatabasePwdfile));
                        pwd = in.readLine();
                        if (pwd == null) {
                            pwd = "";
                        }
                    } catch (IOException exReadPwd) {
                        log("ERROR: Failed to read NSS DB password from file '" + mSourcePKISecurityDatabasePwdfile + "': " + exReadPwd.getMessage() + NEWLINE, true);
                        throw exReadPwd;
                    } finally {
                        if (in != null) {
                            try {
                                in.close();
                            } catch (IOException exClosePwd) {
                            }
                        }
                    }

                    Password mPwd = new Password(pwd.toCharArray());
                    try {
                        processingToken.login(mPwd);
                        if (mVerboseFlag) {
                            log("Logged in to Internal Key Storage Token" + NEWLINE, false);
                        }
                    } finally {
                        mPwd.clear();
                    }
                }

                if (mVerboseFlag) {
                    log("Using NSS DB (software token) for payload processing" + NEWLINE, false);
                }
            } else {
                // Use same HSM for payload unwrap/rewrap operations
                processingToken = mSourceToken;
                if (mVerboseFlag) {
                    log("Using same HSM for payload processing" + NEWLINE, false);
                }
            }

            // Import session key to processing token
            targetSessionKey = importSessionKeyToToken(sessionKey, processingToken);
            if (mVerboseFlag) {
                log("Session key imported to processing token" + NEWLINE, false);
            }
        } catch (Exception e) {
            log("ERROR: Failed to import session key to processing token: " + e.getMessage() + NEWLINE, true);
            throw new Exception("Failed to import session key to processing token", e);
        }

        // cross-scheme: Step 4 - Parse PublicKey from publicKeyData
        PublicKey publicKey;

        try {
            publicKey = parsePublicKeyFromLDIF(publicKeyData);
            if (mVerboseFlag) {
                log("Parsed public key from LDIF" + NEWLINE, false);
                log("DEBUG: Public key algorithm: " + publicKey.getAlgorithm() + NEWLINE, false);
                log("DEBUG: Public key format: " + publicKey.getFormat() + NEWLINE, false);
            }
        } catch (Exception e) {
            log("ERROR: Failed to parse public key: " + e.getMessage() + NEWLINE, true);
            throw new Exception("Failed to parse publicKeyData", e);
        }

        // cross-scheme: Step 5 - Unwrap Private Key in Target Token
        PrivateKey privateKey;

        try {
            // Get source wrapping parameters (use cached values for performance)
            IVParameterSpec sourcePayloadWrapIV = null;
            if (mSourcePayloadNeedsIV) {
                if (ivData != null) {
                    sourcePayloadWrapIV = new IVParameterSpec(ivData);
                } else {
                    throw new Exception("IV required for " + mSourcePayloadWrapAlgName + " but not found in metaInfo");
                }
            }

            if (mVerboseFlag) {
                log("Unwrapping private key using " + mSourcePayloadWrapAlg +
                           " (IV: " + (sourcePayloadWrapIV != null ? "present" : "null") + ")" + NEWLINE, false);
            }

            // Unwrap private key - stays in processing token!
            privateKey = CryptoUtil.unwrap(
                processingToken,
                publicKey,
                true,  // temporary
                targetSessionKey,
                wrappedPrivateKey,
                mSourcePayloadWrapAlg,
                sourcePayloadWrapIV
            );

            if (mVerboseFlag) {
                log("Private key unwrapped in processing token" + NEWLINE, false);
            }
        } catch (Exception e) {
            log("ERROR: Failed to unwrap private key: " + e.getMessage() + NEWLINE, true);
            if (!mUseNssForPayloadProcessing) {
                log("" + NEWLINE, true);
                log("HSM may not support the source payload wrap algorithm: " + mSourcePayloadWrapAlgName + NEWLINE, true);
                log("Suggestion: Try running with -use_nss_for_payload_processing flag" + NEWLINE, true);
                log("           to perform payload operations in NSS DB (software token)" + NEWLINE, true);
            }
            throw new Exception("Failed to unwrap private key in processing token", e);
        }

        // cross-scheme: Step 6 - Generate New Session Key (if needed)
        SymmetricKey newSessionKey;

        try {
            if (needNewSessionKey()) {
                // Generate new session key in processing token
                KeyGenerator kg = processingToken.getKeyGenerator(KeyGenAlgorithm.AES);

                int targetKeySize = getKeySizeFromAlgorithm(mTargetPayloadWrapAlgName);
                if (targetKeySize == 0) {
                    targetKeySize = 128;  // Default
                }

                kg.initialize(targetKeySize);
                kg.setKeyUsages(new SymmetricKey.Usage[] { SymmetricKey.Usage.WRAP, SymmetricKey.Usage.UNWRAP });
                kg.temporaryKeys(true);

                newSessionKey = (SymmetricKey) kg.generate();

                if (mVerboseFlag) {
                    log("Generated new " + targetKeySize + "-bit AES session key" + NEWLINE, false);
                }
            } else {
                // Reuse existing session key
                newSessionKey = targetSessionKey;
                if (mVerboseFlag) {
                    log("Reusing existing session key" + NEWLINE, false);
                }
            }
        } catch (Exception e) {
            log("ERROR: Failed to generate/prepare session key: " + e.getMessage() + NEWLINE, true);
            if (!mUseNssForPayloadProcessing) {
                log("" + NEWLINE, true);
                log("HSM may not support AES session key generation" + NEWLINE, true);
                log("Suggestion: Try running with -use_nss_for_payload_processing flag" + NEWLINE, true);
                log("           to perform payload operations in NSS DB (software token)" + NEWLINE, true);
            }
            throw new Exception("Failed to prepare session key for target", e);
        }

        // cross-scheme: Step 7 - Wrap Private Key with Session Key
        byte[] newWrappedPrivateKey;
        IVParameterSpec targetPayloadWrapIV = null;

        try {
            // Get target wrapping parameters (use cached values for performance)
            if (mTargetPayloadNeedsIV) {
                // Generate new random IV for CBC modes
                targetPayloadWrapIV = generateIV(mTargetPayloadWrapAlg);
                if (mVerboseFlag) {
                    log("Generated new IV for " + mTargetPayloadWrapAlg + NEWLINE, false);
                }
            } else {
                if (mVerboseFlag) {
                    log("No IV needed for " + mTargetPayloadWrapAlg + NEWLINE, false);
                }
            }

            if (mVerboseFlag) {
                log("Wrapping private key using " + mTargetPayloadWrapAlg + NEWLINE, false);
            }

            // Wrap private key
            newWrappedPrivateKey = CryptoUtil.wrapUsingSymmetricKey(
                processingToken,
                newSessionKey,
                privateKey,
                targetPayloadWrapIV,
                mTargetPayloadWrapAlg
            );

            if (mVerboseFlag) {
                log("Private key wrapped with session key (" + newWrappedPrivateKey.length + " bytes)" + NEWLINE, false);
            }
        } catch (Exception e) {
            log("ERROR: Failed to wrap private key: " + e.getMessage() + NEWLINE, true);
            if (!mUseNssForPayloadProcessing) {
                log("" + NEWLINE, true);
                log("HSM may not support the target payload wrap algorithm: " + mTargetPayloadWrapAlgName + NEWLINE, true);
                log("Suggestion: Try running with -use_nss_for_payload_processing flag" + NEWLINE, true);
                log("           to perform payload operations in NSS DB (software token)" + NEWLINE, true);
            }
            throw new Exception("Failed to wrap private key with session key", e);
        }

        // cross-scheme: Step 8 - Wrap Session Key with Target Storage Cert
        byte[] newWrappedSessionKey;

        try {
            if (mVerboseFlag) {
                log("Wrapping session key using " + mTargetRSAWrapAlg + NEWLINE, false);
            }

            // Wrap session key with target storage cert public key
            // Use mWrapPublicKey (PK11PubKey format) instead of getPublicKey() (X509Key)
            newWrappedSessionKey = CryptoUtil.wrapUsingPublicKey(
                processingToken,
                mWrapPublicKey,
                newSessionKey,
                mTargetRSAWrapAlg
            );

            if (mVerboseFlag) {
                log("Session key wrapped with target storage cert (" + newWrappedSessionKey.length + " bytes)" + NEWLINE, false);
            }
        } catch (Exception e) {
            log("ERROR: Failed to wrap session key: " + e.getMessage() + NEWLINE, true);
            throw new Exception("Failed to wrap session key with target storage cert", e);
        }

        // cross-scheme: Step 9 - Build Output DER Structure
        byte[] rewrappedKeyData;

        try {
            DerOutputStream out = new DerOutputStream();

            // Add wrapped session key
            out.putOctetString(newWrappedSessionKey);

            // Add wrapped private key
            out.putOctetString(newWrappedPrivateKey);

            // Wrap in SEQUENCE
            DerOutputStream seq = new DerOutputStream();
            seq.write(DerValue.tag_Sequence, out);

            rewrappedKeyData = seq.toByteArray();

            if (mVerboseFlag) {
                log("Built output DER structure: " + rewrappedKeyData.length + " bytes total" + NEWLINE, false);
            }
        } catch (IOException e) {
            log("ERROR: Failed to build output DER structure: " + e.getMessage() + NEWLINE, true);
            throw new Exception("Failed to build output DER structure", e);
        }

        return rewrappedKeyData;
    }

    /**
     * Helper method used to remove all EOLs ('\n' and '\r')
     * from the passed in string.
     * <P>
     *
     * @param data consisting of a string containing EOLs
     * @return a string consisting of a string with no EOLs
     */
    private static String stripEOL(String data) {
        StringBuilder buffer = new StringBuilder();
        String revised_data = null;

        for (int i = 0; i < data.length(); i++) {
            if ((data.charAt(i) != '\n') &&
                    (data.charAt(i) != '\r')) {
                buffer.append(data.charAt(i));
            }
        }

        revised_data = buffer.toString();

        return revised_data;
    }

    /**
     * Helper method used to format a string containing unformatted data
     * into a string containing formatted data suitable as an entry for
     * an LDIF file.
     * <P>
     *
     * @param length the length of the first line of data
     * @param data a string containing unformatted data
     * @return formatted data consisting of data formatted for an LDIF record
     *         suitable for an LDIF file
     */
    private static String format_ldif_data(int length, String data) {
        StringBuilder revised_data = new StringBuilder();

        if (data.length() > length) {
            // process first line
            for (int i = 0; i < length; i++) {
                revised_data.append(data.charAt(i));
            }

            // terminate first line
            revised_data.append("\n");

            // process remaining lines
            int j = 0;
            for (int i = length; i < data.length(); i++) {
                if (j == 0) {
                    revised_data.append(' ');
                }

                revised_data.append(data.charAt(i));

                j++;

                if (j == 76) {
                    revised_data.append("\n");
                    j = 0;
                }
            }
        }

        return revised_data.toString().replaceAll("\\s+$", "");
    }

    /*********************/
    /* ID Offset Methods */
    /*********************/

    /**
     * Helper method which converts an "indexed" BigInteger into
     * its String representation.
     *
     * <PRE>
     *
     *     NOTE:  Indexed data means that the numeric data
     *            is stored with a prepended length
     *            (e. g. - record '73' is stored as '0273').
     *
     *            Indexed data is currently limited to '99' digits
     *            (an index of '00' is invalid).  See
     *            'com.netscape.cmscore.dbs.BigIntegerMapper.java'
     *            for details.
     *
     * </PRE>
     *
     * This method is based upon code from
     * 'com.netscape.cmscore.dbs.BigIntegerMapper'.
     * <P>
     *
     * @param i an "indexed " BigInteger
     * @return the string representation of the "indexed" BigInteger
     */
    private static String BigIntegerToDB(BigInteger i) {
        int len = i.toString().length();
        String ret = null;

        if (len < 10) {
            ret = "0" + Integer.toString(len) + i.toString();
        } else {
            ret = Integer.toString(len) + i.toString();
        }
        return ret;
    }

    /**
     * Helper method which converts the string representation of an
     * "indexed" integer into a BigInteger.
     *
     * <PRE>
     *     NOTE:  Indexed data means that the numeric data
     *            is stored with a prepended length
     *            (e. g. - record '73' is stored as '0273').
     *
     *            Indexed data is currently limited to '99' digits
     *            (an index of '00' is invalid).  See
     *            'com.netscape.cmscore.dbs.BigIntegerMapper.java'
     *            for details.
     * </PRE>
     *
     * This method is based upon code from
     * 'com.netscape.cmscore.dbs.BigIntegerMapper'.
     * <P>
     *
     * @param i the string representation of the "indexed" integer
     * @return an "indexed " BigInteger
     */
    private static BigInteger BigIntegerFromDB(String i) {
        String s = i.substring(2);

        // possibly check length
        return new BigInteger(s);
    }

    /**
     * This method accepts an "attribute", its "delimiter", a string
     * representation of numeric data, and a flag indicating whether
     * or not the string representation is "indexed".
     *
     * An "attribute" consists of one of the following values:
     *
     * <PRE>
     *     KRA_LDIF_CN = "cn:";
     *     KRA_LDIF_DN_EMBEDDED_CN_DATA = "dn: cn";
     *     KRA_LDIF_EXTDATA_KEY_RECORD = "extdata-keyrecord:";
     *     KRA_LDIF_EXTDATA_REQUEST_ID = "extdata-requestid:";
     *     KRA_LDIF_EXTDATA_SERIAL_NUMBER = "extdata-serialnumber:";
     *     KRA_LDIF_REQUEST_ID = "requestId:";
     *     KRA_LDIF_SERIAL_NO = "serialno:";
     *
     *
     *     NOTE:  Indexed data means that the numeric data
     *            is stored with a prepended length
     *            (e. g. - record '73' is stored as '0273').
     *
     *            Indexed data is currently limited to '99' digits
     *            (an index of '00' is invalid).  See
     *            'com.netscape.cmscore.dbs.BigIntegerMapper.java'
     *            for details.
     * </PRE>
     *
     * <P>
     *
     * @param attribute the string representation of the "name"
     * @param delimiter the separator between the attribute and its contents
     * @param source_line the string containing the "name" and "value"
     * @param indexed boolean flag indicating if the "value" is "indexed"
     * @return a revised line containing the "name" and "value" with the
     *         specified ID offset applied as a "mask" to the "value"
     */
    private static String compose_numeric_line(String attribute,
                                                String delimiter,
                                                String source_line,
                                                boolean indexed) {
        String target_line = null;
        String data = null;
        String revised_data = null;
        BigInteger value = null;

        // Since both "-append_id_offset" and "-remove_id_offset" are OPTIONAL
        // parameters, first check to see if either has been selected
        if (!mAppendIdOffsetFlag &&
                !mRemoveIdOffsetFlag) {
            return source_line;
        }

        try {
            // extract the data
            data = source_line.substring(attribute.length() + 1).trim();

            // skip values which are non-numeric
            if (!data.matches("[0-9]++")) {
                // set the target_line to the unchanged source_line
                target_line = source_line;

                // log this information
                log("Skipped changing non-numeric line '"
                        + source_line
                        + "'."
                        + NEWLINE, false);
            } else {
                // if indexed, first strip the index from the data
                if (indexed) {
                    // NOTE:  Indexed data means that the numeric data
                    //        is stored with a prepended length
                    //        (e. g. - record '73' is stored as '0273').
                    //
                    //        Indexed data is currently limited to '99' digits
                    //        (an index of '00' is invalid).  See
                    //        'com.netscape.cmscore.dbs.BigIntegerMapper.java'
                    //        for details.
                    value = BigIntegerFromDB(data);
                } else {
                    value = new BigInteger(data);
                }

                // compare the specified target ID offset
                // with the actual value of the attribute
                if (mAppendIdOffsetFlag) {
                    if (mAppendIdOffset.compareTo(value) > 0) {
                        // add the target ID offset to this value
                        if (indexed) {
                            revised_data = BigIntegerToDB(
                                               value.add(mAppendIdOffset)
                                               ).toString();
                        } else {
                            revised_data = value.add(
                                               mAppendIdOffset).toString();
                        }
                    } else {
                        log("ERROR:  attribute='"
                                + attribute
                                + "' is greater than the specified "
                                + "append_id_offset='"
                                + mAppendIdOffset.toString()
                                + "'!"
                                + NEWLINE, true);
                        System.exit(0);
                    }
                } else if (mRemoveIdOffsetFlag) {
                    if (mRemoveIdOffset.compareTo(value) <= 0) {
                        // subtract the target ID offset to this value
                        if (indexed) {
                            revised_data = BigIntegerToDB(
                                               value.subtract(mRemoveIdOffset)
                                               ).toString();
                        } else {
                            revised_data = value.subtract(mRemoveIdOffset
                                               ).toString();
                        }
                    } else {
                        log("ERROR:  attribute='"
                                + attribute
                                + "' is less than the specified "
                                + "remove_id_offset='"
                                + mRemoveIdOffset.toString()
                                + "'!"
                                + NEWLINE, true);
                        System.exit(0);
                    }
                }

                // set the target_line to the revised data
                target_line = attribute + delimiter + revised_data;

                // log this information
                log("Changed numeric data '"
                        + data
                        + "' to '"
                        + revised_data
                        + "'."
                        + NEWLINE, false);
            }
        } catch (IndexOutOfBoundsException exBounds) {
            log("ERROR:  source_line='"
                    + source_line
                    + "' IndexOutOfBoundsException: '"
                    + exBounds.toString()
                    + "'"
                    + NEWLINE, true);
            System.exit(0);
        } catch (PatternSyntaxException exPattern) {
            log("ERROR:  data='"
                    + data
                    + "' PatternSyntaxException: '"
                    + exPattern.toString()
                    + "'"
                    + NEWLINE, true);
            System.exit(0);
        }

        return target_line;
    }

    /***********************/
    /* LDIF Parser Methods */
    /***********************/

    /**
     * Helper method which composes the output line for KRA_LDIF_CN.
     * <P>
     *
     * @param record_type the string representation of the input record type
     * @param line the string representation of the input line
     * @return the composed output line
     */
    private static String output_cn(String record_type,
                                     String line) {
        String output = null;

        if (record_type.equals(KRA_LDIF_ENROLLMENT)) {
            if (kratoolCfg.get(KRATOOL_CFG_ENROLLMENT_CN)) {
                output = compose_numeric_line(KRA_LDIF_CN,
                                               SPACE,
                                               line,
                                               false);
            } else {
                output = line;
            }
        } else if (record_type.equals(KRA_LDIF_CA_KEY_RECORD)) {
            if (kratoolCfg.get(KRATOOL_CFG_CA_KEY_RECORD_CN)) {
                output = compose_numeric_line(KRA_LDIF_CN,
                                               SPACE,
                                               line,
                                               false);
            } else {
                output = line;
            }
        } else if (record_type.equals(KRA_LDIF_RECOVERY)) {
            if (kratoolCfg.get(KRATOOL_CFG_RECOVERY_CN)) {
                output = compose_numeric_line(KRA_LDIF_CN,
                                               SPACE,
                                               line,
                                               false);
            } else {
                output = line;
            }
        } else if (record_type.equals(KRA_LDIF_TPS_KEY_RECORD)) {
            if (kratoolCfg.get(KRATOOL_CFG_TPS_KEY_RECORD_CN)) {
                output = compose_numeric_line(KRA_LDIF_CN,
                                               SPACE,
                                               line,
                                               false);
            } else {
                output = line;
            }
        } else if (record_type.equals(KRA_LDIF_KEYGEN)) {
            if (kratoolCfg.get(KRATOOL_CFG_KEYGEN_CN)) {
                output = compose_numeric_line(KRA_LDIF_CN,
                                               SPACE,
                                               line,
                                               false);
            } else {
                output = line;
            }
        } else if (record_type.equals( KRA_LDIF_KEYRECOVERY ) ) {
            if( kratoolCfg.get(KRATOOL_CFG_KEYRECOVERY_CN ) ) {
                output = compose_numeric_line(KRA_LDIF_CN,
                    SPACE,
                    line,
                    false );
            } else {
                output = line;
            }
        } else if (record_type.equals(KRA_LDIF_RECORD)) {
            // Non-Request / Non-Key Record:
            //     Pass through the original
            //     'cn' line UNCHANGED
            //     so that it is ALWAYS written
            output = line;
        } else {
            log("ERROR:  Mismatched record field='"
                    + KRA_LDIF_CN
                    + "' for record type='"
                    + record_type
                    + "'!"
                    + NEWLINE, true);
        }

        return output;
    }

    /**
     * Helper method which composes the output line for KRA_LDIF_DATE_OF_MODIFY.
     * <P>
     *
     * @param record_type the string representation of the input record type
     * @param line the string representation of the input line
     * @return the composed output line
     */
    private static String output_date_of_modify(String record_type,
                                                 String line) {
        String output = null;

        if (record_type.equals(KRA_LDIF_ENROLLMENT)) {
            if (kratoolCfg.get(KRATOOL_CFG_ENROLLMENT_DATE_OF_MODIFY)) {
                output = KRA_LDIF_DATE_OF_MODIFY
                        + SPACE
                        + mDateOfModify;

                log("Changed '"
                        + line
                        + "' to '"
                        + output
                        + "'."
                        + NEWLINE, false);
            } else {
                output = line;
            }
        } else if (record_type.equals(KRA_LDIF_CA_KEY_RECORD)) {
            if (kratoolCfg.get(KRATOOL_CFG_CA_KEY_RECORD_DATE_OF_MODIFY)) {
                output = KRA_LDIF_DATE_OF_MODIFY
                        + SPACE
                        + mDateOfModify;

                log("Changed '"
                        + line
                        + "' to '"
                        + output
                        + "'."
                        + NEWLINE, false);
            } else {
                output = line;
            }
        } else if (record_type.equals(KRA_LDIF_RECOVERY)) {
            if (kratoolCfg.get(KRATOOL_CFG_RECOVERY_DATE_OF_MODIFY)) {
                output = KRA_LDIF_DATE_OF_MODIFY
                        + SPACE
                        + mDateOfModify;

                log("Changed '"
                        + line
                        + "' to '"
                        + output
                        + "'."
                        + NEWLINE, false);
            } else {
                output = line;
            }
        } else if (record_type.equals(KRA_LDIF_TPS_KEY_RECORD)) {
            if (kratoolCfg.get(KRATOOL_CFG_TPS_KEY_RECORD_DATE_OF_MODIFY)) {
                output = KRA_LDIF_DATE_OF_MODIFY
                        + SPACE
                        + mDateOfModify;

                log("Changed '"
                        + line
                        + "' to '"
                        + output
                        + "'."
                        + NEWLINE, false);
            } else {
                output = line;
            }
        } else if (record_type.equals(KRA_LDIF_KEYGEN)) {
            if (kratoolCfg.get(KRATOOL_CFG_KEYGEN_DATE_OF_MODIFY)) {
                output = KRA_LDIF_DATE_OF_MODIFY
                        + SPACE
                        + mDateOfModify;

                log("Changed '"
                        + line
                        + "' to '"
                        + output
                        + "'."
                        + NEWLINE, false);
            } else {
                output = line;
            }
        } else if (record_type.equals( KRA_LDIF_KEYRECOVERY ) ) {
            if( kratoolCfg.get( KRATOOL_CFG_KEYRECOVERY_DATE_OF_MODIFY ) ) {
                output = KRA_LDIF_DATE_OF_MODIFY
                        + SPACE
                        + mDateOfModify;

                 log( "Changed '"
                    + line
                    + "' to '"
                    + output
                    + "'."
                    + NEWLINE, false );
            } else {
                    output = line;
            }
        } else {
            log("ERROR:  Mismatched record field='"
                    + KRA_LDIF_DATE_OF_MODIFY
                    + "' for record type='"
                    + record_type
                    + "'!"
                    + NEWLINE, true);
        }

        return output;
    }

    /**
     * Helper method which composes the output line for KRA_LDIF_DN.
     * <P>
     *
     * @param record_type the string representation of the input record type
     * @param line the string representation of the input line
     * @return the composed output line
     */
    private static String output_dn(String record_type,
                                     String line) {
        String embedded_cn_data[] = null;
        String embedded_cn_output = null;
        String input = null;
        String output = null;

        try {
            if (record_type.equals(KRA_LDIF_ENROLLMENT)) {
                if (kratoolCfg.get(KRATOOL_CFG_ENROLLMENT_DN)) {

                    // First check for an embedded "cn=<value>"
                    // name-value pair
                    if (line.startsWith(KRA_LDIF_DN_EMBEDDED_CN_DATA)) {
                        // At this point, always extract
                        // the embedded "cn=<value>" name-value pair
                        // which will ALWAYS be the first
                        // portion of the "dn: " attribute
                        embedded_cn_data = line.split(COMMA, 2);

                        embedded_cn_output = compose_numeric_line(
                                                 KRA_LDIF_DN_EMBEDDED_CN_DATA,
                                                 EQUAL_SIGN,
                                                 embedded_cn_data[0],
                                                 false);

                        input = embedded_cn_output
                                + COMMA
                                + embedded_cn_data[1];
                    } else {
                        input = line;
                    }

                    // Since "-source_kra_naming_context", and
                    // "-target_kra_naming_context" are OPTIONAL
                    // parameters, ONLY process this portion of the field
                    // if both of these options have been selected
                    if (mKraNamingContextsFlag) {
                        output = input.replace(mSourceKraNamingContext,
                                                mTargetKraNamingContext);
                    } else {
                        output = input;
                    }
                } else {
                    output = line;
                }
            } else if (record_type.equals(KRA_LDIF_CA_KEY_RECORD)) {
                if (kratoolCfg.get(KRATOOL_CFG_CA_KEY_RECORD_DN)) {

                    // First check for an embedded "cn=<value>"
                    // name-value pair
                    if (line.startsWith(KRA_LDIF_DN_EMBEDDED_CN_DATA)) {
                        // At this point, always extract
                        // the embedded "cn=<value>" name-value pair
                        // which will ALWAYS be the first
                        // portion of the "dn: " attribute
                        embedded_cn_data = line.split(COMMA, 2);

                        embedded_cn_output = compose_numeric_line(
                                                 KRA_LDIF_DN_EMBEDDED_CN_DATA,
                                                 EQUAL_SIGN,
                                                 embedded_cn_data[0],
                                                 false);

                        input = embedded_cn_output
                                + COMMA
                                + embedded_cn_data[1];
                    } else {
                        input = line;
                    }

                    // Since "-source_kra_naming_context", and
                    // "-target_kra_naming_context" are OPTIONAL
                    // parameters, ONLY process this portion of the field
                    // if both of these options have been selected
                    if (mKraNamingContextsFlag) {
                        output = input.replace(mSourceKraNamingContext,
                                                mTargetKraNamingContext);
                    } else {
                        output = input;
                    }
                } else {
                    output = line;
                }
            } else if (record_type.equals(KRA_LDIF_RECOVERY)) {
                if (kratoolCfg.get(KRATOOL_CFG_RECOVERY_DN)) {

                    // First check for an embedded "cn=<value>"
                    // name-value pair
                    if (line.startsWith(KRA_LDIF_DN_EMBEDDED_CN_DATA)) {
                        // At this point, always extract
                        // the embedded "cn=<value>" name-value pair
                        // which will ALWAYS be the first
                        // portion of the "dn: " attribute
                        embedded_cn_data = line.split(COMMA, 2);

                        embedded_cn_output = compose_numeric_line(
                                                 KRA_LDIF_DN_EMBEDDED_CN_DATA,
                                                 EQUAL_SIGN,
                                                 embedded_cn_data[0],
                                                 false);

                        input = embedded_cn_output
                                + COMMA
                                + embedded_cn_data[1];
                    } else {
                        input = line;
                    }

                    // Since "-source_kra_naming_context", and
                    // "-target_kra_naming_context" are OPTIONAL
                    // parameters, ONLY process this portion of the field
                    // if both of these options have been selected
                    if (mKraNamingContextsFlag) {
                        output = input.replace(mSourceKraNamingContext,
                                                mTargetKraNamingContext);
                    } else {
                        output = input;
                    }
                } else {
                    output = line;
                }
            } else if (record_type.equals(KRA_LDIF_TPS_KEY_RECORD)) {
                if (kratoolCfg.get(KRATOOL_CFG_TPS_KEY_RECORD_DN)) {

                    // First check for an embedded "cn=<value>"
                    // name-value pair
                    if (line.startsWith(KRA_LDIF_DN_EMBEDDED_CN_DATA)) {
                        // At this point, always extract
                        // the embedded "cn=<value>" name-value pair
                        // which will ALWAYS be the first
                        // portion of the "dn: " attribute
                        embedded_cn_data = line.split(COMMA, 2);

                        embedded_cn_output = compose_numeric_line(
                                                 KRA_LDIF_DN_EMBEDDED_CN_DATA,
                                                 EQUAL_SIGN,
                                                 embedded_cn_data[0],
                                                 false);

                        input = embedded_cn_output
                                + COMMA
                                + embedded_cn_data[1];
                    } else {
                        input = line;
                    }

                    // Since "-source_kra_naming_context", and
                    // "-target_kra_naming_context" are OPTIONAL
                    // parameters, ONLY process this portion of the field
                    // if both of these options have been selected
                    if (mKraNamingContextsFlag) {
                        output = input.replace(mSourceKraNamingContext,
                                                mTargetKraNamingContext);
                    } else {
                        output = input;
                    }
                } else {
                    output = line;
                }
            } else if (record_type.equals(KRA_LDIF_KEYGEN)) {
                if (kratoolCfg.get(KRATOOL_CFG_KEYGEN_DN)) {

                    // First check for an embedded "cn=<value>"
                    // name-value pair
                    if (line.startsWith(KRA_LDIF_DN_EMBEDDED_CN_DATA)) {
                        // At this point, always extract
                        // the embedded "cn=<value>" name-value pair
                        // which will ALWAYS be the first
                        // portion of the "dn: " attribute
                        embedded_cn_data = line.split(COMMA, 2);

                        embedded_cn_output = compose_numeric_line(
                                                 KRA_LDIF_DN_EMBEDDED_CN_DATA,
                                                 EQUAL_SIGN,
                                                 embedded_cn_data[0],
                                                 false);

                        input = embedded_cn_output
                                + COMMA
                                + embedded_cn_data[1];
                    } else {
                        input = line;
                    }

                    // Since "-source_kra_naming_context", and
                    // "-target_kra_naming_context" are OPTIONAL
                    // parameters, ONLY process this portion of the field
                    // if both of these options have been selected
                    if (mKraNamingContextsFlag) {
                        output = input.replace(mSourceKraNamingContext,
                                                mTargetKraNamingContext);
                    } else {
                        output = input;
                    }
                } else {
                    output = line;
                }
            } else if (record_type.equals( KRA_LDIF_KEYRECOVERY ) ) {
                if( kratoolCfg.get( KRATOOL_CFG_KEYRECOVERY_DN ) ) {
                    // First check for an embedded "cn=<value>"
                    // name-value pair
                    if( line.startsWith( KRA_LDIF_DN_EMBEDDED_CN_DATA ) ) {
                        // At this point, always extract
                        // the embedded "cn=<value>" name-value pair
                        // which will ALWAYS be the first
                        // portion of the "dn: " attribute
                        embedded_cn_data = line.split( COMMA, 2 );

                        embedded_cn_output = compose_numeric_line(
                                                 KRA_LDIF_DN_EMBEDDED_CN_DATA,
                                                 EQUAL_SIGN,
                                                 embedded_cn_data[0],
                                                 false );

                        input = embedded_cn_output
                              + COMMA
                              + embedded_cn_data[1];
                    } else {
                        input = line;
                    }

                    // Since "-source_kra_naming_context", and
                    // "-target_kra_naming_context" are OPTIONAL
                    // parameters, ONLY process this portion of the field
                    // if both of these options have been selected
                    if( mKraNamingContextsFlag ) {
                        output = input.replace( mSourceKraNamingContext,
                                                mTargetKraNamingContext );
                    } else {
                        output = input;
                    }

                } else {
                        output = line;
                }
            } else if (record_type.equals(KRA_LDIF_RECORD)) {
                // Non-Request / Non-Key Record:
                //     Pass through the original
                //     'dn' line UNCHANGED
                //     so that it is ALWAYS written
                output = line;
            } else {
                log("ERROR:  Mismatched record field='"
                        + KRA_LDIF_DN
                        + "' for record type='"
                        + record_type
                        + "'!"
                        + NEWLINE, true);
            }
        } catch (PatternSyntaxException exDnEmbeddedCnNameValuePattern) {
            log("ERROR:  line='"
                    + line
                    + "' PatternSyntaxException: '"
                    + exDnEmbeddedCnNameValuePattern.toString()
                    + "'"
                    + NEWLINE, true);
        } catch (NullPointerException exNullPointerException) {
            log("ERROR:  Unable to replace source KRA naming context '"
                    + mSourceKraNamingContext
                    + "' with target KRA naming context '"
                    + mTargetKraNamingContext
                    + "' NullPointerException: '"
                    + exNullPointerException.toString()
                    + "'"
                    + NEWLINE, true);
        }

        return output;
    }

    /**
     * Helper method which composes the output line for
     * KRA_LDIF_EXTDATA_KEY_RECORD.
     * <P>
     *
     * @param record_type the string representation of the input record type
     * @param line the string representation of the input line
     * @return the composed output line
     */
    private static String output_extdata_key_record(String record_type,
                                                     String line) {
        String output = null;

        if (record_type.equals(KRA_LDIF_ENROLLMENT)) {
            if (kratoolCfg.get(KRATOOL_CFG_ENROLLMENT_EXTDATA_KEY_RECORD)) {
                output = compose_numeric_line(KRA_LDIF_EXTDATA_KEY_RECORD,
                                               SPACE,
                                               line,
                                               false);
            } else {
                output = line;
            }
        } else if (record_type.equals(KRA_LDIF_KEYGEN)) {
            if (kratoolCfg.get(KRATOOL_CFG_KEYGEN_EXTDATA_KEY_RECORD)) {
                output = compose_numeric_line(KRA_LDIF_EXTDATA_KEY_RECORD,
                                               SPACE,
                                               line,
                                               false);
            } else {
                output = line;
            }
        } else {
            log("ERROR:  Mismatched record field='"
                    + KRA_LDIF_EXTDATA_KEY_RECORD
                    + "' for record type='"
                    + record_type
                    + "'!"
                    + NEWLINE, true);
        }

        return output;
    }

    /**
     * Helper method which composes the output line for
     * KRA_LDIF_EXTDATA_REQUEST_ID.
     * <P>
     *
     * @param record_type the string representation of the input record type
     * @param line the string representation of the input line
     * @return the composed output line
     */
    private static String output_extdata_request_id(String record_type,
                                                     String line) {
        String output = null;

        if (record_type.equals(KRA_LDIF_ENROLLMENT)) {
            // ALWAYS pass-through "extdata-requestId" for
            // KRA_LDIF_ENROLLMENT records UNCHANGED because the
            // value in this field is associated with the issuing CA!
            output = line;
        } else if (record_type.equals(KRA_LDIF_RECOVERY)) {
            if (kratoolCfg.get(KRATOOL_CFG_RECOVERY_EXTDATA_REQUEST_ID)) {
                output = compose_numeric_line(KRA_LDIF_EXTDATA_REQUEST_ID,
                                               SPACE,
                                               line,
                                               false);
            } else {
                output = line;
            }
        } else if (record_type.equals(KRA_LDIF_KEYGEN)) {
            if (kratoolCfg.get(KRATOOL_CFG_KEYGEN_EXTDATA_REQUEST_ID)) {
                output = compose_numeric_line(KRA_LDIF_EXTDATA_REQUEST_ID,
                                               SPACE,
                                               line,
                                               false);
            } else {
                output = line;
            }
        } else if (record_type.equals( KRA_LDIF_KEYRECOVERY ) ) {
            if( kratoolCfg.get(KRATOOL_CFG_KEYRECOVERY_EXTDATA_REQUEST_ID ) ) {
                output = compose_numeric_line(KRA_LDIF_EXTDATA_REQUEST_ID,
                        SPACE,
                        line,
                        false );
            } else {
                output = line;
            }
        } else {
            log("ERROR:  Mismatched record field='"
                    + KRA_LDIF_EXTDATA_REQUEST_ID
                    + "' for record type='"
                    + record_type
                    + "'!"
                    + NEWLINE, true);
        }

        return output;
    }

    /**
     * Helper method which composes the output line for
     * KRA_LDIF_EXTDATA_REQUEST_NOTES.
     * <P>
     *
     * @param record_type the string representation of the input record type
     * @param line the string representation of the input line
     * @return the composed output line
     */
    private static String output_extdata_request_notes(String record_type,
            String line) {
        StringBuilder input = new StringBuilder();

        String data = null;
        String unformatted_data = null;
        String output = null;
        String next_line = null;

        // extract the data
        if (line.length() > KRA_LDIF_EXTDATA_REQUEST_NOTES.length()) {
            input.append(line.substring(
                        KRA_LDIF_EXTDATA_REQUEST_NOTES.length() + 1
                    ).trim());
        } else {
            input.append(line.substring(
                        KRA_LDIF_EXTDATA_REQUEST_NOTES.length()
                    ).trim());
        }

        while ((line = ldif_record.next()) != null) {
            if (line.startsWith(SPACE)) {
                // Do NOT use "trim()";
                // remove single leading space and
                // trailing carriage returns and newlines ONLY!
                input.append(line.replaceFirst(" ", "").replace('\r', '\0').replace('\n', '\0'));
            } else {
                next_line = line;
                break;
            }
        }

        if (record_type.equals(KRA_LDIF_ENROLLMENT)) {
            if (kratoolCfg.get(KRATOOL_CFG_ENROLLMENT_EXTDATA_REQUEST_NOTES)) {
                // write out a revised 'extdata-requestnotes' line
                if (mRewrapFlag && mAppendIdOffsetFlag) {
                    data = input.toString()
                            + SPACE
                            + LEFT_BRACE
                            + mDateOfModify
                            + RIGHT_BRACE
                            + COLON + SPACE
                            + KRA_LDIF_REWRAP_MESSAGE
                            + mPublicKeySize
                            + KRA_LDIF_RSA_MESSAGE
                            + mSourcePKISecurityDatabasePwdfileMessage
                            + SPACE
                            + PLUS + SPACE
                            + KRA_LDIF_APPENDED_ID_OFFSET_MESSAGE
                            + SPACE
                            + TIC
                            + mAppendIdOffset.toString()
                            + TIC
                            + mKraNamingContextMessage
                            + mProcessRequestsAndKeyRecordsOnlyMessage;

                    // Unformat the data
                    unformatted_data = stripEOL(data);

                    // Format the unformatted_data
                    // to match the desired LDIF format
                    output = KRA_LDIF_EXTDATA_REQUEST_NOTES
                            + SPACE
                            + format_ldif_data(
                                    EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                    unformatted_data);
                } else if (mRewrapFlag && mRemoveIdOffsetFlag) {
                    data = input.toString()
                            + SPACE
                            + LEFT_BRACE
                            + mDateOfModify
                            + RIGHT_BRACE
                            + COLON + SPACE
                            + KRA_LDIF_REWRAP_MESSAGE
                            + mPublicKeySize
                            + KRA_LDIF_RSA_MESSAGE
                            + mSourcePKISecurityDatabasePwdfileMessage
                            + SPACE
                            + PLUS + SPACE
                            + KRA_LDIF_REMOVED_ID_OFFSET_MESSAGE
                            + SPACE
                            + TIC
                            + mRemoveIdOffset.toString()
                            + TIC
                            + mKraNamingContextMessage
                            + mProcessRequestsAndKeyRecordsOnlyMessage;

                    // Unformat the data
                    unformatted_data = stripEOL(data);

                    // Format the unformatted_data
                    // to match the desired LDIF format
                    output = KRA_LDIF_EXTDATA_REQUEST_NOTES
                            + SPACE
                            + format_ldif_data(
                                    EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                    unformatted_data);
                } else if (mRewrapFlag) {
                    data = input.toString()
                            + SPACE
                            + LEFT_BRACE
                            + mDateOfModify
                            + RIGHT_BRACE
                            + COLON + SPACE
                            + KRA_LDIF_REWRAP_MESSAGE
                            + mPublicKeySize
                            + KRA_LDIF_RSA_MESSAGE
                            + mSourcePKISecurityDatabasePwdfileMessage
                            + mKraNamingContextMessage
                            + mProcessRequestsAndKeyRecordsOnlyMessage;

                    // Unformat the data
                    unformatted_data = stripEOL(data);

                    // Format the unformatted_data
                    // to match the desired LDIF format
                    output = KRA_LDIF_EXTDATA_REQUEST_NOTES
                            + SPACE
                            + format_ldif_data(
                                    EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                    unformatted_data);
                } else if (mAppendIdOffsetFlag) {
                    data = input.toString()
                            + SPACE
                            + LEFT_BRACE
                            + mDateOfModify
                            + RIGHT_BRACE
                            + COLON + SPACE
                            + KRA_LDIF_APPENDED_ID_OFFSET_MESSAGE
                            + SPACE
                            + TIC
                            + mAppendIdOffset.toString()
                            + TIC
                            + mKraNamingContextMessage
                            + mProcessRequestsAndKeyRecordsOnlyMessage;

                    // Unformat the data
                    unformatted_data = stripEOL(data);

                    // Format the unformatted_data
                    // to match the desired LDIF format
                    output = KRA_LDIF_EXTDATA_REQUEST_NOTES
                            + SPACE
                            + format_ldif_data(
                                    EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                    unformatted_data);
                } else if (mRemoveIdOffsetFlag) {
                    data = input.toString()
                            + SPACE
                            + LEFT_BRACE
                            + mDateOfModify
                            + RIGHT_BRACE
                            + COLON + SPACE
                            + KRA_LDIF_REMOVED_ID_OFFSET_MESSAGE
                            + SPACE
                            + TIC
                            + mRemoveIdOffset.toString()
                            + TIC
                            + mKraNamingContextMessage
                            + mProcessRequestsAndKeyRecordsOnlyMessage;

                    // Unformat the data
                    unformatted_data = stripEOL(data);

                    // Format the unformatted_data
                    // to match the desired LDIF format
                    output = KRA_LDIF_EXTDATA_REQUEST_NOTES
                            + SPACE
                            + format_ldif_data(
                                    EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                    unformatted_data);
                }

                // log this information
                log("Changed:"
                        + NEWLINE
                        + TIC
                        + KRA_LDIF_EXTDATA_REQUEST_NOTES
                        + SPACE
                        + format_ldif_data(
                                EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                input.toString())
                        + TIC
                        + NEWLINE
                        + "--->"
                        + NEWLINE
                        + TIC
                        + output
                        + TIC
                        + NEWLINE, false);
            } else {
                output = line;
            }
        } else if (record_type.equals(KRA_LDIF_RECOVERY)) {
            if (kratoolCfg.get(KRATOOL_CFG_RECOVERY_EXTDATA_REQUEST_NOTES)) {
                // write out a revised 'extdata-requestnotes' line
                if (mRewrapFlag && mAppendIdOffsetFlag) {
                    data = input.toString()
                            + SPACE
                            + LEFT_BRACE
                            + mDateOfModify
                            + RIGHT_BRACE
                            + COLON + SPACE
                            + KRA_LDIF_REWRAP_MESSAGE
                            + mPublicKeySize
                            + KRA_LDIF_RSA_MESSAGE
                            + mSourcePKISecurityDatabasePwdfileMessage
                            + SPACE
                            + PLUS + SPACE
                            + KRA_LDIF_APPENDED_ID_OFFSET_MESSAGE
                            + SPACE
                            + TIC
                            + mAppendIdOffset.toString()
                            + TIC
                            + mKraNamingContextMessage
                            + mProcessRequestsAndKeyRecordsOnlyMessage;

                    // Unformat the data
                    unformatted_data = stripEOL(data);

                    // Format the unformatted_data
                    // to match the desired LDIF format
                    output = KRA_LDIF_EXTDATA_REQUEST_NOTES
                            + SPACE
                            + format_ldif_data(
                                    EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                    unformatted_data);
                } else if (mRewrapFlag && mRemoveIdOffsetFlag) {
                    data = input.toString()
                            + SPACE
                            + LEFT_BRACE
                            + mDateOfModify
                            + RIGHT_BRACE
                            + COLON + SPACE
                            + KRA_LDIF_REWRAP_MESSAGE
                            + mPublicKeySize
                            + KRA_LDIF_RSA_MESSAGE
                            + mSourcePKISecurityDatabasePwdfileMessage
                            + SPACE
                            + PLUS + SPACE
                            + KRA_LDIF_REMOVED_ID_OFFSET_MESSAGE
                            + SPACE
                            + TIC
                            + mRemoveIdOffset.toString()
                            + TIC
                            + mKraNamingContextMessage
                            + mProcessRequestsAndKeyRecordsOnlyMessage;

                    // Unformat the data
                    unformatted_data = stripEOL(data);

                    // Format the unformatted_data
                    // to match the desired LDIF format
                    output = KRA_LDIF_EXTDATA_REQUEST_NOTES
                            + SPACE
                            + format_ldif_data(
                                    EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                    unformatted_data);
                } else if (mRewrapFlag) {
                    data = input.toString()
                            + SPACE
                            + LEFT_BRACE
                            + mDateOfModify
                            + RIGHT_BRACE
                            + COLON + SPACE
                            + KRA_LDIF_REWRAP_MESSAGE
                            + mPublicKeySize
                            + KRA_LDIF_RSA_MESSAGE
                            + mSourcePKISecurityDatabasePwdfileMessage
                            + mKraNamingContextMessage
                            + mProcessRequestsAndKeyRecordsOnlyMessage;

                    // Unformat the data
                    unformatted_data = stripEOL(data);

                    // Format the unformatted_data
                    // to match the desired LDIF format
                    output = KRA_LDIF_EXTDATA_REQUEST_NOTES
                            + SPACE
                            + format_ldif_data(
                                    EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                    unformatted_data);
                } else if (mAppendIdOffsetFlag) {
                    data = input.toString()
                            + SPACE
                            + LEFT_BRACE
                            + mDateOfModify
                            + RIGHT_BRACE
                            + COLON + SPACE
                            + KRA_LDIF_APPENDED_ID_OFFSET_MESSAGE
                            + SPACE
                            + TIC
                            + mAppendIdOffset.toString()
                            + TIC
                            + mKraNamingContextMessage
                            + mProcessRequestsAndKeyRecordsOnlyMessage;

                    // Unformat the data
                    unformatted_data = stripEOL(data);

                    // Format the unformatted_data
                    // to match the desired LDIF format
                    output = KRA_LDIF_EXTDATA_REQUEST_NOTES
                            + SPACE
                            + format_ldif_data(
                                    EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                    unformatted_data);
                } else if (mRemoveIdOffsetFlag) {
                    data = input.toString()
                            + SPACE
                            + LEFT_BRACE
                            + mDateOfModify
                            + RIGHT_BRACE
                            + COLON + SPACE
                            + KRA_LDIF_REMOVED_ID_OFFSET_MESSAGE
                            + SPACE
                            + TIC
                            + mRemoveIdOffset.toString()
                            + TIC
                            + mKraNamingContextMessage
                            + mProcessRequestsAndKeyRecordsOnlyMessage;

                    // Unformat the data
                    unformatted_data = stripEOL(data);

                    // Format the unformatted_data
                    // to match the desired LDIF format
                    output = KRA_LDIF_EXTDATA_REQUEST_NOTES
                            + SPACE
                            + format_ldif_data(
                                    EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                    unformatted_data);
                }

                // log this information
                log("Changed:"
                        + NEWLINE
                        + TIC
                        + KRA_LDIF_EXTDATA_REQUEST_NOTES
                        + SPACE
                        + format_ldif_data(
                                EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                input.toString())
                        + TIC
                        + NEWLINE
                        + "--->"
                        + NEWLINE
                        + TIC
                        + output
                        + TIC
                        + NEWLINE, false);
            } else {
                output = line;
            }
        } else if (record_type.equals(KRA_LDIF_KEYGEN)) {
            if (kratoolCfg.get(KRATOOL_CFG_KEYGEN_EXTDATA_REQUEST_NOTES)) {
                // write out a revised 'extdata-requestnotes' line
                if (mRewrapFlag && mAppendIdOffsetFlag) {
                    data = input.toString()
                            + SPACE
                            + LEFT_BRACE
                            + mDateOfModify
                            + RIGHT_BRACE
                            + COLON + SPACE
                            + KRA_LDIF_REWRAP_MESSAGE
                            + mPublicKeySize
                            + KRA_LDIF_RSA_MESSAGE
                            + mSourcePKISecurityDatabasePwdfileMessage
                            + SPACE
                            + PLUS + SPACE
                            + KRA_LDIF_APPENDED_ID_OFFSET_MESSAGE
                            + SPACE
                            + TIC
                            + mAppendIdOffset.toString()
                            + TIC
                            + mKraNamingContextMessage
                            + mProcessRequestsAndKeyRecordsOnlyMessage;

                    // Unformat the data
                    unformatted_data = stripEOL(data);

                    // Format the unformatted_data
                    // to match the desired LDIF format
                    output = KRA_LDIF_EXTDATA_REQUEST_NOTES
                            + SPACE
                            + format_ldif_data(
                                    EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                    unformatted_data);
                } else if (mRewrapFlag && mRemoveIdOffsetFlag) {
                    data = input.toString()
                            + SPACE
                            + LEFT_BRACE
                            + mDateOfModify
                            + RIGHT_BRACE
                            + COLON + SPACE
                            + KRA_LDIF_REWRAP_MESSAGE
                            + mPublicKeySize
                            + KRA_LDIF_RSA_MESSAGE
                            + mSourcePKISecurityDatabasePwdfileMessage
                            + SPACE
                            + PLUS + SPACE
                            + KRA_LDIF_REMOVED_ID_OFFSET_MESSAGE
                            + SPACE
                            + TIC
                            + mRemoveIdOffset.toString()
                            + TIC
                            + mKraNamingContextMessage
                            + mProcessRequestsAndKeyRecordsOnlyMessage;

                    // Unformat the data
                    unformatted_data = stripEOL(data);

                    // Format the unformatted_data
                    // to match the desired LDIF format
                    output = KRA_LDIF_EXTDATA_REQUEST_NOTES
                            + SPACE
                            + format_ldif_data(
                                    EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                    unformatted_data);
                } else if (mRewrapFlag) {
                    data = input.toString()
                            + SPACE
                            + LEFT_BRACE
                            + mDateOfModify
                            + RIGHT_BRACE
                            + COLON + SPACE
                            + KRA_LDIF_REWRAP_MESSAGE
                            + mPublicKeySize
                            + KRA_LDIF_RSA_MESSAGE
                            + mSourcePKISecurityDatabasePwdfileMessage
                            + mKraNamingContextMessage
                            + mProcessRequestsAndKeyRecordsOnlyMessage;

                    // Unformat the data
                    unformatted_data = stripEOL(data);

                    // Format the unformatted_data
                    // to match the desired LDIF format
                    output = KRA_LDIF_EXTDATA_REQUEST_NOTES
                            + SPACE
                            + format_ldif_data(
                                    EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                    unformatted_data);
                } else if (mAppendIdOffsetFlag) {
                    data = input.toString()
                            + SPACE
                            + LEFT_BRACE
                            + mDateOfModify
                            + RIGHT_BRACE
                            + COLON + SPACE
                            + KRA_LDIF_APPENDED_ID_OFFSET_MESSAGE
                            + SPACE
                            + TIC
                            + mAppendIdOffset.toString()
                            + TIC
                            + mKraNamingContextMessage
                            + mProcessRequestsAndKeyRecordsOnlyMessage;

                    // Unformat the data
                    unformatted_data = stripEOL(data);

                    // Format the unformatted_data
                    // to match the desired LDIF format
                    output = KRA_LDIF_EXTDATA_REQUEST_NOTES
                            + SPACE
                            + format_ldif_data(
                                    EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                    unformatted_data);
                } else if (mRemoveIdOffsetFlag) {
                    data = input.toString()
                            + SPACE
                            + LEFT_BRACE
                            + mDateOfModify
                            + RIGHT_BRACE
                            + COLON + SPACE
                            + KRA_LDIF_REMOVED_ID_OFFSET_MESSAGE
                            + SPACE
                            + TIC
                            + mRemoveIdOffset.toString()
                            + TIC
                            + mKraNamingContextMessage
                            + mProcessRequestsAndKeyRecordsOnlyMessage;

                    // Unformat the data
                    unformatted_data = stripEOL(data);

                    // Format the unformatted_data
                    // to match the desired LDIF format
                    output = KRA_LDIF_EXTDATA_REQUEST_NOTES
                            + SPACE
                            + format_ldif_data(
                                    EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                    unformatted_data);
                }

                // log this information
                log("Changed:"
                        + NEWLINE
                        + TIC
                        + KRA_LDIF_EXTDATA_REQUEST_NOTES
                        + SPACE
                        + format_ldif_data(
                                EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                input.toString())
                        + TIC
                        + NEWLINE
                        + "--->"
                        + NEWLINE
                        + TIC
                        + output
                        + TIC
                        + NEWLINE, false);
            } else {
                output = line;
            }
        } else if (record_type.equals( KRA_LDIF_KEYRECOVERY ) ) {
            if( kratoolCfg.get( KRATOOL_CFG_KEYRECOVERY_EXTDATA_REQUEST_NOTES ) ) {
                // write out a revised 'extdata-requestnotes' line
                if( mRewrapFlag && mAppendIdOffsetFlag ) {
                    data = input
                         + SPACE
                         + LEFT_BRACE
                         + mDateOfModify
                         + RIGHT_BRACE
                         + COLON + SPACE
                         + KRA_LDIF_REWRAP_MESSAGE
                         + mPublicKeySize
                         + KRA_LDIF_RSA_MESSAGE
                         + mSourcePKISecurityDatabasePwdfileMessage
                         + SPACE
                         + PLUS + SPACE
                         + KRA_LDIF_APPENDED_ID_OFFSET_MESSAGE
                         + SPACE
                         + TIC
                         + mAppendIdOffset.toString()
                         + TIC
                         + mKraNamingContextMessage
                         + mProcessRequestsAndKeyRecordsOnlyMessage;

                    // Unformat the data
                    unformatted_data = stripEOL( data );

                    // Format the unformatted_data
                    // to match the desired LDIF format
                    output = KRA_LDIF_EXTDATA_REQUEST_NOTES
                           + SPACE
                           + format_ldif_data(
                                 EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                 unformatted_data );
                } else if( mRewrapFlag && mRemoveIdOffsetFlag ) {
                    data = input
                         + SPACE
                         + LEFT_BRACE
                         + mDateOfModify
                         + RIGHT_BRACE
                         + COLON + SPACE
                         + KRA_LDIF_REWRAP_MESSAGE
                         + mPublicKeySize
                         + KRA_LDIF_RSA_MESSAGE
                         + mSourcePKISecurityDatabasePwdfileMessage
                         + SPACE
                         + PLUS + SPACE
                         + KRA_LDIF_REMOVED_ID_OFFSET_MESSAGE
                         + SPACE
                         + TIC
                         + mRemoveIdOffset.toString()
                         + TIC
                         + mKraNamingContextMessage
                         + mProcessRequestsAndKeyRecordsOnlyMessage;

                    // Unformat the data
                    unformatted_data = stripEOL( data );

                    // Format the unformatted_data
                    // to match the desired LDIF format
                    output = KRA_LDIF_EXTDATA_REQUEST_NOTES
                           + SPACE
                           + format_ldif_data(
                                 EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                 unformatted_data );
                } else if( mRewrapFlag ) {
                    data = input
                         + SPACE
                         + LEFT_BRACE
                         + mDateOfModify
                         + RIGHT_BRACE
                         + COLON + SPACE
                         + KRA_LDIF_REWRAP_MESSAGE
                         + mPublicKeySize
                         + KRA_LDIF_RSA_MESSAGE
                         + mSourcePKISecurityDatabasePwdfileMessage
                         + mKraNamingContextMessage
                         + mProcessRequestsAndKeyRecordsOnlyMessage;

                    // Unformat the data
                    unformatted_data = stripEOL( data );

                    // Format the unformatted_data
                    // to match the desired LDIF format
                    output = KRA_LDIF_EXTDATA_REQUEST_NOTES
                           + SPACE
                           + format_ldif_data(
                                 EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                 unformatted_data );
                } else if( mAppendIdOffsetFlag ) {
                    data = input
                         + SPACE
                         + LEFT_BRACE
                         + mDateOfModify
                         + RIGHT_BRACE
                         + COLON + SPACE
                         + KRA_LDIF_APPENDED_ID_OFFSET_MESSAGE
                         + SPACE
                         + TIC
                         + mAppendIdOffset.toString()
                         + TIC
                         + mKraNamingContextMessage
                         + mProcessRequestsAndKeyRecordsOnlyMessage;

                    // Unformat the data
                    unformatted_data = stripEOL( data );

                    // Format the unformatted_data
                    // to match the desired LDIF format
                    output = KRA_LDIF_EXTDATA_REQUEST_NOTES
                           + SPACE
                           + format_ldif_data(
                                 EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                 unformatted_data );
                } else if( mRemoveIdOffsetFlag ) {
                    data = input
                         + SPACE
                         + LEFT_BRACE
                         + mDateOfModify
                         + RIGHT_BRACE
                         + COLON + SPACE
                         + KRA_LDIF_REMOVED_ID_OFFSET_MESSAGE
                         + SPACE
                         + TIC
                         + mRemoveIdOffset.toString()
                         + TIC
                         + mKraNamingContextMessage
                         + mProcessRequestsAndKeyRecordsOnlyMessage;

                    // Unformat the data
                    unformatted_data = stripEOL( data );

                    // Format the unformatted_data
                    // to match the desired LDIF format
                    output = KRA_LDIF_EXTDATA_REQUEST_NOTES
                           + SPACE
                           + format_ldif_data(
                                 EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                 unformatted_data );
                }

                // log this information
                log( "Changed:"
                   + NEWLINE
                   + TIC
                   + KRA_LDIF_EXTDATA_REQUEST_NOTES
                   + SPACE
                   + format_ldif_data(
                         EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                         input.toString() )
                   + TIC
                   + NEWLINE
                   + "--->"
                   + NEWLINE
                   + TIC
                   + output
                   + TIC
                   + NEWLINE, false );
            } else {
                output = line;
            }
        } else {
            log("ERROR:  Mismatched record field='"
                    + KRA_LDIF_EXTDATA_REQUEST_NOTES
                    + "' for record type='"
                    + record_type
                    + "'!"
                    + NEWLINE, true);
        }

        if (output != null) {
            output += NEWLINE + next_line;
        }

        return output;
    }

    /**
     * Helper method which composes the output line for
     * KRA_LDIF_EXTDATA_REQUEST_NOTES.
     * <P>
     *
     * @param record_type the string representation of the input record type
     * @param previous_line the string representation of the previous input line
     * @param writer the PrintWriter used to output this new LDIF line
     * @return the composed output line
     */
    private static void create_extdata_request_notes(String record_type,
                                                      String previous_line,
                                                      PrintWriter writer) {
        String data = null;
        String unformatted_data = null;
        String output = null;

        if (record_type.equals(KRA_LDIF_RECOVERY)) {
            if (kratoolCfg.get(KRATOOL_CFG_RECOVERY_EXTDATA_REQUEST_NOTES)) {
                if (!previous_line.startsWith(KRA_LDIF_EXTDATA_REQUEST_NOTES)) {
                    // write out the missing 'extdata-requestnotes' line
                    if (mRewrapFlag && mAppendIdOffsetFlag) {
                        data = LEFT_BRACE
                                + mDateOfModify
                                + RIGHT_BRACE
                                + COLON + SPACE
                                + KRA_LDIF_REWRAP_MESSAGE
                                + mPublicKeySize
                                + KRA_LDIF_RSA_MESSAGE
                                + mSourcePKISecurityDatabasePwdfileMessage
                                + SPACE
                                + PLUS + SPACE
                                + KRA_LDIF_APPENDED_ID_OFFSET_MESSAGE
                                + SPACE
                                + TIC
                                + mAppendIdOffset.toString()
                                + TIC
                                + mKraNamingContextMessage
                                + mProcessRequestsAndKeyRecordsOnlyMessage;

                        // Unformat the data
                        unformatted_data = stripEOL(data);

                        // Format the unformatted_data
                        // to match the desired LDIF format
                        output = KRA_LDIF_EXTDATA_REQUEST_NOTES
                                + SPACE
                                + format_ldif_data(
                                        EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                        unformatted_data);
                    } else if (mRewrapFlag && mRemoveIdOffsetFlag) {
                        data = LEFT_BRACE
                                + mDateOfModify
                                + RIGHT_BRACE
                                + COLON + SPACE
                                + KRA_LDIF_REWRAP_MESSAGE
                                + mPublicKeySize
                                + KRA_LDIF_RSA_MESSAGE
                                + mSourcePKISecurityDatabasePwdfileMessage
                                + SPACE
                                + PLUS + SPACE
                                + KRA_LDIF_REMOVED_ID_OFFSET_MESSAGE
                                + SPACE
                                + TIC
                                + mRemoveIdOffset.toString()
                                + TIC
                                + mKraNamingContextMessage
                                + mProcessRequestsAndKeyRecordsOnlyMessage;

                        // Unformat the data
                        unformatted_data = stripEOL(data);

                        // Format the unformatted_data
                        // to match the desired LDIF format
                        output = KRA_LDIF_EXTDATA_REQUEST_NOTES
                                + SPACE
                                + format_ldif_data(
                                        EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                        unformatted_data);
                    } else if (mRewrapFlag) {
                        data = LEFT_BRACE
                                + mDateOfModify
                                + RIGHT_BRACE
                                + COLON + SPACE
                                + KRA_LDIF_REWRAP_MESSAGE
                                + mPublicKeySize
                                + KRA_LDIF_RSA_MESSAGE
                                + mSourcePKISecurityDatabasePwdfileMessage
                                + mKraNamingContextMessage
                                + mProcessRequestsAndKeyRecordsOnlyMessage;

                        // Unformat the data
                        unformatted_data = stripEOL(data);

                        // Format the unformatted_data
                        // to match the desired LDIF format
                        output = KRA_LDIF_EXTDATA_REQUEST_NOTES
                                + SPACE
                                + format_ldif_data(
                                        EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                        unformatted_data);
                    } else if (mAppendIdOffsetFlag) {
                        data = LEFT_BRACE
                                + mDateOfModify
                                + RIGHT_BRACE
                                + COLON + SPACE
                                + KRA_LDIF_APPENDED_ID_OFFSET_MESSAGE
                                + SPACE
                                + TIC
                                + mAppendIdOffset.toString()
                                + TIC
                                + mKraNamingContextMessage
                                + mProcessRequestsAndKeyRecordsOnlyMessage;

                        // Unformat the data
                        unformatted_data = stripEOL(data);

                        // Format the unformatted_data
                        // to match the desired LDIF format
                        output = KRA_LDIF_EXTDATA_REQUEST_NOTES
                                + SPACE
                                + format_ldif_data(
                                        EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                        unformatted_data);
                    } else if (mRemoveIdOffsetFlag) {
                        data = LEFT_BRACE
                                + mDateOfModify
                                + RIGHT_BRACE
                                + COLON + SPACE
                                + KRA_LDIF_REMOVED_ID_OFFSET_MESSAGE
                                + SPACE
                                + TIC
                                + mRemoveIdOffset.toString()
                                + TIC
                                + mKraNamingContextMessage
                                + mProcessRequestsAndKeyRecordsOnlyMessage;

                        // Unformat the data
                        unformatted_data = stripEOL(data);

                        // Format the unformatted_data
                        // to match the desired LDIF format
                        output = KRA_LDIF_EXTDATA_REQUEST_NOTES
                                + SPACE
                                + format_ldif_data(
                                        EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                        unformatted_data);
                    }

                    // log this information
                    log("Created:"
                            + NEWLINE
                            + TIC
                            + output
                            + TIC
                            + NEWLINE, false);

                    // Write out this revised line
                    // and flush the buffer
                    writer.write(output + NEWLINE);
                    writer.flush();
                    System.out.print(".");
                }
            }
        } else if (record_type.equals(KRA_LDIF_KEYGEN)) {
            if (kratoolCfg.get(KRATOOL_CFG_KEYGEN_EXTDATA_REQUEST_NOTES)) {
                if (!previous_line.startsWith(KRA_LDIF_EXTDATA_REQUEST_NOTES)) {
                    // write out the missing 'extdata-requestnotes' line
                    if (mRewrapFlag && mAppendIdOffsetFlag) {
                        data = LEFT_BRACE
                                + mDateOfModify
                                + RIGHT_BRACE
                                + COLON + SPACE
                                + KRA_LDIF_REWRAP_MESSAGE
                                + mPublicKeySize
                                + KRA_LDIF_RSA_MESSAGE
                                + mSourcePKISecurityDatabasePwdfileMessage
                                + SPACE
                                + PLUS + SPACE
                                + KRA_LDIF_APPENDED_ID_OFFSET_MESSAGE
                                + SPACE
                                + TIC
                                + mAppendIdOffset.toString()
                                + TIC
                                + mKraNamingContextMessage
                                + mProcessRequestsAndKeyRecordsOnlyMessage;

                        // Unformat the data
                        unformatted_data = stripEOL(data);

                        // Format the unformatted_data
                        // to match the desired LDIF format
                        output = KRA_LDIF_EXTDATA_REQUEST_NOTES
                                + SPACE
                                + format_ldif_data(
                                        EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                        unformatted_data);
                    } else if (mRewrapFlag && mRemoveIdOffsetFlag) {
                        data = LEFT_BRACE
                                + mDateOfModify
                                + RIGHT_BRACE
                                + COLON + SPACE
                                + KRA_LDIF_REWRAP_MESSAGE
                                + mPublicKeySize
                                + KRA_LDIF_RSA_MESSAGE
                                + mSourcePKISecurityDatabasePwdfileMessage
                                + SPACE
                                + PLUS + SPACE
                                + KRA_LDIF_REMOVED_ID_OFFSET_MESSAGE
                                + SPACE
                                + TIC
                                + mRemoveIdOffset.toString()
                                + TIC
                                + mKraNamingContextMessage
                                + mProcessRequestsAndKeyRecordsOnlyMessage;

                        // Unformat the data
                        unformatted_data = stripEOL(data);

                        // Format the unformatted_data
                        // to match the desired LDIF format
                        output = KRA_LDIF_EXTDATA_REQUEST_NOTES
                                + SPACE
                                + format_ldif_data(
                                        EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                        unformatted_data);
                    } else if (mRewrapFlag) {
                        data = LEFT_BRACE
                                + mDateOfModify
                                + RIGHT_BRACE
                                + COLON + SPACE
                                + KRA_LDIF_REWRAP_MESSAGE
                                + mPublicKeySize
                                + KRA_LDIF_RSA_MESSAGE
                                + mSourcePKISecurityDatabasePwdfileMessage
                                + mKraNamingContextMessage
                                + mProcessRequestsAndKeyRecordsOnlyMessage;

                        // Unformat the data
                        unformatted_data = stripEOL(data);

                        // Format the unformatted_data
                        // to match the desired LDIF format
                        output = KRA_LDIF_EXTDATA_REQUEST_NOTES
                                + SPACE
                                + format_ldif_data(
                                        EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                        unformatted_data);
                    } else if (mAppendIdOffsetFlag) {
                        data = LEFT_BRACE
                                + mDateOfModify
                                + RIGHT_BRACE
                                + COLON + SPACE
                                + KRA_LDIF_APPENDED_ID_OFFSET_MESSAGE
                                + SPACE
                                + TIC
                                + mAppendIdOffset.toString()
                                + TIC
                                + mKraNamingContextMessage
                                + mProcessRequestsAndKeyRecordsOnlyMessage;

                        // Unformat the data
                        unformatted_data = stripEOL(data);

                        // Format the unformatted_data
                        // to match the desired LDIF format
                        output = KRA_LDIF_EXTDATA_REQUEST_NOTES
                                + SPACE
                                + format_ldif_data(
                                        EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                        unformatted_data);
                    } else if (mRemoveIdOffsetFlag) {
                        data = LEFT_BRACE
                                + mDateOfModify
                                + RIGHT_BRACE
                                + COLON + SPACE
                                + KRA_LDIF_REMOVED_ID_OFFSET_MESSAGE
                                + SPACE
                                + TIC
                                + mRemoveIdOffset.toString()
                                + TIC
                                + mKraNamingContextMessage
                                + mProcessRequestsAndKeyRecordsOnlyMessage;

                        // Unformat the data
                        unformatted_data = stripEOL(data);

                        // Format the unformatted_data
                        // to match the desired LDIF format
                        output = KRA_LDIF_EXTDATA_REQUEST_NOTES
                                + SPACE
                                + format_ldif_data(
                                        EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                        unformatted_data);
                    }

                    // log this information
                    log("Created:"
                            + NEWLINE
                            + TIC
                            + output
                            + TIC
                            + NEWLINE, false);

                    // Write out this revised line
                    // and flush the buffer
                    writer.write(output + NEWLINE);
                    writer.flush();
                    System.out.print(".");
                }
            }
        } else if (record_type.equals(KRA_LDIF_KEYRECOVERY)) {
            if( kratoolCfg.get( KRATOOL_CFG_KEYRECOVERY_EXTDATA_REQUEST_NOTES ) ) {
                if(!previous_line.startsWith( KRA_LDIF_EXTDATA_REQUEST_NOTES)) {
                    // write out the missing 'extdata-requestnotes' line
                    if( mRewrapFlag && mAppendIdOffsetFlag ) {
                        data = LEFT_BRACE
                             + mDateOfModify
                             + RIGHT_BRACE
                             + COLON + SPACE
                             + KRA_LDIF_REWRAP_MESSAGE
                             + mPublicKeySize
                             + KRA_LDIF_RSA_MESSAGE
                             + mSourcePKISecurityDatabasePwdfileMessage
                             + SPACE
                             + PLUS + SPACE
                             + KRA_LDIF_APPENDED_ID_OFFSET_MESSAGE
                             + SPACE
                             + TIC
                             + mAppendIdOffset.toString()
                             + TIC
                             + mKraNamingContextMessage
                             + mProcessRequestsAndKeyRecordsOnlyMessage;

                        // Unformat the data
                        unformatted_data = stripEOL( data );

                        // Format the unformatted_data
                        // to match the desired LDIF format
                        output = KRA_LDIF_EXTDATA_REQUEST_NOTES
                               + SPACE
                               + format_ldif_data(
                                   EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                   unformatted_data );
                    } else if( mRewrapFlag && mRemoveIdOffsetFlag ) {
                        data = LEFT_BRACE
                             + mDateOfModify
                             + RIGHT_BRACE
                             + COLON + SPACE
                             + KRA_LDIF_REWRAP_MESSAGE
                             + mPublicKeySize
                             + KRA_LDIF_RSA_MESSAGE
                             + mSourcePKISecurityDatabasePwdfileMessage
                             + SPACE
                             + PLUS + SPACE
                             + KRA_LDIF_REMOVED_ID_OFFSET_MESSAGE
                             + SPACE
                             + TIC
                             + mRemoveIdOffset.toString()
                             + TIC
                             + mKraNamingContextMessage
                             + mProcessRequestsAndKeyRecordsOnlyMessage;

                        // Unformat the data
                        unformatted_data = stripEOL( data );

                        // Format the unformatted_data
                        // to match the desired LDIF format
                        output = KRA_LDIF_EXTDATA_REQUEST_NOTES
                               + SPACE
                               + format_ldif_data(
                                   EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                   unformatted_data );
                    } else if( mRewrapFlag ) {
                        data = LEFT_BRACE
                             + mDateOfModify
                             + RIGHT_BRACE
                             + COLON + SPACE
                             + KRA_LDIF_REWRAP_MESSAGE
                             + mPublicKeySize
                             + KRA_LDIF_RSA_MESSAGE
                             + mSourcePKISecurityDatabasePwdfileMessage
                             + mKraNamingContextMessage
                             + mProcessRequestsAndKeyRecordsOnlyMessage;

                        // Unformat the data
                        unformatted_data = stripEOL( data );

                        // Format the unformatted_data
                        // to match the desired LDIF format
                        output = KRA_LDIF_EXTDATA_REQUEST_NOTES
                               + SPACE
                               + format_ldif_data(
                                   EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                   unformatted_data );
                    } else if( mAppendIdOffsetFlag ) {
                        data = LEFT_BRACE
                             + mDateOfModify
                             + RIGHT_BRACE
                             + COLON + SPACE
                             + KRA_LDIF_APPENDED_ID_OFFSET_MESSAGE
                             + SPACE
                             + TIC
                             + mAppendIdOffset.toString()
                             + TIC
                             + mKraNamingContextMessage
                             + mProcessRequestsAndKeyRecordsOnlyMessage;

                        // Unformat the data
                        unformatted_data = stripEOL( data );

                        // Format the unformatted_data
                        // to match the desired LDIF format
                        output = KRA_LDIF_EXTDATA_REQUEST_NOTES
                               + SPACE
                               + format_ldif_data(
                                   EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                   unformatted_data );
                    } else if( mRemoveIdOffsetFlag ) {
                        data = LEFT_BRACE
                             + mDateOfModify
                             + RIGHT_BRACE
                             + COLON + SPACE
                             + KRA_LDIF_REMOVED_ID_OFFSET_MESSAGE
                             + SPACE
                             + TIC
                             + mRemoveIdOffset.toString()
                             + TIC
                             + mKraNamingContextMessage
                             + mProcessRequestsAndKeyRecordsOnlyMessage;

                        // Unformat the data
                        unformatted_data = stripEOL( data );

                        // Format the unformatted_data
                        // to match the desired LDIF format
                        output = KRA_LDIF_EXTDATA_REQUEST_NOTES
                               + SPACE
                               + format_ldif_data(
                                   EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                   unformatted_data );
                    }

                    // log this information
                    log( "Created:"
                       + NEWLINE
                       + TIC
                       + output
                       + TIC
                       + NEWLINE, false );

                    // Write out this revised line
                    // and flush the buffer
                    writer.write( output + NEWLINE );
                    writer.flush();
                    System.out.print( "." );
                }
            }
        }
    }

    /**
     * Helper method which composes the output line for
     * KRA_LDIF_EXTDATA_SERIAL_NUMBER.
     * <P>
     *
     * @param record_type the string representation of the input record type
     * @param line the string representation of the input line
     * @return the composed output line
     */
    private static String output_extdata_serial_number(String record_type,
                                                        String line) {
        String output = null;

        if (record_type.equals(KRA_LDIF_RECOVERY)) {
            if (kratoolCfg.get(KRATOOL_CFG_RECOVERY_EXTDATA_SERIAL_NUMBER)) {
                output = compose_numeric_line(KRA_LDIF_EXTDATA_SERIAL_NUMBER,
                                               SPACE,
                                               line,
                                               false);
            } else {
                output = line;
            }
        } else {
            log("ERROR:  Mismatched record field='"
                    + KRA_LDIF_EXTDATA_SERIAL_NUMBER
                    + "' for record type='"
                    + record_type
                    + "'!"
                    + NEWLINE, true);
        }

        return output;
    }

    /**
     * Helper method which composes the output line for
     * KRA_LDIF_PRIVATE_KEY_DATA.
     * <P>
     *
     * @param record_type the string representation of the input record type
     * @param line the string representation of the input line
     * @return the composed output line
     */
    private static byte[] extract_private_key_data(String line, String[] saved_line_holder) {
        try {
            StringBuilder data = new StringBuilder();

            // Extract the data from the first line
            data.append(line.substring(
                    KRA_LDIF_PRIVATE_KEY_DATA.length() + 1
                    ).trim());

            // Read continuation lines
            while (ldif_record.hasNext()) {
                line = ldif_record.next();
                if (line.startsWith(SPACE)) {
                    data.append(line.trim());
                } else {
                    // Save this non-continuation line for later processing
                    saved_line_holder[0] = line;
                    break;
                }
            }

            // Decode base64 to binary
            String base64Data = data.toString();
            log("DEBUG: privateKeyData base64 length: " + base64Data.length() + NEWLINE, false);
            byte[] decoded = Utils.base64decode(base64Data);
            log("DEBUG: privateKeyData decoded length: " + decoded.length + NEWLINE, false);
            return decoded;
        } catch (Exception e) {
            log("ERROR: Failed to extract privateKeyData: " + e.getMessage() + NEWLINE, true);
            return null;
        }
    }

    /**
     * cross-scheme: Helper method to extract publicKeyData from LDIF field.
     * <P>
     *
     * @param line the string representation of the publicKeyData line
     * @param saved_line_holder array to return the non-continuation line (if any)
     * @return the decoded binary publicKeyData
     */
    private static byte[] extract_public_key_data(String line, String[] saved_line_holder) {
        try {
            StringBuilder data = new StringBuilder();

            // Extract the data from the first line
            data.append(line.substring(
                    KRA_LDIF_PUBLIC_KEY_DATA.length() + 1
                    ).trim());

            // Read continuation lines
            while (ldif_record.hasNext()) {
                line = ldif_record.next();
                if (line.startsWith(SPACE)) {
                    data.append(line.trim());
                } else {
                    // Save this non-continuation line for later processing
                    saved_line_holder[0] = line;
                    break;
                }
            }

            // Decode base64 to binary
            return Utils.base64decode(data.toString());
        } catch (Exception e) {
            log("ERROR: Failed to extract publicKeyData: " + e.getMessage() + NEWLINE, true);
            return null;
        }
    }

    /**
     * cross-scheme: Helper method which composes the output line for rewrapped private key data.
     * This method is called when all required data (privateKeyData, publicKeyData, and IV if needed) have been extracted.
     * <P>
     *
     * @param record_type the string representation of the input record type
     * @param privateKeyData the extracted private key data bytes
     * @param publicKeyData the extracted public key data bytes
     * @param ivData the IV extracted from metaInfo (for AES/CBC, null otherwise)
     * @return the composed output line with rewrapped private key
     */
    private static String output_private_public_key_data(String record_type,
                                                          byte[] privateKeyData,
                                                          byte[] publicKeyData,
                                                          byte[] ivData) {
        byte[] target_wrappedKeyData = null;
        String revised_data = null;
        String unformatted_data = null;
        String formatted_data = null;
        String output = null;

        try {
            // cross-scheme: rewrap the source wrapped private key data
            target_wrappedKeyData = rewrap_wrapped_key_data(
                                        privateKeyData,
                                        publicKeyData,
                                        ivData);

            // Encode the BINARY BASE 64 byte[] object
            // into an ASCII BASE 64 certificate
            // enclosed in a String() object
            revised_data = Utils.base64encode(target_wrappedKeyData, true);

            // Unformat the ASCII BASE 64 certificate for the log file
            unformatted_data = stripEOL(revised_data);

            // Format the ASCII BASE 64 certificate to match the desired LDIF format
            formatted_data = format_ldif_data(
                    PRIVATE_KEY_DATA_FIRST_LINE_DATA_LENGTH,
                    unformatted_data);

            // construct a revised 'privateKeyData' line
            output = KRA_LDIF_PRIVATE_KEY_DATA
                    + SPACE
                    + formatted_data;

            // log this information
            log("Rewrapped privateKeyData for " + record_type + NEWLINE, false);

            // Now add the publicKeyData (unchanged from source)
            // Note: We output both lines together with embedded newline
            revised_data = Utils.base64encode(publicKeyData, true);
            unformatted_data = stripEOL(revised_data);
            formatted_data = format_ldif_data(
                    PRIVATE_KEY_DATA_FIRST_LINE_DATA_LENGTH,  // Same length as privateKeyData
                    unformatted_data);

            output += NEWLINE
                    + KRA_LDIF_PUBLIC_KEY_DATA
                    + SPACE
                    + formatted_data;

            log("Added publicKeyData for " + record_type + NEWLINE, false);

        } catch (Exception e) {
            log("ERROR: Failed to rewrap private key data: " + e.getMessage() + NEWLINE, true);
            return null;
        }

        return output;
    }

    /**
     * This method performs the actual parsing of the 'source' LDIF file
     * line-by-line, calling the appropriate "output_XXX()" methods to write
     * to the 'target' LDIF file.
     * <P>
     *
     * @param record_type the string representation of the input record type
     * @param line the string representation of the input line
     * @return the composed output line
     */
    private static String output_private_key_data(String record_type,
                                                   String line) {
        byte source_wrappedKeyData[] = null;
        byte target_wrappedKeyData[] = null;
        StringBuilder data = new StringBuilder();
        String revised_data = null;
        String unformatted_data = null;
        String formatted_data = null;
        String output = null;

        try {
            if (record_type.equals(KRA_LDIF_CA_KEY_RECORD)) {
                if (kratoolCfg.get(KRATOOL_CFG_CA_KEY_RECORD_PRIVATE_KEY_DATA)) {
                    // Since "-source_pki_security_database_path",
                    // "-source_storage_token_name",
                    // "-source_storage_certificate_nickname", and
                    // "-target_storage_certificate_file" are OPTIONAL
                    // parameters, ONLY process this field if all of
                    // these options have been selected
                    if (mRewrapFlag) {
                        // extract the data
                        data.append(line.substring(
                                KRA_LDIF_PRIVATE_KEY_DATA.length() + 1
                                ).trim());

                        while ((line = ldif_record.next()) != null) {
                            if (line.startsWith(SPACE)) {
                                data.append(line.trim());
                            } else {
                                break;
                            }
                        }

                        // Decode the ASCII BASE 64 certificate
                        // enclosed in the String() object
                        // into a BINARY BASE 64 byte[] object
                        source_wrappedKeyData =
                                Utils.base64decode(data.toString());

                        // rewrap the source wrapped private key data
                        // pass null values to satisfy change to rewrap_wrapped_key_data() for cross-scheme
                        target_wrappedKeyData = rewrap_wrapped_key_data(
                                                    source_wrappedKeyData);

                        // Encode the BINARY BASE 64 byte[] object
                        // into an ASCII BASE 64 certificate
                        // enclosed in a String() object
                        revised_data = Utils.base64encode(
                                           target_wrappedKeyData, true);

                        // Unformat the ASCII BASE 64 certificate
                        // for the log file
                        unformatted_data = stripEOL(revised_data);

                        // Format the ASCII BASE 64 certificate
                        // to match the desired LDIF format
                        formatted_data = format_ldif_data(
                                PRIVATE_KEY_DATA_FIRST_LINE_DATA_LENGTH,
                                unformatted_data);

                        // construct a revised 'privateKeyData' line
                        output = KRA_LDIF_PRIVATE_KEY_DATA
                                + SPACE
                                + formatted_data
                                + NEWLINE
                                + line;

                        // log this information
                        log("Changed 'privateKeyData' from:"
                                + NEWLINE
                                + TIC
                                + data.toString()
                                + TIC
                                + NEWLINE
                                + " to:"
                                + NEWLINE
                                + TIC
                                + unformatted_data
                                + TIC
                                + NEWLINE, false);
                    } else {
                        output = line;
                    }
                } else {
                    output = line;
                }
            } else if (record_type.equals(KRA_LDIF_TPS_KEY_RECORD)) {
                if (kratoolCfg.get(KRATOOL_CFG_TPS_KEY_RECORD_PRIVATE_KEY_DATA)) {
                    // Since "-source_pki_security_database_path",
                    // "-source_storage_token_name",
                    // "-source_storage_certificate_nickname", and
                    // "-target_storage_certificate_file" are OPTIONAL
                    // parameters, ONLY process this field if all of
                    // these options have been selected
                    if (mRewrapFlag) {
                        // extract the data
                        data.append(line.substring(
                                   KRA_LDIF_PRIVATE_KEY_DATA.length() + 1
                                ).trim());

                        while ((line = ldif_record.next()) != null) {
                            if (line.startsWith(SPACE)) {
                                data.append(line.trim());
                            } else {
                                break;
                            }
                        }

                        // Decode the ASCII BASE 64 certificate
                        // enclosed in the String() object
                        // into a BINARY BASE 64 byte[] object
                        source_wrappedKeyData =
                                Utils.base64decode(data.toString());

                        // rewrap the source wrapped private key data
                        // pass null values to satisfy change to rewrap_wrapped_key_data() for cross-scheme
                        target_wrappedKeyData = rewrap_wrapped_key_data(
                                                    source_wrappedKeyData);

                        // Encode the BINARY BASE 64 byte[] object
                        // into an ASCII BASE 64 certificate
                        // enclosed in a String() object
                        revised_data = Utils.base64encode(
                                           target_wrappedKeyData, true);

                        // Unformat the ASCII BASE 64 certificate
                        // for the log file
                        unformatted_data = stripEOL(revised_data);

                        // Format the ASCII BASE 64 certificate
                        // to match the desired LDIF format
                        formatted_data = format_ldif_data(
                                PRIVATE_KEY_DATA_FIRST_LINE_DATA_LENGTH,
                                unformatted_data);

                        // construct a revised 'privateKeyData' line
                        output = KRA_LDIF_PRIVATE_KEY_DATA
                                + SPACE
                                + formatted_data
                                + NEWLINE
                                + line;

                        // log this information
                        log("Changed 'privateKeyData' from:"
                                + NEWLINE
                                + TIC
                                + data.toString()
                                + TIC
                                + NEWLINE
                                + " to:"
                                + NEWLINE
                                + TIC
                                + unformatted_data
                                + TIC
                                + NEWLINE, false);
                    } else {
                        output = line;
                    }
                } else {
                    output = line;
                }
            } else {
                log("ERROR:  Mismatched record field='"
                        + KRA_LDIF_PRIVATE_KEY_DATA
                        + "' for record type='"
                        + record_type
                        + "'!"
                        + NEWLINE, true);
            }
        } catch (Exception exRewrap) {
            log("ERROR:  Unable to rewrap BINARY BASE 64 data. "
                    + "Exception: '"
                    + exRewrap.toString()
                    + "'"
                    + NEWLINE, true);
        }

        return output;
    }

    /**
     * Helper method which composes the output line for KRA_LDIF_REQUEST_ID.
     * <P>
     *
     * @param record_type the string representation of the input record type
     * @param line the string representation of the input line
     * @return the composed output line
     */
    private static String output_request_id(String record_type,
                                             String line) {
        String output = null;

        if (record_type.equals(KRA_LDIF_ENROLLMENT)) {
            if (kratoolCfg.get(KRATOOL_CFG_ENROLLMENT_REQUEST_ID)) {
                output = compose_numeric_line(KRA_LDIF_REQUEST_ID,
                                               SPACE,
                                               line,
                                               true);
            } else {
                output = line;
            }
        } else if (record_type.equals(KRA_LDIF_RECOVERY)) {
            if (kratoolCfg.get(KRATOOL_CFG_RECOVERY_REQUEST_ID)) {
                output = compose_numeric_line(KRA_LDIF_REQUEST_ID,
                                               SPACE,
                                               line,
                                               true);
            } else {
                output = line;
            }
        } else if (record_type.equals(KRA_LDIF_KEYGEN)) {
            if (kratoolCfg.get(KRATOOL_CFG_KEYGEN_REQUEST_ID)) {
                output = compose_numeric_line(KRA_LDIF_REQUEST_ID,
                                               SPACE,
                                               line,
                                               true);
            } else {
                output = line;
            }
        } else if ( record_type.equals( KRA_LDIF_KEYRECOVERY ) ) {
            if ( kratoolCfg.get( KRATOOL_CFG_KEYRECOVERY_REQUEST_ID ) ) {
                    output = compose_numeric_line(KRA_LDIF_REQUEST_ID,
                                                  SPACE,
                                                  line,
                                                  true);
            } else {
                    output = line;
            }
        } else {
            log("ERROR:  Mismatched record field='"
                    + KRA_LDIF_REQUEST_ID
                    + "' for record type='"
                    + record_type
                    + "'!"
                    + NEWLINE, true);
        }

        return output;
    }

    /**
     * Helper method which composes the output line for KRA_LDIF_SERIAL_NO.
     * <P>
     *
     * @param record_type the string representation of the input record type
     * @param line the string representation of the input line
     * @return the composed output line
     */
    private static String output_serial_no(String record_type,
                                            String line) {
        String output = null;

        if (record_type.equals(KRA_LDIF_CA_KEY_RECORD)) {
            if (kratoolCfg.get(KRATOOL_CFG_CA_KEY_RECORD_SERIAL_NO)) {
                output = compose_numeric_line(KRA_LDIF_SERIAL_NO,
                                               SPACE,
                                               line,
                                               true);
            } else {
                output = line;
            }
        } else if (record_type.equals(KRA_LDIF_TPS_KEY_RECORD)) {
            if (kratoolCfg.get(KRATOOL_CFG_TPS_KEY_RECORD_SERIAL_NO)) {
                output = compose_numeric_line(KRA_LDIF_SERIAL_NO,
                                               SPACE,
                                               line,
                                               true);
            } else {
                output = line;
            }
        } else if (record_type.equals(KRA_LDIF_RECORD)) {
            // Non-Request / Non-Key Record:
            //     Pass through the original
            //     'serialno' line UNCHANGED
            //     so that it is ALWAYS written
            output = line;
        } else {
            log("ERROR:  Mismatched record field='"
                    + KRA_LDIF_SERIAL_NO
                    + "' for record type='"
                    + record_type
                    + "'!"
                    + NEWLINE, true);
        }

        return output;
    }

    /**
     * Helper method which composes the output line for
     * KRA_LDIF_EXTDATA_AUTH_TOKEN_USER.
     * <P>
     *
     * @param record_type the string representation of the input record type
     * @param line the string representation of the input line
     * @return the composed output line
     */
    private static String output_extdata_auth_token_user(String record_type,
                                                          String line) {
        String output = null;

        try {
            if (record_type.equals(KRA_LDIF_ENROLLMENT)) {
                // Since "-source_kra_naming_context", and
                // "-target_kra_naming_context" are OPTIONAL
                // parameters, ONLY process this field if both of
                // these options have been selected
                if (mKraNamingContextsFlag) {
                    output = line.replace(mSourceKraNamingContext,
                                           mTargetKraNamingContext);
                } else {
                    output = line;
                }
            } else {
                log("ERROR:  Mismatched record field='"
                        + KRA_LDIF_EXTDATA_AUTH_TOKEN_USER
                        + "' for record type='"
                        + record_type
                        + "'!"
                        + NEWLINE, true);
            }
        } catch (NullPointerException exNullPointerException) {
            log("ERROR:  Unable to replace source KRA naming context '"
                    + mSourceKraNamingContext
                    + "' with target KRA naming context '"
                    + mTargetKraNamingContext
                    + "' NullPointerException: '"
                    + exNullPointerException.toString()
                    + "'"
                    + NEWLINE, true);
        }

        return output;
    }

    /**
     * Helper method which composes the output line for
     * KRA_LDIF_EXTDATA_AUTH_TOKEN_USER_DN.
     * <P>
     *
     * @param record_type the string representation of the input record type
     * @param line the string representation of the input line
     * @return the composed output line
     */
    private static String output_extdata_auth_token_user_dn(String record_type,
                                                             String line) {
        String output = null;

        try {
            if (record_type.equals(KRA_LDIF_ENROLLMENT)) {
                // Since "-source_kra_naming_context", and
                // "-target_kra_naming_context" are OPTIONAL
                // parameters, ONLY process this field if both of
                // these options have been selected
                if (mKraNamingContextsFlag) {
                    output = line.replace(mSourceKraNamingContext,
                                           mTargetKraNamingContext);
                } else {
                    output = line;
                }
            } else {
                log("ERROR:  Mismatched record field='"
                        + KRA_LDIF_EXTDATA_AUTH_TOKEN_USER_DN
                        + "' for record type='"
                        + record_type
                        + "'!"
                        + NEWLINE, true);
            }
        } catch (NullPointerException exNullPointerException) {
            log("ERROR:  Unable to replace source KRA naming context '"
                    + mSourceKraNamingContext
                    + "' with target KRA naming context '"
                    + mTargetKraNamingContext
                    + "' NullPointerException: '"
                    + exNullPointerException.toString()
                    + "'"
                    + NEWLINE, true);
        }

        return output;
    }

    /**
     * Baseline code: only used when -use_cross_scheme is not used
     *
     * This method performs the actual parsing of the "source" LDIF file
     * and produces the "target" LDIF file.
     * <P>
     *
     * @return true if the "target" LDIF file is successfully created
     */
    private static boolean convert_source_ldif_to_target_ldif() {
        boolean success = false;
        BufferedReader reader = null;
        PrintWriter writer = null;
        String input = null;
        String line = null;
        String previous_line = null;
        String output = null;
        String data = null;
        String record_type = null;

        if (mRewrapFlag) {
            success = obtain_RSA_rewrapping_keys();
            if (!success) {
                return FAILURE;
            }
        }

        // Create a vector for LDIF input
        record = new Vector<>(INITIAL_LDIF_RECORD_CAPACITY);

        // Process each line in the source LDIF file
        // and store it in the target LDIF file
        try {
            // Open source LDIF file for reading
            reader = new BufferedReader(
                         new FileReader(mSourceLdifFilename));

            // Open target LDIF file for writing
            writer = new PrintWriter(
                         new BufferedWriter(
                                 new FileWriter(mTargetLdifFilename)));

            System.out.print("PROCESSING: ");
            while ((input = reader.readLine()) != null) {
                // Read in a record from the source LDIF file and
                // add this line of input into the record vector
                success = record.add(input);
                if (!success) {
                    return FAILURE;
                }

                // Check for the end of an LDIF record
                if (!input.equals("")) {
                    // Check to see if input line identifies the record type
                    if (input.startsWith(KRA_LDIF_REQUEST_TYPE)) {
                        // set the record type:
                        //
                        //     * KRA_LDIF_ENROLLMENT
                        //     * KRA_LDIF_KEYGEN
                        //     * KRA_LDIF_RECOVERY
                        //
                        record_type = input.substring(
                                          KRA_LDIF_REQUEST_TYPE.length() + 1
                                      ).trim();
                        if (!record_type.equals(KRA_LDIF_ENROLLMENT) &&
                                !record_type.equals(KRA_LDIF_KEYGEN) &&
                                !record_type.equals(KRA_LDIF_RECOVERY) &&
                                !record_type.equals( KRA_LDIF_KEYRECOVERY)) {
                            log("ERROR:  Unknown LDIF record type='"
                                    + record_type
                                    + "'!"
                                    + NEWLINE, true);
                            return FAILURE;
                        }
                    } else if (input.startsWith(KRA_LDIF_ARCHIVED_BY)) {
                        // extract the data
                        data = input.substring(
                                   KRA_LDIF_ARCHIVED_BY.length() + 1
                                ).trim();

                        // set the record type:
                        //
                        //     * KRA_LDIF_CA_KEY_RECORD
                        //     * KRA_LDIF_TPS_KEY_RECORD
                        //
                        if (data.startsWith(KRA_LDIF_TPS_KEY_RECORD)) {
                            record_type = KRA_LDIF_TPS_KEY_RECORD;
                        } else if (data.startsWith(KRA_LDIF_CA_KEY_RECORD)) {
                            record_type = KRA_LDIF_CA_KEY_RECORD;
                        } else {
                            log("ERROR:  Unable to determine LDIF record type "
                                    + "from data='"
                                    + data
                                    + "'!"
                                    + NEWLINE, true);
                            return FAILURE;
                        }
                    }

                    // continue adding input lines into this record
                    continue;
                }

                // If record type is unset, then this record is neither
                // an LDIF request record nor an LDIF key record; check
                // to see if it needs to be written out to the target
                // LDIF file or thrown away.
                if ((record_type == null) &&
                        mProcessRequestsAndKeyRecordsOnlyFlag) {
                    // Mark each removed record with an 'x'
                    System.out.print("x");

                    // log this information
                    log("INFO:  Throwing away an LDIF record which is "
                            + "neither a Request nor a Key Record!"
                            + NEWLINE, false);

                    // clear this LDIF record from the record vector
                    record.clear();

                    // NOTE:  there is no need to reset the record type

                    // begin adding input lines into a new record
                    continue;
                } else if (record_type == null) {
                    // Set record type to specify a "generic" LDIF record
                    record_type = KRA_LDIF_RECORD;
                }

                ldif_record = record.iterator();

                // Process each line of the record:
                //   * If LDIF Record Type for this line is 'valid'
                //     * If KRATOOL Configuration File Parameter is 'true'
                //       * Process this data
                //     * Else If KRATOOL Configuration File Parameter is 'false'
                //       * Pass through this data unchanged
                //   * Else If LDIF Record Type for this line is 'invalid'
                //     * Log error and leave method returning 'false'
                while (ldif_record.hasNext()) {

                    line = ldif_record.next();

                    if (line.startsWith(KRA_LDIF_CN)) {
                        output = output_cn(record_type, line);
                        if (output == null) {
                            return FAILURE;
                        }
                    } else if (line.startsWith(KRA_LDIF_DATE_OF_MODIFY)) {
                        output = output_date_of_modify(record_type, line);
                        if (output == null) {
                            return FAILURE;
                        }
                    } else if (line.startsWith(KRA_LDIF_DN)) {
                        output = output_dn(record_type, line);
                        if (output == null) {
                            return FAILURE;
                        }
                    } else if (line.startsWith(KRA_LDIF_EXTDATA_KEY_RECORD)) {
                        output = output_extdata_key_record(record_type,
                                                            line);
                        if (output == null) {
                            return FAILURE;
                        }
                    } else if (line.startsWith(KRA_LDIF_EXTDATA_REQUEST_ID)) {
                        output = output_extdata_request_id(record_type,
                                                            line);
                        if (output == null) {
                            return FAILURE;
                        }
                    } else if (line.startsWith(KRA_LDIF_EXTDATA_REQUEST_NOTES)) {
                        output = output_extdata_request_notes(record_type,
                                                               line);
                        if (output == null) {
                            return FAILURE;
                        }
                    } else if (line.startsWith(KRA_LDIF_EXTDATA_REQUEST_TYPE)) {
                        // if one is not already present,
                        // compose and write out the missing
                        // 'extdata_requestnotes' line
                        if (previous_line != null) {
                            create_extdata_request_notes(record_type,
                                    previous_line,
                                    writer);
                        } else {
                            return FAILURE;
                        }

                        // ALWAYS pass through the original
                        // 'extdata-requesttype' line UNCHANGED
                        // so that it is ALWAYS written
                        output = line;
                    } else if (line.startsWith(KRA_LDIF_EXTDATA_SERIAL_NUMBER)) {
                        output = output_extdata_serial_number(record_type,
                                                               line);
                        if (output == null) {
                            return FAILURE;
                        }
                    } else if (line.startsWith(KRA_LDIF_PRIVATE_KEY_DATA)) {
                        output = output_private_key_data(record_type,
                                                          line);
                        if (output == null) {
                            return FAILURE;
                        }
                    } else if (line.startsWith(KRA_LDIF_REQUEST_ID)) {
                        output = output_request_id(record_type, line);
                        if (output == null) {
                            return FAILURE;
                        }
                    } else if (line.startsWith(KRA_LDIF_SERIAL_NO)) {
                        output = output_serial_no(record_type, line);
                        if (output == null) {
                            return FAILURE;
                        }
                    } else if (previous_line != null &&
                               previous_line.startsWith(
                                       KRA_LDIF_EXTDATA_AUTH_TOKEN_USER)) {
                        output = output_extdata_auth_token_user(record_type,
                                                                 line);
                        if (output == null) {
                            return FAILURE;
                        }
                    } else if (previous_line != null &&
                               previous_line.startsWith(
                                       KRA_LDIF_EXTDATA_AUTH_TOKEN_USER_DN)) {
                        output = output_extdata_auth_token_user_dn(record_type,
                                                                    line);
                        if (output == null) {
                            return FAILURE;
                        }
                    } else {
                        // Pass through line unchanged
                        output = line;
                    }

                    // Always save a copy of this line
                    previous_line = output;

                    // Always write out the output line and flush the buffer
                    writer.write(output + NEWLINE);
                    writer.flush();
                    System.out.print(".");
                }
                // Mark the end of the LDIF record
                System.out.print("!");

                // clear this LDIF record from the record vector
                record.clear();
            }
            System.out.println(" FINISHED." + NEWLINE);
        } catch (IOException exIO) {
            log("ERROR:  line='"
                    + line
                    + "' OR output='"
                    + output
                    + "' IOException: '"
                    + exIO.toString()
                    + "'"
                    + NEWLINE, true);
            return FAILURE;
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            if (writer != null) {
                writer.close();
            }
        }

        return SUCCESS;
    }

    /**
     * cross-scheme: Get the output filename for current file number (for split mode).
     */
    private static String getOutputFilename() {
        if (mSplitTargetLdifPerRecords > 0) {
            // Split mode: insert file number before extension
            String baseName = mTargetLdifFilename;
            int dotIndex = baseName.lastIndexOf('.');
            if (dotIndex > 0) {
                return baseName.substring(0, dotIndex) + "-" + mCurrentFileNumber + baseName.substring(dotIndex);
            } else {
                return baseName + "-" + mCurrentFileNumber;
            }
        } else {
            // Normal mode: use target filename as-is
            return mTargetLdifFilename;
        }
    }

    /**
     * cross-scheme: Roll over to a new output file (split mode).
     * Closes current writer and opens a new one with incremented file number.
     * NOTE: Caller should only call this when mRecordsInCurrentFile reaches the limit.
     */
    private static BufferedWriter rolloverToNextFile(BufferedWriter currentWriter) throws IOException {
        // Close current file
        currentWriter.close();
        log("Completed output file: " + getOutputFilename() + " (" + mRecordsInCurrentFile + " records)" + NEWLINE, true);

        // Move to next file
        mCurrentFileNumber++;
        mRecordsInCurrentFile = 0;

        // Open new file
        BufferedWriter newWriter = new BufferedWriter(new FileWriter(getOutputFilename()));
        log("Created new output file: " + getOutputFilename() + NEWLINE, true);

        // Write LDIF version header to new file (unless processing partial LDIF for concatenation)
        if (!mProcessRequestsAndKeyRecordsOnlyFlag) {
            newWriter.write("version: 1" + NEWLINE);
            newWriter.write(NEWLINE);
        }

        return newWriter;
    }

    /**
     * cross-scheme: Entry-based LDIF processing for cross-scheme algorithm migration.
     * This method processes complete LDIF entries at once, allowing for interdependent
     * field transformations when migrating between different wrapping algorithms.
     * <P>
     *
     * @return true if the "target" LDIF file is successfully created
     */
    private static boolean use_cross_scheme_convert_source_ldif_to_target_ldif() {
        boolean success = false;
        BufferedReader reader = null;
        BufferedWriter writer = null;

        // Initialize crypto components for rewrapping
        if (mRewrapFlag) {
            success = obtain_RSA_rewrapping_keys();
            if (!success) {
                return FAILURE;
            }

            // cross-scheme: Initialize cached payload algorithm objects and IV requirements (performance)
            // This avoids repeated algorithm lookups for every key record
            try {
                if (mSourcePayloadWrapAlgName != null) {
                    mSourcePayloadWrapAlg = getPayloadWrapAlgorithm(mSourcePayloadWrapAlgName);
                    mSourcePayloadNeedsIV = needsIV(mSourcePayloadWrapAlg);
                    log("Source payload algorithm: " + mSourcePayloadWrapAlg + " (needsIV=" + mSourcePayloadNeedsIV + ")" + NEWLINE, false);
                }
                if (mTargetPayloadWrapAlgName != null) {
                    mTargetPayloadWrapAlg = getPayloadWrapAlgorithm(mTargetPayloadWrapAlgName);
                    mTargetPayloadNeedsIV = needsIV(mTargetPayloadWrapAlg);
                    log("Target payload algorithm: " + mTargetPayloadWrapAlg + " (needsIV=" + mTargetPayloadNeedsIV + ")" + NEWLINE, false);
                }
            } catch (Exception e) {
                log("Failed to initialize payload wrap algorithms: " + e.getMessage() + NEWLINE, true);
                return FAILURE;
            }
        }

        // Process LDIF file entry by entry
        try {
            reader = new BufferedReader(new FileReader(mSourceLdifFilename));
            writer = new BufferedWriter(new FileWriter(getOutputFilename()));

            if (mSplitTargetLdifPerRecords > 0) {
                log("Split mode enabled: creating new file every " + mSplitTargetLdifPerRecords + " records" + NEWLINE, true);
            }

            String line;
            List<String> entryLines = new ArrayList<>();
            boolean headerWritten = false;

            System.out.print("PROCESSING: ");

            while ((line = reader.readLine()) != null) {
                // Handle LDIF version header (first non-blank line)
                // Skip version header when -process_requests_and_key_records_only is used
                // because output will be concatenated with target KRA's db2ldif
                if (!headerWritten && line.startsWith("version:")) {
                    if (!mProcessRequestsAndKeyRecordsOnlyFlag) {
                        writer.write(line + NEWLINE);
                        writer.write(NEWLINE);  // Blank line after version header
                    }
                    headerWritten = true;
                    continue;
                }

                if (line.isEmpty()) {
                    // Blank line signals end of entry
                    if (!entryLines.isEmpty()) {
                        // Track whether entry was written (vs filtered out)
                        int entriesBeforeProcessing = mProcessedEntries;
                        success = processEntry(entryLines, writer);
                        if (!success) {
                            return FAILURE;
                        }
                        entryLines.clear();

                        // Write blank line only if an entry was actually written (not filtered)
                        if (mProcessedEntries > entriesBeforeProcessing) {
                            writer.write(NEWLINE);

                            // Split mode: Track records in current file and rollover when limit reached.
                            // PERFORMANCE NOTE: We only check for rollover when split mode is enabled
                            // and only when we've actually written a record. This avoids function call
                            // overhead for the common case (split mode disabled) and for filtered records.
                            // Using equality check (==) instead of range check (>=) is slightly faster
                            // and sufficient since we increment by 1 each time.
                            if (mSplitTargetLdifPerRecords > 0) {
                                mRecordsInCurrentFile++;
                                if (mRecordsInCurrentFile == mSplitTargetLdifPerRecords) {
                                    writer = rolloverToNextFile(writer);
                                }
                            }
                        }
                    }
                } else {
                    // Accumulate lines for this entry
                    entryLines.add(line);
                }
            }

            // Process last entry if file doesn't end with blank line
            if (!entryLines.isEmpty()) {
                success = processEntry(entryLines, writer);
                if (!success) {
                    return FAILURE;
                }
            }

            System.out.println(" FINISHED." + NEWLINE);

        } catch (IOException e) {
            log("ERROR: IOException processing LDIF file: " + e.getMessage() + NEWLINE, true);
            return FAILURE;
        } catch (Exception e) {
            log("ERROR: Exception processing LDIF file: " + e.getMessage() + NEWLINE, true);
            if (mVerboseFlag) {
                e.printStackTrace();
            }
            return FAILURE;
        } finally {
            // Close resources
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    log("Error closing reader: " + e.getMessage(), true);
                    if (mVerboseFlag) {
                        e.printStackTrace();
                    }
                }
            }
            if (writer != null) {
                try {
                    writer.close();
                    if (mSplitTargetLdifPerRecords > 0) {
                        log("Completed final output file: " + getOutputFilename() + " (" + mRecordsInCurrentFile + " records)" + NEWLINE, true);
                    }
                } catch (IOException e) {
                    log("Error closing writer: " + e.getMessage(), true);
                    if (mVerboseFlag) {
                        e.printStackTrace();
                    }
                }
            }
        }

        return SUCCESS;
    }

    /**
     * cross-scheme: Process a single LDIF entry (key record).
     * Parses the entry into attributes, applies transformations, and writes to target.
     */
    private static boolean processEntry(List<String> entryLines, BufferedWriter writer)
            throws IOException, Exception {

        // Parse entry into attribute map (preserves order via LinkedHashMap)
        Map<String, List<String>> attributes = new LinkedHashMap<>();
        List<String> entryComments = new ArrayList<>();  // Collect all comment lines before first attribute
        boolean inCommentBlock = true;  // Track if we're still in the leading comment block
        String currentAttr = null;
        StringBuilder currentValue = new StringBuilder();

        for (String line : entryLines) {
            // Collect comment lines that appear before any attributes (leading comment block)
            if (line.startsWith("#")) {
                if (inCommentBlock) {
                    entryComments.add(line);
                }
                // Skip comments in the middle of the record
                continue;
            }

            // Once we see a non-comment line, we're past the leading comment block
            inCommentBlock = false;

            // Check if this is a continuation line (starts with space)
            if (line.startsWith(" ")) {
                if (currentAttr != null) {
                    currentValue.append(line.substring(1)); // Remove leading space
                }
                continue;
            }

            // Save previous attribute if any
            if (currentAttr != null) {
                attributes.computeIfAbsent(currentAttr, k -> new ArrayList<>())
                          .add(currentValue.toString());
            }

            // Parse new attribute (including dn/rdn)
            int colonIndex = line.indexOf(':');
            if (colonIndex > 0) {
                currentAttr = line.substring(0, colonIndex);
                String valueStart = line.substring(colonIndex + 1);
                // Handle "::" for base64 encoded values
                if (valueStart.startsWith(":")) {
                    currentValue = new StringBuilder(valueStart.substring(1).trim());
                } else {
                    currentValue = new StringBuilder(valueStart.trim());
                }
            }
        }

        // Save last attribute
        if (currentAttr != null) {
            attributes.computeIfAbsent(currentAttr, k -> new ArrayList<>())
                      .add(currentValue.toString());
        }

        // Determine record type
        String recordType = determineRecordType(attributes);
        if (recordType == null) {
            log("ERROR: Unable to determine record type for entry" + NEWLINE, true);
            return FAILURE;
        }

        // Check if this record should be filtered out (process_requests_and_key_records_only)
        if (mProcessRequestsAndKeyRecordsOnlyFlag) {
            // Only include enrollment, recovery, keygen, keyrecovery requests, and key records
            boolean isRequest = recordType.equals(KRA_LDIF_ENROLLMENT) ||
                                recordType.equals(KRA_LDIF_RECOVERY) ||
                                recordType.equals(KRA_LDIF_KEYGEN) ||
                                recordType.equals(KRA_LDIF_KEYRECOVERY);
            boolean isKeyRecord = recordType.equals(KRA_LDIF_CA_KEY_RECORD) ||
                                  recordType.equals(KRA_LDIF_TPS_KEY_RECORD);

            if (!isRequest && !isKeyRecord) {
                // Mark each filtered record with an 'x'
                System.out.print("x");
                return SUCCESS;  // Skip this record
            }
        }

        // Apply transformations based on record type
        // In cross-scheme mode, always process key records (rewrapping is the purpose)
        if (recordType.equals(KRA_LDIF_CA_KEY_RECORD) ||
            recordType.equals(KRA_LDIF_TPS_KEY_RECORD)) {
            return processKeyRecord(attributes, recordType, entryComments, writer);
        } else {
            // For request records, update dateOfModify to match legacy behavior
            boolean isRequestRecord = recordType.equals(KRA_LDIF_ENROLLMENT) ||
                                      recordType.equals(KRA_LDIF_RECOVERY) ||
                                      recordType.equals(KRA_LDIF_KEYGEN) ||
                                      recordType.equals(KRA_LDIF_KEYRECOVERY);
            if (isRequestRecord) {
                String currentDate = new java.text.SimpleDateFormat(DATE_OF_MODIFY_PATTERN).format(new java.util.Date());
                attributes.put("dateOfModify", Collections.singletonList(currentDate));
            }

            // Pass through unchanged for non-key records (after applying naming context and ID offset)
            return writeEntryUnchanged(attributes, entryComments, writer);
        }
    }

    /**
     * cross-scheme: Determine the record type from attributes.
     */
    private static String determineRecordType(Map<String, List<String>> attributes) {
        // Check requestType field (for enrollment/recovery/keygen requests)
        List<String> requestType = attributes.get("requestType");
        if (requestType != null && !requestType.isEmpty()) {
            return requestType.get(0).trim();
        }

        // Check archivedBy field for key records
        List<String> archivedBy = attributes.get("archivedBy");
        if (archivedBy != null && !archivedBy.isEmpty()) {
            String data = archivedBy.get(0).trim();
            if (data.startsWith(KRA_LDIF_TPS_KEY_RECORD)) {
                return KRA_LDIF_TPS_KEY_RECORD;
            } else if (data.startsWith(KRA_LDIF_CA_KEY_RECORD)) {
                return KRA_LDIF_CA_KEY_RECORD;
            }
        }

        // Default: generic LDIF record (organizational entries, users, groups, etc.)
        return KRA_LDIF_RECORD;
    }

    /**
     * cross-scheme: Apply ID offset and naming context transformations to attribute value.
     * Handles:
     * - ID offset (append/remove) for cn, dn, rdn, and request record reference fields
     * - KRA naming context replacement
     */
    private static String applyLdifTransformations(String attr, String value) {
        String result = value;

        // Apply ID offset to cn attribute (if -append_id_offset or -remove_id_offset specified)
        if ((mAppendIdOffsetFlag || mRemoveIdOffsetFlag) && attr.equals("cn")) {
            // Skip non-numeric cn values
            if (value.matches("[0-9]++")) {
                try {
                    BigInteger cnValue = new BigInteger(value);
                    if (mAppendIdOffsetFlag) {
                        if (mAppendIdOffset.compareTo(cnValue) > 0) {
                            // Add the offset
                            result = cnValue.add(mAppendIdOffset).toString();
                            if (mVerboseFlag) {
                                log("Applied append ID offset to cn: " + value + " -> " + result + NEWLINE, false);
                            }
                        } else {
                            log("ERROR: cn value '" + value + "' is greater than append_id_offset '"
                                + mAppendIdOffset.toString() + "'!" + NEWLINE, true);
                            System.exit(0);
                        }
                    } else if (mRemoveIdOffsetFlag) {
                        if (mRemoveIdOffset.compareTo(cnValue) <= 0) {
                            // Subtract the offset
                            result = cnValue.subtract(mRemoveIdOffset).toString();
                            if (mVerboseFlag) {
                                log("Applied remove ID offset to cn: " + value + " -> " + result + NEWLINE, false);
                            }
                        } else {
                            log("ERROR: cn value '" + value + "' is less than remove_id_offset '"
                                + mRemoveIdOffset.toString() + "'!" + NEWLINE, true);
                            System.exit(0);
                        }
                    }
                } catch (NumberFormatException e) {
                    log("Skipped non-numeric cn value: " + value + NEWLINE, false);
                }
            }
        }

        // Apply ID offset to embedded cn in dn/rdn (if -append_id_offset or -remove_id_offset specified)
        if ((mAppendIdOffsetFlag || mRemoveIdOffsetFlag) && (attr.equals("dn") || attr.equals("rdn"))) {
            // Look for cn=<number> pattern in dn
            if (result.contains("cn=")) {
                String[] parts = result.split(",");
                StringBuilder newDn = new StringBuilder();
                for (int i = 0; i < parts.length; i++) {
                    String part = parts[i].trim();
                    if (part.startsWith("cn=")) {
                        String cnValue = part.substring(3);
                        if (cnValue.matches("[0-9]++")) {
                            try {
                                BigInteger cn = new BigInteger(cnValue);
                                if (mAppendIdOffsetFlag) {
                                    if (mAppendIdOffset.compareTo(cn) > 0) {
                                        String newCn = cn.add(mAppendIdOffset).toString();
                                        newDn.append("cn=").append(newCn);
                                        if (mVerboseFlag) {
                                        log("Applied append ID offset to " + attr + " cn: " + cnValue + " -> " + newCn + NEWLINE, false);
                                        }
                                    } else {
                                        log("ERROR: " + attr + " cn value '" + cnValue + "' is greater than append_id_offset '"
                                            + mAppendIdOffset.toString() + "'!" + NEWLINE, true);
                                        System.exit(0);
                                    }
                                } else if (mRemoveIdOffsetFlag) {
                                    if (mRemoveIdOffset.compareTo(cn) <= 0) {
                                        String newCn = cn.subtract(mRemoveIdOffset).toString();
                                        newDn.append("cn=").append(newCn);
                                        if (mVerboseFlag) {
                                        log("Applied remove ID offset to " + attr + " cn: " + cnValue + " -> " + newCn + NEWLINE, false);
                                        }
                                    } else {
                                        log("ERROR: " + attr + " cn value '" + cnValue + "' is less than remove_id_offset '"
                                            + mRemoveIdOffset.toString() + "'!" + NEWLINE, true);
                                        System.exit(0);
                                    }
                                }
                            } catch (NumberFormatException e) {
                                newDn.append(part);
                            }
                        } else {
                            newDn.append(part);
                        }
                    } else {
                        newDn.append(part);
                    }
                    if (i < parts.length - 1) {
                        newDn.append(", ");
                    }
                }
                result = newDn.toString();
            }
        }

        // Apply ID offset to serialno and requestId (indexed format: LLVALUE where LL=digit count, VALUE=decimal)
        // Reuses legacy BigIntegerFromDB/BigIntegerToDB functions for correct encoding
        if ((mAppendIdOffsetFlag || mRemoveIdOffsetFlag) &&
            (attr.equals("serialno") || attr.equals("requestId"))) {
            if (result.matches("[0-9]++")) {
                try {
                    // Decode indexed value
                    BigInteger idValue = BigIntegerFromDB(result);

                    // Apply offset
                    BigInteger newIdValue;
                    if (mAppendIdOffsetFlag) {
                        if (mAppendIdOffset.compareTo(idValue) > 0) {
                            newIdValue = idValue.add(mAppendIdOffset);
                        } else {
                            log("ERROR: " + attr + " value " + idValue + " >= append_id_offset " + mAppendIdOffset + NEWLINE, true);
                            System.exit(0);
                            return result; // unreachable
                        }
                    } else { // mRemoveIdOffsetFlag
                        if (mRemoveIdOffset.compareTo(idValue) <= 0) {
                            newIdValue = idValue.subtract(mRemoveIdOffset);
                        } else {
                            log("ERROR: " + attr + " value " + idValue + " < remove_id_offset " + mRemoveIdOffset + NEWLINE, true);
                            System.exit(0);
                            return result; // unreachable
                        }
                    }

                    // Re-encode to indexed format
                    result = BigIntegerToDB(newIdValue);
                    if (mVerboseFlag) {
                    log("Applied ID offset to " + attr + ": " + value + " -> " + result + NEWLINE, false);
                    }

                } catch (Exception e) {
                    log("Skipped non-numeric " + attr + ": " + result + NEWLINE, false);
                }
            }
        }

        // Apply ID offset to extdata reference fields (plain decimal format, not indexed)
        if ((mAppendIdOffsetFlag || mRemoveIdOffsetFlag) &&
            (attr.equals("extdata-keyrecord") || attr.equals("extdata-requestid") ||
             attr.equals("extdata-serialnumber"))) {
            if (result.matches("[0-9]++")) {
                try {
                    BigInteger idValue = new BigInteger(result);

                    // Apply offset
                    if (mAppendIdOffsetFlag) {
                        if (mAppendIdOffset.compareTo(idValue) > 0) {
                            result = idValue.add(mAppendIdOffset).toString();
                            if (mVerboseFlag) {
                            log("Applied ID offset to " + attr + ": " + value + " -> " + result + NEWLINE, false);
                            }
                        } else {
                            log("ERROR: " + attr + " value " + idValue + " >= append_id_offset " + mAppendIdOffset + NEWLINE, true);
                            System.exit(0);
                        }
                    } else { // mRemoveIdOffsetFlag
                        if (mRemoveIdOffset.compareTo(idValue) <= 0) {
                            result = idValue.subtract(mRemoveIdOffset).toString();
                            if (mVerboseFlag) {
                            log("Applied ID offset to " + attr + ": " + value + " -> " + result + NEWLINE, false);
                            }
                        } else {
                            log("ERROR: " + attr + " value " + idValue + " < remove_id_offset " + mRemoveIdOffset + NEWLINE, true);
                            System.exit(0);
                        }
                    }
                } catch (NumberFormatException e) {
                    log("Skipped non-numeric " + attr + ": " + result + NEWLINE, false);
                }
            }
        }

        // Apply naming context replacement (if -target_kra_naming_context specified)
        if (mKraNamingContextsFlag) {
            result = result.replace(mSourceKraNamingContext, mTargetKraNamingContext);
        }

        return result;
    }

    /**
     * cross-scheme: Write LDIF attribute with proper line wrapping.
     * Uses the same line wrapping logic as legacy format_ldif_data():
     * - First line: attribute name + separator + data (limited to keep total line reasonable)
     * - Continuation lines: 76 chars of data with leading space
     * This matches the legacy PRIVATE_KEY_DATA_FIRST_LINE_DATA_LENGTH approach.
     */
    private static void writeWrappedLdifAttribute(String attr, String value, boolean isBase64, BufferedWriter writer) throws IOException {
        String separator = isBase64 ? ":: " : ": ";
        int prefixLength = attr.length() + separator.length();

        // For first line, use a data length that keeps total line around 77-78 chars
        // This matches legacy behavior (e.g., PRIVATE_KEY_DATA_FIRST_LINE_DATA_LENGTH = 60)
        int firstLineDataLength = 77 - prefixLength;

        // If value fits on first line, write it as-is
        if (value.length() <= firstLineDataLength) {
            writer.write(attr + separator + value + NEWLINE);
            return;
        }

        // Write first line with limited data
        writer.write(attr + separator + value.substring(0, firstLineDataLength) + NEWLINE);

        // Write continuation lines (76 chars of data each, with leading space)
        // This matches format_ldif_data() line 3081
        int pos = firstLineDataLength;
        while (pos < value.length()) {
            int endPos = Math.min(pos + 76, value.length());
            writer.write(" " + value.substring(pos, endPos) + NEWLINE);
            pos = endPos;
        }
    }

    /**
     * cross-scheme: Write entry unchanged to target LDIF.
     */
    private static boolean writeEntryUnchanged(Map<String, List<String>> attributes,
                                                List<String> entryComments, BufferedWriter writer) throws IOException {
        // Write all leading comment lines
        for (String comment : entryComments) {
            writer.write(comment + NEWLINE);
        }

        // Write all attributes in order (including dn/rdn which will be first)
        for (Map.Entry<String, List<String>> entry : attributes.entrySet()) {
            String attr = entry.getKey();
            for (String value : entry.getValue()) {
                // Apply LDIF transformations (ID offset, naming context)
                String transformedValue = applyLdifTransformations(attr, value);

                // Determine if this was base64 encoded (has "::" marker)
                boolean isBase64 = attr.equals("privateKeyData") || attr.equals("publicKeyData");

                // Write with proper LDIF line wrapping
                writeWrappedLdifAttribute(attr, transformedValue, isBase64, writer);
            }
        }

        mProcessedEntries++;  // Track that we wrote an entry
        System.out.print(".");
        return SUCCESS;
    }

    /**
     * cross-scheme: Extract base64-encoded attribute value.
     */
    private static byte[] extractBase64Attribute(Map<String, List<String>> attributes, String attrName) {
        List<String> values = attributes.get(attrName);
        if (values == null || values.isEmpty()) {
            return null;
        }
        try {
            return Utils.base64decode(values.get(0));
        } catch (Exception e) {
            log("ERROR: Failed to decode " + attrName + ": " + e.getMessage() + NEWLINE, true);
            return null;
        }
    }

    /**
     * cross-scheme: Process and transform a key record with algorithm migration.
     */
    private static boolean processKeyRecord(Map<String, List<String>> attributes,
                                             String recordType, List<String> entryComments, BufferedWriter writer)
            throws IOException, Exception {

        System.out.print(".");

        // Log record separator for debugging (counter will be incremented after successful processing)
        if (mVerboseFlag) {
            log("==== Processing keyRecord: " + (mProcessedKeyRecords + 1) + " ====" + NEWLINE, false);
        }

        // TEST MODE: If -skip_rewrap is set, just copy key data as-is and skip crypto operations
        if (mSkipRewrap) {
            log("SKIP_REWRAP: Copying key data as-is (no cryptographic operations)" + NEWLINE, false);
            mProcessedKeyRecords++;

            // Update dateOfModify timestamp to show record was processed
            String currentDate = new java.text.SimpleDateFormat(DATE_OF_MODIFY_PATTERN).format(new java.util.Date());
            attributes.put("dateOfModify", Collections.singletonList(currentDate));

            // Write entry with LDIF transformations applied (ID offset, naming context, line wrapping)
            return writeEntryUnchanged(attributes, entryComments, writer);
        }

        // NORMAL MODE: Perform actual rewrap operations
        // Extract required data for rewrapping
        byte[] privateKeyData = extractBase64Attribute(attributes, "privateKeyData");
        byte[] publicKeyData = extractBase64Attribute(attributes, "publicKeyData");
        byte[] ivData = extractIVFromMetaInfo(attributes);

        if (privateKeyData == null || publicKeyData == null) {
            log("ERROR: Missing privateKeyData or publicKeyData in key record" + NEWLINE, true);
            mFailedKeyRecords++;
            return FAILURE;
        }

        log("Extracted privateKeyData (" + privateKeyData.length + " bytes)" + NEWLINE, false);
        log("Extracted publicKeyData (" + publicKeyData.length + " bytes)" + NEWLINE, false);

        // Check if IV is required and present (use cached values for performance)
        if (mSourcePayloadNeedsIV) {
            if (ivData == null) {
                log("ERROR: IV required for " + mSourcePayloadWrapAlgName +
                    " but not found in metaInfo" + NEWLINE, true);
                mFailedKeyRecords++;
                return FAILURE;
            }
            log("Extracted payload wrap IV (" + ivData.length + " bytes)" + NEWLINE, false);
        }

        // Perform rewrap operation
        byte[] rewrappedData = rewrap_wrapped_key_data(privateKeyData, publicKeyData, ivData);
        if (rewrappedData == null) {
            log("ERROR: Failed to rewrap key record" + NEWLINE, true);
            mFailedKeyRecords++;
            return FAILURE;
        }

        if (mVerboseFlag) {
            log("Rewrapped privateKeyData for " + recordType + NEWLINE, false);
        }
        mProcessedKeyRecords++;

        // Progress logging every 1000 records (only when not in verbose mode)
        if (!mVerboseFlag && mProcessedKeyRecords % 1000 == 0) {
            log("Progress: " + mProcessedKeyRecords + " key records processed"
                       + (mFailedKeyRecords > 0 ? " (" + mFailedKeyRecords + " failed)" : "") + NEWLINE, false);
        }

        // Update attributes with rewrapped data
        String rewrappedBase64 = Utils.base64encode(rewrappedData, true);
        attributes.put("privateKeyData", Collections.singletonList(stripEOL(rewrappedBase64)));

        // Update metaInfo fields for new algorithms
        updateMetaInfoForNewAlgorithms(attributes);

        // Update dateOfModify timestamp
        String currentDate = new java.text.SimpleDateFormat(DATE_OF_MODIFY_PATTERN).format(new java.util.Date());
        attributes.put("dateOfModify", Collections.singletonList(currentDate));

        // Write transformed entry
        return writeEntryUnchanged(attributes, entryComments, writer);
    }

    /**
     * cross-scheme: Extract IV from metaInfo attributes.
     * Checks both payloadWrapIV and payloadEncryptionIV for compatibility.
     */
    private static byte[] extractIVFromMetaInfo(Map<String, List<String>> attributes) {
        List<String> metaInfos = attributes.get("metaInfo");
        if (metaInfos == null) {
            return null;
        }

        for (String metaInfo : metaInfos) {
            // Check for payloadWrapIV first (test server format)
            if (metaInfo.contains("payloadWrapIV:")) {
                try {
                    int ivStart = metaInfo.indexOf("payloadWrapIV:") + "payloadWrapIV:".length();
                    String ivBase64 = metaInfo.substring(ivStart).trim();
                    return Utils.base64decode(ivBase64);
                } catch (Exception e) {
                    log("WARNING: Failed to parse payloadWrapIV: " + e.getMessage() + NEWLINE, false);
                    return null;
                }
            }
            // Also check for payloadEncryptionIV (found in some LDIF exports)
            if (metaInfo.contains("payloadEncryptionIV:")) {
                try {
                    int ivStart = metaInfo.indexOf("payloadEncryptionIV:") + "payloadEncryptionIV:".length();
                    String ivBase64 = metaInfo.substring(ivStart).trim();
                    return Utils.base64decode(ivBase64);
                } catch (Exception e) {
                    log("WARNING: Failed to parse payloadEncryptionIV: " + e.getMessage() + NEWLINE, false);
                    return null;
                }
            }
        }
        return null;
    }

    /**
     * cross-scheme: Update metaInfo attributes to reflect new wrapping algorithms.
     */
    private static void updateMetaInfoForNewAlgorithms(Map<String, List<String>> attributes) throws Exception {
        List<String> metaInfos = attributes.get("metaInfo");
        if (metaInfos == null) {
            metaInfos = new ArrayList<>();
            attributes.put("metaInfo", metaInfos);
        }

        // Process each metaInfo entry and update algorithm-related fields
        List<String> updatedMetaInfos = new ArrayList<>();

        for (String metaInfo : metaInfos) {
            String updatedInfo = metaInfo;

            // Update sessionKeyWrapAlgorithm if RSA wrap algorithm changed
            if (metaInfo.startsWith("sessionKeyWrapAlgorithm:")) {
                if (mTargetRSAWrapAlgName != null) {
                    String targetAlg = mTargetRSAWrapAlgName.equalsIgnoreCase("RSA-OAEP") ?
                                       "RSAES-OAEP" : "RSA";
                    updatedInfo = "sessionKeyWrapAlgorithm:" + targetAlg;
                    log("Updated sessionKeyWrapAlgorithm: " + targetAlg + NEWLINE, false);
                }
            }
            // Update sessionKeyType if session key was regenerated
            else if (metaInfo.startsWith("sessionKeyType:")) {
                // Check if we regenerated the session key
                if (mSessionKeyDecisionMade != null && mSessionKeyDecisionMade) {
                    // For now, we always generate AES keys
                    updatedInfo = "sessionKeyType:AES";
                }
            }
            // Update sessionKeyLength if session key was regenerated
            else if (metaInfo.startsWith("sessionKeyLength:")) {
                // Check if we regenerated the session key
                if (mSessionKeyDecisionMade != null && mSessionKeyDecisionMade) {
                    int targetKeySize = getKeySizeFromAlgorithm(mTargetPayloadWrapAlgName);
                    if (targetKeySize == 0) {
                        targetKeySize = 128;  // Default
                    }
                    updatedInfo = "sessionKeyLength:" + targetKeySize;
                    log("Updated sessionKeyLength: " + targetKeySize + NEWLINE, false);
                }
            }
            // Update payloadWrapAlgorithm if payload algorithm changed
            else if (metaInfo.startsWith("payloadWrapAlgorithm:")) {
                if (mTargetPayloadWrapAlgName != null) {
                    updatedInfo = "payloadWrapAlgorithm:" + mTargetPayloadWrapAlgName;
                    log("Updated payloadWrapAlgorithm: " + mTargetPayloadWrapAlgName + NEWLINE, false);
                }
            }
            // DO NOT update payloadEncryptionOID - it is not used during unwrapping and causes errors.
            // The KRA uses payloadWrapAlgorithm for actual unwrapping operations.
            // The payloadEncryptionOID field is a legacy artifact that, if changed to an OID
            // not recognized by JSS (e.g., 2.16.840.1.101.3.4.1.45 for AES-256-KeyWrap),
            // will cause NoSuchAlgorithmException in KeyRecord.getWrappingParams() during recovery.
            // Keep the original value unchanged.
            else if (metaInfo.startsWith("payloadEncryptionOID:")) {
                // Keep original value - do not update
            }
            // Remove payloadWrapIV/payloadEncryptionIV if switching from CBC to KeyWrap
            else if (metaInfo.startsWith("payloadWrapIV:") || metaInfo.startsWith("payloadEncryptionIV:")) {
                if (mTargetPayloadWrapAlgName != null && !mTargetPayloadNeedsIV) {
                    log("Removed " + metaInfo.substring(0, metaInfo.indexOf(':')) +
                        " (not needed for " + mTargetPayloadWrapAlgName + ")" + NEWLINE, false);
                    continue;  // Skip this metaInfo entry (don't add to updated list)
                }
            }

            updatedMetaInfos.add(updatedInfo);
        }

        // Replace metaInfo list with updated version
        attributes.put("metaInfo", updatedMetaInfos);
    }

    /**
     * cross-scheme: Get OID for a given payload wrap algorithm name and key size.
     *
     * @param algorithmName The algorithm name (e.g., "AES/CBC/PKCS5Padding", "AES KeyWrap/Padding")
     * @param keySize The key size in bits (128, 192, or 256)
     * @return The OID string
     */
    private static String getOIDForAlgorithm(String algorithmName, int keySize) {
        // OID mappings based on observed LDIF data:
        // 2.16.840.1.101.3.4.1.2 = AES-128-CBC
        // 2.16.840.1.101.3.4.1.5 = AES-128-KW (KeyWrap)
        // 2.16.840.1.101.3.4.1.22 = AES-192-CBC
        // 2.16.840.1.101.3.4.1.25 = AES-192-KW
        // 2.16.840.1.101.3.4.1.42 = AES-256-CBC
        // 2.16.840.1.101.3.4.1.45 = AES-256-KW

        boolean isCBC = algorithmName.contains("CBC");
        boolean isKeyWrap = algorithmName.contains("KeyWrap") || algorithmName.contains("Wrap");

        if (keySize == 128) {
            return isCBC ? "2.16.840.1.101.3.4.1.2" : "2.16.840.1.101.3.4.1.5";
        } else if (keySize == 192) {
            return isCBC ? "2.16.840.1.101.3.4.1.22" : "2.16.840.1.101.3.4.1.25";
        } else if (keySize == 256) {
            return isCBC ? "2.16.840.1.101.3.4.1.42" : "2.16.840.1.101.3.4.1.45";
        }

        // Fallback for unexpected key sizes - default to 128-bit based on algorithm type
        if (isCBC) {
            return "2.16.840.1.101.3.4.1.2";  // AES-128-CBC
        } else if (isKeyWrap) {
            return "2.16.840.1.101.3.4.1.5";  // AES-128-KW
        } else {
            // Unknown algorithm type - default to AES-128-CBC
            log("WARNING: Unknown algorithm type '" + algorithmName + "' - defaulting to AES-128-CBC" + NEWLINE, false);
            return "2.16.840.1.101.3.4.1.2";
        }
    }

    /**************************************/
    /* KRATOOL Config File Parser Methods */
    /**************************************/

    /**
     * This method performs the actual parsing of the KRATOOL config file
     * and initializes how the KRA Record Fields should be processed.
     * <P>
     *
     * @return true if the KRATOOL config file is successfully processed
     */
    private static boolean process_kratool_config_file() {
        BufferedReader reader = null;
        String line = null;
        String name_value_pair[] = null;
        String name = null;
        Boolean value = null;

        // Process each line containing a name/value pair
        // in the KRATOOL config file
        try {
            // Open KRATOOL config file for reading
            reader = new BufferedReader(
                         new FileReader(mKratoolCfgFilename));

            // Create a hashtable for relevant name/value pairs
            kratoolCfg = new Hashtable<>();

            System.out.print("PROCESSING KRATOOL CONFIG FILE: ");
            while ((line = reader.readLine()) != null) {
                if (line.startsWith(KRATOOL_CFG_PREFIX)) {
                    // obtain "name=value" pair
                    name_value_pair = line.split(EQUAL_SIGN);

                    // obtain "name"
                    name = name_value_pair[0];

                    // compute "boolean" value
                    if (name_value_pair[1].equals("true")) {
                        value = Boolean.TRUE;
                    } else {
                        value = Boolean.FALSE;
                    }

                    // store relevant KRA LDIF fields for processing
                    if (name.equals(KRATOOL_CFG_ENROLLMENT_CN)
                            || name.equals(KRATOOL_CFG_ENROLLMENT_DATE_OF_MODIFY)
                            || name.equals(KRATOOL_CFG_ENROLLMENT_DN)
                            || name.equals(KRATOOL_CFG_ENROLLMENT_EXTDATA_KEY_RECORD)
                            || name.equals(KRATOOL_CFG_ENROLLMENT_EXTDATA_REQUEST_NOTES)
                            || name.equals(KRATOOL_CFG_ENROLLMENT_REQUEST_ID)
                            || name.equals(KRATOOL_CFG_CA_KEY_RECORD_CN)
                            || name.equals(KRATOOL_CFG_CA_KEY_RECORD_DATE_OF_MODIFY)
                            || name.equals(KRATOOL_CFG_CA_KEY_RECORD_DN)
                            || name.equals(KRATOOL_CFG_CA_KEY_RECORD_PRIVATE_KEY_DATA)
                            || name.equals(KRATOOL_CFG_CA_KEY_RECORD_SERIAL_NO)
                            || name.equals(KRATOOL_CFG_RECOVERY_CN)
                            || name.equals(KRATOOL_CFG_RECOVERY_DATE_OF_MODIFY)
                            || name.equals(KRATOOL_CFG_RECOVERY_DN)
                            || name.equals(KRATOOL_CFG_RECOVERY_EXTDATA_REQUEST_ID)
                            || name.equals(KRATOOL_CFG_RECOVERY_EXTDATA_REQUEST_NOTES)
                            || name.equals(KRATOOL_CFG_RECOVERY_EXTDATA_SERIAL_NUMBER)
                            || name.equals(KRATOOL_CFG_RECOVERY_REQUEST_ID)
                            || name.equals(KRATOOL_CFG_TPS_KEY_RECORD_CN)
                            || name.equals(KRATOOL_CFG_TPS_KEY_RECORD_DATE_OF_MODIFY)
                            || name.equals(KRATOOL_CFG_TPS_KEY_RECORD_DN)
                            || name.equals(KRATOOL_CFG_TPS_KEY_RECORD_PRIVATE_KEY_DATA)
                            || name.equals(KRATOOL_CFG_TPS_KEY_RECORD_SERIAL_NO)
                            || name.equals(KRATOOL_CFG_KEYGEN_CN)
                            || name.equals(KRATOOL_CFG_KEYGEN_DATE_OF_MODIFY)
                            || name.equals(KRATOOL_CFG_KEYGEN_DN)
                            || name.equals(KRATOOL_CFG_KEYGEN_EXTDATA_KEY_RECORD)
                            || name.equals(KRATOOL_CFG_KEYGEN_EXTDATA_REQUEST_ID)
                            || name.equals(KRATOOL_CFG_KEYGEN_EXTDATA_REQUEST_NOTES)
                            || name.equals(KRATOOL_CFG_KEYGEN_REQUEST_ID)
                            || name.equals(KRATOOL_CFG_KEYRECOVERY_REQUEST_ID )
                            || name.equals(KRATOOL_CFG_KEYRECOVERY_DN )
                            || name.equals(KRATOOL_CFG_KEYRECOVERY_DATE_OF_MODIFY)
                            || name.equals(KRATOOL_CFG_KEYRECOVERY_EXTDATA_REQUEST_ID)
                            || name.equals(KRATOOL_CFG_KEYRECOVERY_CN)
                            || name.equals(KRATOOL_CFG_KEYRECOVERY_EXTDATA_REQUEST_NOTES) ) {
                        kratoolCfg.put(name, value);
                        System.out.print(".");
                    }
                }
            }
            System.out.println(" FINISHED." + NEWLINE);
        } catch (FileNotFoundException exKratoolCfgFileNotFound) {
            log("ERROR:  No KRATOOL config file named '"
                    + mKratoolCfgFilename
                    + "' exists!  FileNotFoundException: '"
                    + exKratoolCfgFileNotFound.toString()
                    + "'"
                    + NEWLINE, true);
            return FAILURE;
        } catch (IOException exKratoolCfgIO) {
            log("ERROR:  line='"
                    + line
                    + "' IOException: '"
                    + exKratoolCfgIO.toString()
                    + "'"
                    + NEWLINE, true);
            return FAILURE;
        } catch (PatternSyntaxException exKratoolCfgNameValuePattern) {
            log("ERROR:  line='"
                    + line
                    + "' PatternSyntaxException: '"
                    + exKratoolCfgNameValuePattern.toString()
                    + "'"
                    + NEWLINE, true);
            return FAILURE;
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    log("Error closing reader: " + e.getMessage(), true);
                    if (mVerboseFlag) {
                        e.printStackTrace();
                    }
                }
            }
        }

        return SUCCESS;
    }

    /************/
    /* KRA Tool */
    /************/

    /**
     * The main KRATool method.
     * <P>
     *
     * @param args KRATool options
     */
    public static void main(String[] args) {
        // Variables
        String append_id_offset = null;
        String remove_id_offset = null;
        String process_kra_naming_context_fields = null;
        String process_requests_and_key_records_only = null;
        String use_PKI_security_database_pwdfile = null;
        String keyUnwrapAlgorithmName = null;
        File cfgFile = null;
        File sourceFile = null;
        File sourceDBPath = null;
        File sourceDBPwdfile = null;
        File targetStorageCertFile = null;
        File targetFile = null;
        File logFile = null;
        boolean success = false;

        // Get current date and time
        mDateOfModify = now(DATE_OF_MODIFY_PATTERN);

        // Check for help flag first
        if (args.length > 0 && (args[0].equals("-h") || args[0].equals("--help"))) {
            printUsage();
            System.exit(0);
        }

        // Check minimum number of arguments
        // With cross-scheme migration options and boolean flags, we can't use
        // rigid argument counting. Instead, we'll validate mandatory arguments
        // after parsing.
        if (args.length < 2) {
            System.err.println("ERROR:  Insufficient arguments!"
                              + NEWLINE);
            printUsage();
            System.exit(0);
        }

        // Process command-line arguments
        for (int i = 0; i < args.length; i += 2) {
            if (args[i].equals(KRATOOL_CFG_FILE)) {
                mKratoolCfgFilename = args[i + 1];
                mMandatoryNameValuePairs++;
            } else if (args[i].equals(SOURCE_LDIF_FILE)) {
                mSourceLdifFilename = args[i + 1];
                mMandatoryNameValuePairs++;
            } else if (args[i].equals(TARGET_LDIF_FILE)) {
                mTargetLdifFilename = args[i + 1];
                mMandatoryNameValuePairs++;
            } else if (args[i].equals(LOG_FILE)) {
                mLogFilename = args[i + 1];
                mMandatoryNameValuePairs++;
            } else if (args[i].equals(SOURCE_NSS_DB_PATH)) {
                mSourcePKISecurityDatabasePath = args[i + 1];
                mRewrapNameValuePairs++;
            } else if (args[i].equals(SOURCE_STORAGE_TOKEN_NAME)) {
                mSourceStorageTokenName = args[i + 1];
                mRewrapNameValuePairs++;
            } else if (args[i].equals(SOURCE_STORAGE_CERT_NICKNAME)) {
                mSourceStorageCertNickname = args[i + 1];
                mRewrapNameValuePairs++;
            } else if (args[i].equals(TARGET_STORAGE_CERTIFICATE_FILE)) {
                mTargetStorageCertificateFilename = args[i + 1];
                mRewrapNameValuePairs++;
            } else if (args[i].equals(SOURCE_NSS_DB_PWDFILE)) {
                mSourcePKISecurityDatabasePwdfile = args[i + 1];
                mPKISecurityDatabasePwdfileNameValuePairs++;
            } else if (args[i].equals(SOURCE_HSM_TOKEN_PWDFILE)) {
                mSourceHsmTokenPwdfile = args[i + 1];
                mHsmPwdfileFlag = true;
            } else if (args[i].equals(APPEND_ID_OFFSET)) {
                append_id_offset = args[i + 1];
                mAppendIdOffsetNameValuePairs++;
            } else if (args[i].equals(REMOVE_ID_OFFSET)) {
                remove_id_offset = args[i + 1];
                mRemoveIdOffsetNameValuePairs++;
            } else if (args[i].equals(SOURCE_KRA_NAMING_CONTEXT)) {
                mSourceKraNamingContext = args[i + 1];
                mKraNamingContextNameValuePairs++;
            } else if (args[i].equals(TARGET_KRA_NAMING_CONTEXT)) {
                mTargetKraNamingContext = args[i + 1];
                mKraNamingContextNameValuePairs++;
            } else if (args[i].equals(PROCESS_REQUESTS_AND_KEY_RECORDS_ONLY)) {
                mProcessRequestsAndKeyRecordsOnlyFlag = true;
                i -= 1;
            } else if (args[i].equals(VERBOSE)) {
                mVerboseFlag = true;
                i -= 1;
            } else if (args[i].contentEquals(KEY_UNWRAP_ALGORITHM)) {
                keyUnwrapAlgorithmName = args[i + 1];
            } else if (args[i].contentEquals(USE_OAEP_RSA_KEY_WRAP)) {
                mUseOAEPKeyWrapAlg = true;
            } else if (args[i].contentEquals(SOURCE_RSA_WRAP_ALGORITHM)) {
                // cross-scheme
                mSourceRSAWrapAlgName = args[i + 1];
            } else if (args[i].contentEquals(TARGET_RSA_WRAP_ALGORITHM)) {
                // cross-scheme
                mTargetRSAWrapAlgName = args[i + 1];
            } else if (args[i].contentEquals(SOURCE_PAYLOAD_WRAP_ALGORITHM)) {
                // cross-scheme
                mSourcePayloadWrapAlgName = args[i + 1];
            } else if (args[i].contentEquals(TARGET_PAYLOAD_WRAP_ALGORITHM)) {
                // cross-scheme
                mTargetPayloadWrapAlgName = args[i + 1];
            } else if (args[i].contentEquals(SOURCE_PAYLOAD_WRAP_KEYSIZE)) {
                // cross-scheme
                try {
                    mSourcePayloadWrapKeySize = Integer.parseInt(args[i + 1]);
                    if (mSourcePayloadWrapKeySize != 128 && mSourcePayloadWrapKeySize != 192 && mSourcePayloadWrapKeySize != 256) {
                        System.err.println("ERROR:  Source payload wrapping key size must be 128, 192, or 256" + NEWLINE);
                        printUsage();
                        System.exit(0);
                    }
                } catch (NumberFormatException e) {
                    System.err.println("ERROR:  Invalid source payload wrapping key size: " + args[i + 1] + NEWLINE);
                    printUsage();
                    System.exit(0);
                }
            } else if (args[i].contentEquals(TARGET_PAYLOAD_WRAP_KEYSIZE)) {
                // cross-scheme
                try {
                    mTargetPayloadWrapKeySize = Integer.parseInt(args[i + 1]);
                    if (mTargetPayloadWrapKeySize != 128 && mTargetPayloadWrapKeySize != 192 && mTargetPayloadWrapKeySize != 256) {
                        System.err.println("ERROR:  Target payload wrapping key size must be 128, 192, or 256" + NEWLINE);
                        printUsage();
                        System.exit(0);
                    }
                } catch (NumberFormatException e) {
                    System.err.println("ERROR:  Invalid target payload wrapping key size: " + args[i + 1] + NEWLINE);
                    printUsage();
                    System.exit(0);
                }
            } else if (args[i].contentEquals(USE_NSS_FOR_PAYLOAD_PROCESSING)) {
                // cross-scheme: boolean flag, compensate for loop's i+=2
                mUseNssForPayloadProcessing = true;
                i -= 1;
            } else if (args[i].contentEquals(REGENERATE_SESSION_KEY)) {
                // cross-scheme: boolean flag, compensate for loop's i+=2
                mRegenerateSessionKey = true;
                i -= 1;
            } else if (args[i].contentEquals(SKIP_REWRAP)) {
                // cross-scheme: TEST ONLY: boolean flag, compensate for loop's i+=2
                mSkipRewrap = true;
                i -= 1;
            } else if (args[i].contentEquals(FORCE_RSA_KEYPAIR_TRANSFER)) {
                // cross-scheme: TEST ONLY: boolean flag, compensate for loop's i+=2
                mForceRSAKeypairTransfer = true;
                i -= 1;
            } else if (args[i].contentEquals(SPLIT_TARGET_LDIF_PER_RECORDS)) {
                // cross-scheme: split output into multiple files
                if (i + 1 >= args.length || args[i + 1].startsWith("-")) {
                    System.err.println("ERROR:  " + SPLIT_TARGET_LDIF_PER_RECORDS + " requires a numeric value" + NEWLINE);
                    printUsage();
                    System.exit(0);
                }
                try {
                    mSplitTargetLdifPerRecords = Integer.parseInt(args[i + 1]);
                    if (mSplitTargetLdifPerRecords <= 0) {
                        System.err.println("ERROR:  Split records count must be greater than 0" + NEWLINE);
                        printUsage();
                        System.exit(0);
                    }
                } catch (NumberFormatException e) {
                    System.err.println("ERROR:  Invalid split records count: " + args[i + 1] + NEWLINE);
                    printUsage();
                    System.exit(0);
                }
            } else if (args[i].contentEquals(USE_CROSS_SCHEME)) {
                // cross-scheme: boolean flag, compensate for loop's i+=2
                mUseCrossSchemeFlag = true;
                i -= 1;
            } else {
                System.err.println("ERROR:  Unknown argument '"
                                  + args[i]
                                  + "'!"
                                  + NEWLINE);
                printUsage();
                System.exit(0);
            }
        }

        // Verify that correct number of valid mandatory
        // arguments were submitted to the program
        if (mMandatoryNameValuePairs != MANDATORY_NAME_VALUE_PAIRS ||
                mKratoolCfgFilename == null ||
                mKratoolCfgFilename.length() == 0 ||
                mSourceLdifFilename == null ||
                mSourceLdifFilename.length() == 0 ||
                mTargetLdifFilename == null ||
                mTargetLdifFilename.length() == 0 ||
                mLogFilename == null ||
                mLogFilename.length() == 0) {
            System.err.println("ERROR:  Missing mandatory arguments!"
                              + NEWLINE);
            printUsage();
            System.exit(0);
        } else {
            // Check for a valid KRATOOL config file
            cfgFile = new File(mKratoolCfgFilename);
            if (!cfgFile.exists() ||
                    !cfgFile.isFile() ||
                    (cfgFile.length() == 0)) {
                System.err.println("ERROR:  '"
                                  + mKratoolCfgFilename
                                  + "' does NOT exist, is NOT a file, "
                                  + "or is empty!"
                                  + NEWLINE);
                printUsage();
                System.exit(0);
            }

            // Check for a valid source LDIF file
            sourceFile = new File(mSourceLdifFilename);
            if (!sourceFile.exists() ||
                    !sourceFile.isFile() ||
                    (sourceFile.length() == 0)) {
                System.err.println("ERROR:  '"
                                  + mSourceLdifFilename
                                  + "' does NOT exist, is NOT a file, "
                                  + "or is empty!"
                                  + NEWLINE);
                printUsage();
                System.exit(0);
            }

            // Check that the target LDIF file does NOT exist
            targetFile = new File(mTargetLdifFilename);
            if (targetFile.exists()) {
                System.err.println("ERROR:  '"
                                  + mTargetLdifFilename
                                  + "' ALREADY exists!"
                                  + NEWLINE);
                printUsage();
                System.exit(0);
            }

            // Check that the log file does NOT exist
            logFile = new File(mLogFilename);
            if (logFile.exists()) {
                System.err.println("ERROR:  '"
                                  + mLogFilename
                                  + "' ALREADY exists!"
                                  + NEWLINE);
                printUsage();
                System.exit(0);
            }
        }

        // Check to see that if the 'Rewrap' command-line options were
        // specified, that they are all present and accounted for
        if (mRewrapNameValuePairs > 0) {
            if (mRewrapNameValuePairs != REWRAP_NAME_VALUE_PAIRS ||
                    mSourcePKISecurityDatabasePath == null ||
                    mSourcePKISecurityDatabasePath.length() == 0 ||
                    mSourceStorageTokenName == null ||
                    mSourceStorageTokenName.length() == 0 ||
                    mSourceStorageCertNickname == null ||
                    mSourceStorageCertNickname.length() == 0 ||
                    mTargetStorageCertificateFilename == null ||
                    mTargetStorageCertificateFilename.length() == 0) {
                System.err.println("ERROR:  Missing 'Rewrap' arguments!"
                                  + NEWLINE);
                printUsage();
                System.exit(0);
            } else {
                // Check for a valid path to the PKI security databases
                sourceDBPath = new File(mSourcePKISecurityDatabasePath);
                if (!sourceDBPath.exists() ||
                        !sourceDBPath.isDirectory()) {
                    System.err.println("ERROR:  '"
                                      + mSourcePKISecurityDatabasePath
                                      + "' does NOT exist or "
                                      + "'is NOT a directory!"
                                      + NEWLINE);
                    printUsage();
                    System.exit(0);
                }

                // Check for a valid target storage certificate file
                targetStorageCertFile = new File(
                                            mTargetStorageCertificateFilename);
                if (!targetStorageCertFile.exists() ||
                        !targetStorageCertFile.isFile() ||
                        (targetStorageCertFile.length() == 0)) {
                    System.err.println("ERROR:  '"
                                      + mTargetStorageCertificateFilename
                                      + "' does NOT exist, is NOT a file, "
                                      + "or is empty!"
                                      + NEWLINE);
                    printUsage();
                    System.exit(0);
                }

                // Mark the 'Rewrap' flag true
                mRewrapFlag = true;
            }
        }

        // Check to see that BOTH append 'ID Offset' command-line options
        // and remove 'ID Offset' command-line options were NOT specified
        // since these two command-line options are mutually exclusive!
        if ((mAppendIdOffsetNameValuePairs > 0) &&
                (mRemoveIdOffsetNameValuePairs > 0)) {
            System.err.println("ERROR:  The 'append ID Offset' option "
                                  + "and the 'remove ID Offset' option are "
                                  + "mutually exclusive!"
                                  + NEWLINE);
            printUsage();
            System.exit(0);
        }

        // Check to see that if the 'append ID Offset' command-line options
        // were specified, that they are all present and accounted for
        if (mAppendIdOffsetNameValuePairs > 0) {
            if (mAppendIdOffsetNameValuePairs == ID_OFFSET_NAME_VALUE_PAIRS &&
                    append_id_offset != null &&
                    append_id_offset.length() != 0) {
                try {
                    if (!append_id_offset.matches("[0-9]++")) {
                        System.err.println("ERROR:  '"
                                          + append_id_offset
                                          + "' contains non-numeric "
                                          + "characters!"
                                          + NEWLINE);
                        printUsage();
                        System.exit(0);
                    } else {
                        mAppendIdOffset = new BigInteger(
                                              append_id_offset);

                        // Mark the 'append ID Offset' flag true
                        mAppendIdOffsetFlag = true;
                    }
                } catch (PatternSyntaxException exAppendPattern) {
                    System.err.println("ERROR:  append_id_offset='"
                                      + append_id_offset
                                      + "' PatternSyntaxException: '"
                                      + exAppendPattern.toString()
                                      + "'"
                                      + NEWLINE);
                    System.exit(0);
                }
            } else {
                System.err.println("ERROR:  Missing "
                                  + "'append ID Offset' arguments!"
                                  + NEWLINE);
                printUsage();
                System.exit(0);
            }
        }

        // Check to see that if the 'remove ID Offset' command-line options
        // were specified, that they are all present and accounted for
        if (mRemoveIdOffsetNameValuePairs > 0) {
            if (mRemoveIdOffsetNameValuePairs == ID_OFFSET_NAME_VALUE_PAIRS &&
                    remove_id_offset != null &&
                    remove_id_offset.length() != 0) {
                try {
                    if (!remove_id_offset.matches("[0-9]++")) {
                        System.err.println("ERROR:  '"
                                          + remove_id_offset
                                          + "' contains non-numeric "
                                          + "characters!"
                                          + NEWLINE);
                        printUsage();
                        System.exit(0);
                    } else {
                        mRemoveIdOffset = new BigInteger(
                                              remove_id_offset);

                        // Mark the 'remove ID Offset' flag true
                        mRemoveIdOffsetFlag = true;
                    }
                } catch (PatternSyntaxException exRemovePattern) {
                    System.err.println("ERROR:  remove_id_offset='"
                                      + remove_id_offset
                                      + "' PatternSyntaxException: '"
                                      + exRemovePattern.toString()
                                      + "'"
                                      + NEWLINE);
                    System.exit(0);
                }
            } else {
                System.err.println("ERROR:  Missing "
                                  + "'remove ID Offset' arguments!"
                                  + NEWLINE);
                printUsage();
                System.exit(0);
            }
        }

        // Make certain that at least one of the "Rewrap", "Append ID Offset",
        // or "Remove ID Offset" options has been specified
        if (!mRewrapFlag &&
                !mAppendIdOffsetFlag &&
                !mRemoveIdOffsetFlag) {
            System.err.println("ERROR:  At least one of the 'rewrap', "
                              + "'append ID Offset', or 'remove ID Offset' "
                              + "options MUST be specified!"
                              + NEWLINE);
            printUsage();
            System.exit(0);
        }

        // Check to see that if the OPTIONAL
        // 'PKI Security Database Password File'
        // command-line options were specified,
        // that they are all present and accounted for
        if (mPKISecurityDatabasePwdfileNameValuePairs > 0) {
            if (mPKISecurityDatabasePwdfileNameValuePairs !=
                    PWDFILE_NAME_VALUE_PAIRS ||
                    mSourcePKISecurityDatabasePwdfile == null ||
                    mSourcePKISecurityDatabasePwdfile.length() == 0) {
                System.err.println("ERROR:  Missing 'Password File' "
                                  + "arguments!"
                                  + NEWLINE);
                printUsage();
                System.exit(0);
            } else {
                if (mRewrapFlag) {
                    // Check for a valid source PKI
                    // security database password file
                    sourceDBPwdfile = new
                                      File(mSourcePKISecurityDatabasePwdfile);
                    if (!sourceDBPwdfile.exists() ||
                            !sourceDBPwdfile.isFile() ||
                            (sourceDBPwdfile.length() == 0)) {
                        System.err.println("ERROR:  '"
                                          + mSourcePKISecurityDatabasePwdfile
                                          + "' does NOT exist, is NOT a file, "
                                          + "or is empty!"
                                          + NEWLINE);
                        printUsage();
                        System.exit(0);
                    }

                    use_PKI_security_database_pwdfile = SPACE
                                             + SOURCE_NSS_DB_PWDFILE
                                             + SPACE
                                             + TIC
                                             + mSourcePKISecurityDatabasePwdfile
                                             + TIC;

                    mSourcePKISecurityDatabasePwdfileMessage = SPACE
                                             + PLUS
                                             + SPACE
                                             + KRA_LDIF_USED_PWDFILE_MESSAGE;

                    // Mark the 'Password File' flag true
                    mPwdfileFlag = true;
                } else {
                    System.err.println("ERROR:  The "
                                      + TIC
                                      + SOURCE_NSS_DB_PWDFILE
                                      + TIC
                                      + " option is ONLY valid when "
                                      + "performing rewrapping."
                                      + NEWLINE);
                    printUsage();
                    System.exit(0);
                }
            }
        } else {
            use_PKI_security_database_pwdfile = "";
            mSourcePKISecurityDatabasePwdfileMessage = "";
        }

        // Check to see that if the OPTIONAL 'KRA Naming Context' command-line
        // options were specified, that they are all present and accounted for
        if (mKraNamingContextNameValuePairs > 0) {
            if (mKraNamingContextNameValuePairs !=
                    NAMING_CONTEXT_NAME_VALUE_PAIRS ||
                    mSourceKraNamingContext == null ||
                    mSourceKraNamingContext.length() == 0 ||
                    mTargetKraNamingContext == null ||
                    mTargetKraNamingContext.length() == 0) {
                System.err.println("ERROR:  Both 'source KRA naming context' "
                                  + "and 'target KRA naming context' "
                                  + "options MUST be specified!"
                                  + NEWLINE);
                printUsage();
                System.exit(0);
            } else {
                process_kra_naming_context_fields = SPACE
                                                  + SOURCE_KRA_NAMING_CONTEXT
                                                  + SPACE
                                                  + TIC
                                                  + mSourceKraNamingContext
                                                  + TIC
                                                  + SPACE
                                                  + TARGET_KRA_NAMING_CONTEXT
                                                  + SPACE
                                                  + TIC
                                                  + mTargetKraNamingContext
                                                  + TIC;

                mKraNamingContextMessage = SPACE
                                         + PLUS
                                         + SPACE
                                         + KRA_LDIF_SOURCE_NAME_CONTEXT_MESSAGE
                                         + mSourceKraNamingContext
                                         + KRA_LDIF_TARGET_NAME_CONTEXT_MESSAGE
                                         + mTargetKraNamingContext
                                         + TIC;

                // Mark the 'KRA Naming Contexts' flag true
                mKraNamingContextsFlag = true;
            }
        } else {
            process_kra_naming_context_fields = "";
            mKraNamingContextMessage = "";
        }

        // Check for the Key Unwrap Algorithm provided by user.
        // If unprovided, choose DES3 as the default (to maintain consistency with old code)
        if (keyUnwrapAlgorithmName != null) {
            if (keyUnwrapAlgorithmName.equalsIgnoreCase("DES3")) {
                keyUnwrapAlgorithm = SymmetricKey.DES3;
            } else if (keyUnwrapAlgorithmName.equalsIgnoreCase("AES")) {
                keyUnwrapAlgorithm = SymmetricKey.AES;
            } else {
                System.err.println("ERROR:  Unsupported key unwrap algorithm '"
                        + keyUnwrapAlgorithmName + "'"
                        + NEWLINE);
                System.exit(1);
            }
            keyUnwrapAlgorithmName = SPACE + KEY_UNWRAP_ALGORITHM + SPACE + keyUnwrapAlgorithmName;
        } else {
            keyUnwrapAlgorithmName = "";
        }

        // Check for OPTIONAL "Process Requests and Key Records ONLY" option
        if (mProcessRequestsAndKeyRecordsOnlyFlag) {
            process_requests_and_key_records_only = SPACE
                                                  + PROCESS_REQUESTS_AND_KEY_RECORDS_ONLY;
            mProcessRequestsAndKeyRecordsOnlyMessage = SPACE + PLUS + SPACE +
                    KRA_LDIF_PROCESS_REQUESTS_AND_KEY_RECORDS_ONLY_MESSAGE;
        } else {
            process_requests_and_key_records_only = "";
            mProcessRequestsAndKeyRecordsOnlyMessage = "";
        }

        // Process RSA wrap algorithm flags with backward compatibility
        // legacy flag: -use_rsa_oaep_keywrap sets BOTH source and target to RSA-OAEP
        // cross-scheme flags: -source_rsa_wrap_algorithm and -target_rsa_wrap_algorithm allow separate control
        if (mUseOAEPKeyWrapAlg) {
            // Legacy flag - apply to both source and target if not explicitly overridden
            if (mSourceRSAWrapAlgName == null) {
                mSourceRSAWrapAlg = KeyWrapAlgorithm.RSA_OAEP;
                log("Using RSA-OAEP for source (from -use_rsa_oaep_keywrap)" + NEWLINE, false);
            }
            if (mTargetRSAWrapAlgName == null) {
                mTargetRSAWrapAlg = KeyWrapAlgorithm.RSA_OAEP;
                log("Using RSA-OAEP for target (from -use_rsa_oaep_keywrap)" + NEWLINE, false);
            }
        }

        // Process source RSA wrap algorithm
        if (mSourceRSAWrapAlgName != null) {
            if (mSourceRSAWrapAlgName.equalsIgnoreCase("RSA")) {
                mSourceRSAWrapAlg = KeyWrapAlgorithm.RSA;
            } else if (mSourceRSAWrapAlgName.equalsIgnoreCase("RSA_OAEP") ||
                       mSourceRSAWrapAlgName.equalsIgnoreCase("RSA-OAEP") ||
                       mSourceRSAWrapAlgName.equalsIgnoreCase("RSAES-OAEP")) {
                mSourceRSAWrapAlg = KeyWrapAlgorithm.RSA_OAEP;
            } else {
                System.err.println("ERROR: Unsupported source RSA wrap algorithm: " + mSourceRSAWrapAlgName +
                           " (must be RSA or RSA-OAEP)" + NEWLINE);
                System.exit(1);
            }
            System.out.println("Source RSA wrap algorithm: " + mSourceRSAWrapAlgName);
        } else {
            System.out.println("Source RSA wrap algorithm: RSA (default)");
        }

        // Process target RSA wrap algorithm
        if (mTargetRSAWrapAlgName != null) {
            if (mTargetRSAWrapAlgName.equalsIgnoreCase("RSA")) {
                mTargetRSAWrapAlg = KeyWrapAlgorithm.RSA;
            } else if (mTargetRSAWrapAlgName.equalsIgnoreCase("RSA_OAEP") ||
                       mTargetRSAWrapAlgName.equalsIgnoreCase("RSA-OAEP") ||
                       mTargetRSAWrapAlgName.equalsIgnoreCase("RSAES-OAEP")) {
                mTargetRSAWrapAlg = KeyWrapAlgorithm.RSA_OAEP;
            } else {
                System.err.println("ERROR: Unsupported target RSA wrap algorithm: " + mTargetRSAWrapAlgName +
                           " (must be RSA or RSA-OAEP)" + NEWLINE);
                System.exit(1);
            }
            System.out.println("Target RSA wrap algorithm: " + mTargetRSAWrapAlgName);
        } else {
            System.out.println("Target RSA wrap algorithm: RSA-OAEP (default)");
        }

        // cross-scheme: Log payload wrap algorithms if provided
        // Note: Validation happens at runtime in getPayloadWrapAlgorithm()
        if (mSourcePayloadWrapAlgName != null) {
            System.out.println("Source payload wrap algorithm: " + mSourcePayloadWrapAlgName);
        }
        if (mTargetPayloadWrapAlgName != null) {
            System.out.println("Target payload wrap algorithm: " + mTargetPayloadWrapAlgName);
        }

        // Build cross-scheme parameters string for logging
        String use_cross_scheme_params = "";
        if (mUseCrossSchemeFlag) {
            use_cross_scheme_params = SPACE + USE_CROSS_SCHEME;
            if (mSourceRSAWrapAlgName != null) {
                use_cross_scheme_params += SPACE + SOURCE_RSA_WRAP_ALGORITHM + SPACE + mSourceRSAWrapAlgName;
            }
            if (mTargetRSAWrapAlgName != null) {
                use_cross_scheme_params += SPACE + TARGET_RSA_WRAP_ALGORITHM + SPACE + mTargetRSAWrapAlgName;
            }
            if (mSourcePayloadWrapAlgName != null) {
                use_cross_scheme_params += SPACE + SOURCE_PAYLOAD_WRAP_ALGORITHM + SPACE + TIC + mSourcePayloadWrapAlgName + TIC;
            }
            // Always include source payload wrapping key size
            use_cross_scheme_params += SPACE + SOURCE_PAYLOAD_WRAP_KEYSIZE + SPACE + mSourcePayloadWrapKeySize;
            if (mTargetPayloadWrapAlgName != null) {
                use_cross_scheme_params += SPACE + TARGET_PAYLOAD_WRAP_ALGORITHM + SPACE + TIC + mTargetPayloadWrapAlgName + TIC;
            }
            // Always include target payload wrapping key size
            use_cross_scheme_params += SPACE + TARGET_PAYLOAD_WRAP_KEYSIZE + SPACE + mTargetPayloadWrapKeySize;
            if (mSourceHsmTokenPwdfile != null) {
                use_cross_scheme_params += SPACE + SOURCE_HSM_TOKEN_PWDFILE + SPACE + mSourceHsmTokenPwdfile;
            }
            if (mUseNssForPayloadProcessing) {
                use_cross_scheme_params += SPACE + USE_NSS_FOR_PAYLOAD_PROCESSING;
            }
            if (mRegenerateSessionKey) {
                use_cross_scheme_params += SPACE + REGENERATE_SESSION_KEY;
            }
            if (mSkipRewrap) {
                use_cross_scheme_params += SPACE + SKIP_REWRAP;
            }
            if (mSplitTargetLdifPerRecords > 0) {
                use_cross_scheme_params += SPACE + SPLIT_TARGET_LDIF_PER_RECORDS + SPACE + mSplitTargetLdifPerRecords;
            }
        }

        // Enable logging process . . .
        open_log(mLogFilename);

        // Begin logging progress . . .
        if (mRewrapFlag && mAppendIdOffsetFlag) {
            log("BEGIN \""
                    + KRA_TOOL + SPACE
                    + KRATOOL_CFG_FILE + SPACE
                    + mKratoolCfgFilename + SPACE
                    + SOURCE_LDIF_FILE + SPACE
                    + mSourceLdifFilename + SPACE
                    + TARGET_LDIF_FILE + SPACE
                    + mTargetLdifFilename + SPACE
                    + LOG_FILE + SPACE
                    + mLogFilename + SPACE
                    + SOURCE_NSS_DB_PATH + SPACE
                    + mSourcePKISecurityDatabasePath + SPACE
                    + SOURCE_STORAGE_TOKEN_NAME + SPACE
                    + TIC + mSourceStorageTokenName + TIC + SPACE
                    + SOURCE_STORAGE_CERT_NICKNAME + SPACE
                    + TIC + mSourceStorageCertNickname + TIC + SPACE
                    + TARGET_STORAGE_CERTIFICATE_FILE + SPACE
                    + mTargetStorageCertificateFilename + SPACE
                    + use_PKI_security_database_pwdfile
                    + APPEND_ID_OFFSET + SPACE
                    + append_id_offset
                    + process_kra_naming_context_fields
                    + process_requests_and_key_records_only
                    + keyUnwrapAlgorithmName
                    + use_cross_scheme_params
                    + "\" . . ."
                    + NEWLINE, true);
        } else if (mRewrapFlag && mRemoveIdOffsetFlag) {
            log("BEGIN \""
                    + KRA_TOOL + SPACE
                    + KRATOOL_CFG_FILE + SPACE
                    + mKratoolCfgFilename + SPACE
                    + SOURCE_LDIF_FILE + SPACE
                    + mSourceLdifFilename + SPACE
                    + TARGET_LDIF_FILE + SPACE
                    + mTargetLdifFilename + SPACE
                    + LOG_FILE + SPACE
                    + mLogFilename + SPACE
                    + SOURCE_NSS_DB_PATH + SPACE
                    + mSourcePKISecurityDatabasePath + SPACE
                    + SOURCE_STORAGE_TOKEN_NAME + SPACE
                    + TIC + mSourceStorageTokenName + TIC + SPACE
                    + SOURCE_STORAGE_CERT_NICKNAME + SPACE
                    + TIC + mSourceStorageCertNickname + TIC + SPACE
                    + TARGET_STORAGE_CERTIFICATE_FILE + SPACE
                    + mTargetStorageCertificateFilename + SPACE
                    + use_PKI_security_database_pwdfile
                    + REMOVE_ID_OFFSET + SPACE
                    + remove_id_offset
                    + process_kra_naming_context_fields
                    + process_requests_and_key_records_only
                    + keyUnwrapAlgorithmName
                    + use_cross_scheme_params
                    + "\" . . ."
                    + NEWLINE, true);
        } else if (mRewrapFlag) {
            log("BEGIN \""
                    + KRA_TOOL + SPACE
                    + KRATOOL_CFG_FILE + SPACE
                    + mKratoolCfgFilename + SPACE
                    + SOURCE_LDIF_FILE + SPACE
                    + mSourceLdifFilename + SPACE
                    + TARGET_LDIF_FILE + SPACE
                    + mTargetLdifFilename + SPACE
                    + LOG_FILE + SPACE
                    + mLogFilename + SPACE
                    + SOURCE_NSS_DB_PATH + SPACE
                    + mSourcePKISecurityDatabasePath + SPACE
                    + SOURCE_STORAGE_TOKEN_NAME + SPACE
                    + TIC + mSourceStorageTokenName + TIC + SPACE
                    + SOURCE_STORAGE_CERT_NICKNAME + SPACE
                    + TIC + mSourceStorageCertNickname + TIC + SPACE
                    + TARGET_STORAGE_CERTIFICATE_FILE + SPACE
                    + mTargetStorageCertificateFilename
                    + use_PKI_security_database_pwdfile
                    + process_kra_naming_context_fields
                    + process_requests_and_key_records_only
                    + keyUnwrapAlgorithmName
                    + use_cross_scheme_params
                    + "\" . . ."
                    + NEWLINE, true);
        } else if (mAppendIdOffsetFlag) {
            log("BEGIN \""
                    + KRA_TOOL + SPACE
                    + KRATOOL_CFG_FILE + SPACE
                    + mKratoolCfgFilename + SPACE
                    + SOURCE_LDIF_FILE + SPACE
                    + mSourceLdifFilename + SPACE
                    + TARGET_LDIF_FILE + SPACE
                    + mTargetLdifFilename + SPACE
                    + LOG_FILE + SPACE
                    + mLogFilename + SPACE
                    + APPEND_ID_OFFSET + SPACE
                    + append_id_offset
                    + process_kra_naming_context_fields
                    + process_requests_and_key_records_only
                    + "\" . . ."
                    + NEWLINE, true);
        } else if (mRemoveIdOffsetFlag) {
            log("BEGIN \""
                    + KRA_TOOL + SPACE
                    + KRATOOL_CFG_FILE + SPACE
                    + mKratoolCfgFilename + SPACE
                    + SOURCE_LDIF_FILE + SPACE
                    + mSourceLdifFilename + SPACE
                    + TARGET_LDIF_FILE + SPACE
                    + mTargetLdifFilename + SPACE
                    + LOG_FILE + SPACE
                    + mLogFilename + SPACE
                    + REMOVE_ID_OFFSET + SPACE
                    + remove_id_offset
                    + process_kra_naming_context_fields
                    + process_requests_and_key_records_only
                    + "\" . . ."
                    + NEWLINE, true);
        }

        // Process the KRATOOL config file
        success = process_kratool_config_file();
        if (!success) {
            log("FAILED processing kratool config file!"
                    + NEWLINE, true);
        } else {
            log("SUCCESSFULLY processed kratool config file!"
                    + NEWLINE, true);

            // Convert the source LDIF file to a target LDIF file
            // Use cross-scheme entry-based processing if flag is set
            if (mUseCrossSchemeFlag) {
                success = use_cross_scheme_convert_source_ldif_to_target_ldif();
            } else {
                success = convert_source_ldif_to_target_ldif();
            }
            if (!success) {
                log("FAILED converting source LDIF file --> target LDIF file!"
                        + NEWLINE, true);
            } else {
                log("SUCCESSFULLY converted source LDIF file --> "
                        + "target LDIF file!"
                        + NEWLINE, true);
                log("" + NEWLINE, true);
                // cross-scheme: Only print summary when using cross-scheme mode (baseline mode doesn't track counters)
                if (mUseCrossSchemeFlag) {
                    log("Summary: " + mProcessedKeyRecords + " key record(s) processed successfully, "
                            + mFailedKeyRecords + " failed."
                            + NEWLINE, true);
                    log("" + NEWLINE, true);
                }
                // Only print target LDIF filename if not in split mode (split mode already reported each file)
                if (mSplitTargetLdifPerRecords == 0) {
                    log("Target LDIF file: " + mTargetLdifFilename + NEWLINE, true);
                }
                log("Debug log file:   " + mLogFilename + NEWLINE, true);
            }
        }

        // Finish logging progress
        if (mRewrapFlag && mAppendIdOffsetFlag) {
            log("FINISHED \""
                    + KRA_TOOL + SPACE
                    + KRATOOL_CFG_FILE + SPACE
                    + mKratoolCfgFilename + SPACE
                    + SOURCE_LDIF_FILE + SPACE
                    + mSourceLdifFilename + SPACE
                    + TARGET_LDIF_FILE + SPACE
                    + mTargetLdifFilename + SPACE
                    + LOG_FILE + SPACE
                    + mLogFilename + SPACE
                    + SOURCE_NSS_DB_PATH + SPACE
                    + mSourcePKISecurityDatabasePath + SPACE
                    + SOURCE_STORAGE_TOKEN_NAME + SPACE
                    + TIC + mSourceStorageTokenName + TIC + SPACE
                    + SOURCE_STORAGE_CERT_NICKNAME + SPACE
                    + TIC + mSourceStorageCertNickname + TIC + SPACE
                    + TARGET_STORAGE_CERTIFICATE_FILE + SPACE
                    + mTargetStorageCertificateFilename + SPACE
                    + use_PKI_security_database_pwdfile
                    + APPEND_ID_OFFSET + SPACE
                    + append_id_offset
                    + process_kra_naming_context_fields
                    + process_requests_and_key_records_only
                    + keyUnwrapAlgorithmName
                    + use_cross_scheme_params
                    + "\"."
                    + NEWLINE, true);
        } else if (mRewrapFlag && mRemoveIdOffsetFlag) {
            log("FINISHED \""
                    + KRA_TOOL + SPACE
                    + KRATOOL_CFG_FILE + SPACE
                    + mKratoolCfgFilename + SPACE
                    + SOURCE_LDIF_FILE + SPACE
                    + mSourceLdifFilename + SPACE
                    + TARGET_LDIF_FILE + SPACE
                    + mTargetLdifFilename + SPACE
                    + LOG_FILE + SPACE
                    + mLogFilename + SPACE
                    + SOURCE_NSS_DB_PATH + SPACE
                    + mSourcePKISecurityDatabasePath + SPACE
                    + SOURCE_STORAGE_TOKEN_NAME + SPACE
                    + TIC + mSourceStorageTokenName + TIC + SPACE
                    + SOURCE_STORAGE_CERT_NICKNAME + SPACE
                    + TIC + mSourceStorageCertNickname + TIC + SPACE
                    + TARGET_STORAGE_CERTIFICATE_FILE + SPACE
                    + mTargetStorageCertificateFilename + SPACE
                    + use_PKI_security_database_pwdfile
                    + REMOVE_ID_OFFSET + SPACE
                    + remove_id_offset
                    + process_kra_naming_context_fields
                    + process_requests_and_key_records_only
                    + keyUnwrapAlgorithmName
                    + use_cross_scheme_params
                    + "\"."
                    + NEWLINE, true);
        } else if (mRewrapFlag) {
            log("FINISHED \""
                    + KRA_TOOL + SPACE
                    + KRATOOL_CFG_FILE + SPACE
                    + mKratoolCfgFilename + SPACE
                    + SOURCE_LDIF_FILE + SPACE
                    + mSourceLdifFilename + SPACE
                    + TARGET_LDIF_FILE + SPACE
                    + mTargetLdifFilename + SPACE
                    + LOG_FILE + SPACE
                    + mLogFilename + SPACE
                    + SOURCE_NSS_DB_PATH + SPACE
                    + mSourcePKISecurityDatabasePath + SPACE
                    + SOURCE_STORAGE_TOKEN_NAME + SPACE
                    + TIC + mSourceStorageTokenName + TIC + SPACE
                    + SOURCE_STORAGE_CERT_NICKNAME + SPACE
                    + TIC + mSourceStorageCertNickname + TIC + SPACE
                    + TARGET_STORAGE_CERTIFICATE_FILE + SPACE
                    + mTargetStorageCertificateFilename
                    + use_PKI_security_database_pwdfile
                    + process_kra_naming_context_fields
                    + process_requests_and_key_records_only
                    + keyUnwrapAlgorithmName
                    + use_cross_scheme_params
                    + "\"."
                    + NEWLINE, true);
        } else if (mAppendIdOffsetFlag) {
            log("FINISHED \""
                    + KRA_TOOL + SPACE
                    + KRATOOL_CFG_FILE + SPACE
                    + mKratoolCfgFilename + SPACE
                    + SOURCE_LDIF_FILE + SPACE
                    + mSourceLdifFilename + SPACE
                    + TARGET_LDIF_FILE + SPACE
                    + mTargetLdifFilename + SPACE
                    + LOG_FILE + SPACE
                    + mLogFilename + SPACE
                    + APPEND_ID_OFFSET + SPACE
                    + append_id_offset
                    + process_kra_naming_context_fields
                    + process_requests_and_key_records_only
                    + "\"."
                    + NEWLINE, true);
        } else if (mRemoveIdOffsetFlag) {
            log("FINISHED \""
                    + KRA_TOOL + SPACE
                    + KRATOOL_CFG_FILE + SPACE
                    + mKratoolCfgFilename + SPACE
                    + SOURCE_LDIF_FILE + SPACE
                    + mSourceLdifFilename + SPACE
                    + TARGET_LDIF_FILE + SPACE
                    + mTargetLdifFilename + SPACE
                    + LOG_FILE + SPACE
                    + mLogFilename + SPACE
                    + REMOVE_ID_OFFSET + SPACE
                    + remove_id_offset
                    + process_kra_naming_context_fields
                    + process_requests_and_key_records_only
                    + "\"."
                    + NEWLINE, true);
        }

        // Shutdown logging process
        close_log(mLogFilename);
    }
}
