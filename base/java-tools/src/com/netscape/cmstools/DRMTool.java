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
// (C) 2011 Red Hat, Inc.
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
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Vector;
import java.util.regex.PatternSyntaxException;

import netscape.security.provider.RSAPublicKey;
import netscape.security.util.DerInputStream;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;
import netscape.security.x509.X509CertImpl;

import org.mozilla.jss.CertDatabaseException;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.KeyDatabaseException;
import org.mozilla.jss.crypto.AlreadyInitializedException;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.InvalidKeyFormatException;
import org.mozilla.jss.crypto.KeyWrapAlgorithm;
import org.mozilla.jss.crypto.KeyWrapper;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.TokenCertificate;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.pkcs11.PK11PubKey;
import org.mozilla.jss.util.Password;

import com.netscape.cmsutil.util.Utils;

/**
 * The DRMTool class is a utility program designed to operate on an LDIF file
 * to perform one or more of the following tasks:
 *
 * <PRE>
 *     (A) Use a new storage key (e. g. - a 2048-bit key to replace a
 *         1024-bit key) to rewrap the existing triple DES symmetric key
 *         that was used to wrap a user's private key.
 *
 *         STARTING INVENTORY:
 *
 *             (1) a DRMTOOL configuration file containing DRM LDIF record
 *                 types and the processing status of their associated fields
 *
 *             (2) an LDIF file containing 'exported' DRM data
 *                 (referred to as the "source" DRM)
 *
 *                 NOTE:  If this LDIF file contains data that was originally
 *                        from a DRM instance that was prior to RHCS 8, it
 *                        must have previously undergone the appropriate
 *                        migration steps.
 *
 *             (3) the NSS security databases (e. g. - cert8.db, key3.db,
 *                 and secmod.db) associated with the data contained in
 *                 the source LDIF file
 *
 *                 NOTE:  If the storage key was located on an HSM, then the
 *                        HSM must be available to the machine on which the
 *                        DRMTool is being executed (since the RSA private
 *                        storage key is required for unwrapping the
 *                        symmetric triple DES key).  Additionally, a
 *                        password may be required to unlock access to
 *                        this key (e. g. - which may be located in
 *                        the source DRM's 'password.conf' file).
 *
 *             (4) a file containing the ASCII BASE-64 storage certificate
 *                 from the DRM instance for which the output LDIF file is
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
 *                 'import' into a new DRM (referred to as the "target" DRM)
 *
 *         DRMTool PARAMETERS:
 *
 *             (1) the name of the DRMTOOL configuration file containing
 *                 DRM LDIF record types and the processing status of their
 *                 associated fields
 *
 *             (2) the name of the input LDIF file containing data which was
 *                 'exported' from the source DRM instance
 *
 *             (3) the name of the output LDIF file intended to contain the
 *                 revised data suitable for 'import' to a target DRM instance
 *
 *             (4) the name of the log file that may be used for auditing
 *                 purposes
 *
 *             (5) the path to the security databases that were used by
 *                 the source DRM instance
 *
 *             (6) the name of the token that was used by
 *                 the source DRM instance
 *
 *             (7) the name of the storage certificate that was used by
 *                 the source DRM instance
 *
 *             (8) the name of the file containing the ASCII BASE-64 storage
 *                 certificate from the target DRM instance for which the
 *                 output LDIF file is intended
 *
 *             (9) OPTIONALLY, the name of a file which ONLY contains the
 *                 password needed to access the source DRM instance's
 *                 security databases
 *
 *            (10) OPTIONALLY, choose to change the specified source DRM naming
 *                 context to the specified target DRM naming context
 *
 *            (11) OPTIONALLY, choose to ONLY process CA enrollment requests,
 *                 CA recovery requests, CA key records, TPS netkeyKeygen
 *                 enrollment requests, TPS recovery requests, and
 *                 TPS key records
 *
 *         DATA FIELDS AFFECTED (using default config file values):
 *
 *             (1) CA DRM enrollment request
 *
 *                 (a) dateOfModify
 *                 (b) extdata-requestnotes
 *
 *             (2) CA DRM key record
 *
 *                 (a) dateOfModify
 *                 (b) privateKeyData
 *
 *             (3) CA DRM recovery request
 *
 *                 (a) dateOfModify
 *                 (b) extdata-requestnotes (NEW)
 *
 *             (4) TPS DRM netkeyKeygen (enrollment) request
 *
 *                 (a) dateOfModify
 *                 (b) extdata-requestnotes (NEW)
 *
 *             (5) TPS DRM key record
 *
 *                 (a) dateOfModify
 *                 (b) privateKeyData
 *
 *             (6) TPS DRM recovery request
 *
 *                 (a) dateOfModify
 *                 (b) extdata-requestnotes (NEW)
 *
 *     (B) Specify an ID offset to append to existing numeric data
 *         (e. g. - to renumber data for use in DRM consolidation efforts).
 *
 *         STARTING INVENTORY:
 *
 *             (1) a DRMTOOL configuration file containing DRM LDIF record
 *                 types and the processing status of their associated fields
 *
 *             (2) an LDIF file containing 'exported' DRM data
 *                 (referred to as the "source" DRM)
 *
 *                 NOTE:  If this LDIF file contains data that was originally
 *                        from a DRM instance that was prior to RHCS 8, it
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
 *                 'import' into a new DRM (referred to as the "target" DRM)
 *
 *         DRMTool PARAMETERS:
 *
 *             (1) the name of the DRMTOOL configuration file containing
 *                 DRM LDIF record types and the processing status of their
 *                 associated fields
 *
 *             (2) the name of the input LDIF file containing data which was
 *                 'exported' from the source DRM instance
 *
 *             (3) the name of the output LDIF file intended to contain the
 *                 revised data suitable for 'import' to a target DRM instance
 *
 *             (4) the name of the log file that may be used for auditing
 *                 purposes
 *
 *             (5) a large numeric ID offset (mask) to be appended to existing
 *                 numeric data in the source DRM instance's LDIF file
 *
 *             (6) OPTIONALLY, choose to change the specified source DRM naming
 *                 context to the specified target DRM naming context
 *
 *             (7) OPTIONALLY, choose to ONLY process CA enrollment requests,
 *                 CA recovery requests, CA key records, TPS netkeyKeygen
 *                 enrollment requests, TPS recovery requests, and
 *                 TPS key records
 *
 *         DATA FIELDS AFFECTED (using default config file values):
 *
 *             (1) CA DRM enrollment request
 *
 *                 (a) cn
 *                 (b) dateOfModify
 *                 (c) extdata-keyrecord
 *                 (d) extdata-requestnotes
 *                 (e) requestId
 *
 *             (2) CA DRM key record
 *
 *                 (a) cn
 *                 (b) dateOfModify
 *                 (c) serialno
 *
 *             (3) CA DRM recovery request
 *
 *                 (a) cn
 *                 (b) dateOfModify
 *                 (c) extdata-requestid
 *                 (d) extdata-requestnotes (NEW)
 *                 (e) extdata-serialnumber
 *                 (f) requestId
 *
 *             (4) TPS DRM netkeyKeygen (enrollment) request
 *
 *                 (a) cn
 *                 (b) dateOfModify
 *                 (c) extdata-keyrecord
 *                 (d) extdata-requestid
 *                 (e) extdata-requestnotes (NEW)
 *                 (f) requestId
 *
 *             (5) TPS DRM key record
 *
 *                 (a) cn
 *                 (b) dateOfModify
 *                 (c) serialno
 *
 *             (6) TPS DRM recovery request
 *
 *                 (a) cn
 *                 (b) dateOfModify
 *                 (c) extdata-requestid
 *                 (d) extdata-requestnotes (NEW)
 *                 (e) extdata-serialnumber
 *                 (f) requestId
 *
 *     (C) Specify an ID offset to be removed from existing numeric data
 *         (e. g. - to undo renumbering used in DRM consolidation efforts).
 *
 *         STARTING INVENTORY:
 *
 *             (1) a DRMTOOL configuration file containing DRM LDIF record
 *                 types and the processing status of their associated fields
 *
 *             (2) an LDIF file containing 'exported' DRM data
 *                 (referred to as the "source" DRM)
 *
 *                 NOTE:  If this LDIF file contains data that was originally
 *                        from a DRM instance that was prior to RHCS 8, it
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
 *                 'import' into a new DRM (referred to as the "target" DRM)
 *
 *         DRMTool PARAMETERS:
 *
 *             (1) the name of the DRMTOOL configuration file containing
 *                 DRM LDIF record types and the processing status of their
 *                 associated fields
 *
 *             (2) the name of the input LDIF file containing data which was
 *                 'exported' from the source DRM instance
 *
 *             (3) the name of the output LDIF file intended to contain the
 *                 revised data suitable for 'import' to a target DRM instance
 *
 *             (4) the name of the log file that may be used for auditing
 *                 purposes
 *
 *             (5) a large numeric ID offset (mask) to be removed from existing
 *                 numeric data in the source DRM instance's LDIF file
 *
 *             (6) OPTIONALLY, choose to change the specified source DRM naming
 *                 context to the specified target DRM naming context
 *
 *             (7) OPTIONALLY, choose to ONLY process CA enrollment requests,
 *                 CA recovery requests, CA key records, TPS netkeyKeygen
 *                 enrollment requests, TPS recovery requests, and
 *                 TPS key records
 *
 *         DATA FIELDS AFFECTED (using default config file values):
 *
 *             (1) CA DRM enrollment request
 *
 *                 (a) cn
 *                 (b) dateOfModify
 *                 (c) extdata-keyrecord
 *                 (d) extdata-requestnotes
 *                 (e) requestId
 *
 *             (2) CA DRM key record
 *
 *                 (a) cn
 *                 (b) dateOfModify
 *                 (c) serialno
 *
 *             (3) CA DRM recovery request
 *
 *                 (a) cn
 *                 (b) dateOfModify
 *                 (c) extdata-requestid
 *                 (d) extdata-requestnotes (NEW)
 *                 (e) extdata-serialnumber
 *                 (f) requestId
 *
 *             (4) TPS DRM netkeyKeygen (enrollment) request
 *
 *                 (a) cn
 *                 (b) dateOfModify
 *                 (c) extdata-keyrecord
 *                 (d) extdata-requestid
 *                 (e) extdata-requestnotes (NEW)
 *                 (f) requestId
 *
 *             (5) TPS DRM key record
 *
 *                 (a) cn
 *                 (b) dateOfModify
 *                 (c) serialno
 *
 *             (6) TPS DRM recovery request
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
 * DRMTool may be invoked as follows:
 *
 * <PRE>
 *
 *    DRMTool
 *    -drmtool_config_file &lt;path + drmtool config file&gt;
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
 *    [-source_drm_naming_context '&lt;original source DRM naming context&gt;']
 *    [-target_drm_naming_context '&lt;renamed target DRM naming context&gt;']
 *    [-process_requests_and_key_records_only]
 *
 *    where the following options are 'Mandatory':
 *
 *    -drmtool_config_file &lt;path + drmtool config file&gt;
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
 *            the password needed to access the source DRM instance's
 *            security databases:
 *
 *            [-source_pki_security_database_pwdfile
 *             &lt;path to PKI password file&gt;]
 *
 *            AND OPTIONALLY, rename source DRM naming context --> target
 *            DRM naming context:
 *
 *            [-source_drm_naming_context '&lt;source DRM naming context&gt;']
 *            [-target_drm_naming_context '&lt;target DRM naming context&gt;']
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
 *            AND OPTIONALLY, rename source DRM naming context --> target
 *            DRM naming context:
 *
 *            [-source_drm_naming_context '&lt;source DRM naming context&gt;']
 *            [-target_drm_naming_context '&lt;target DRM naming context&gt;']
 *
 *            AND OPTIONALLY, process requests and key records ONLY:
 *
 *            [-process_requests_and_key_records_only]
 *
 *        (c) option for removing the specified numeric ID offset
 *            from existing numerical data:
 *
 *            AND OPTIONALLY, rename source DRM naming context --> target
 *            DRM naming context:
 *
 *            [-source_drm_naming_context '&lt;source DRM naming context&gt;']
 *            [-target_drm_naming_context '&lt;target DRM naming context&gt;']
 *
 *            [-remove_id_offset &lt;numeric offset&gt;]
 *
 *            AND OPTIONALLY, process requests and key records ONLY:
 *
 *            [-process_requests_and_key_records_only]
 *
 *        (d) (a) rewrap AND (b) append ID offset
 *            [AND OPTIONALLY, rename source DRM naming context --> target
 *            DRM naming context]
 *            [AND OPTIONALLY process requests and key records ONLY]
 *
 *        (e) (a) rewrap AND (c) remove ID offset
 *            [AND OPTIONALLY, rename source DRM naming context --> target
 *            DRM naming context]
 *            [AND OPTIONALLY process requests and key records ONLY]
 *
 *        NOTE:  Options (b) and (c) are mutually exclusive!
 *
 * </PRE>
 *
 * @author mharmsen
 * @version $Revision$, $Date$
 */
public class DRMTool {
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

    // Constants:  PKCS #11 Information
    private static final String INTERNAL_TOKEN = "Internal Key Storage Token";

    // Constants:  Command-line Options
    private static final int ID_OFFSET_NAME_VALUE_PAIRS = 1;
    private static final int PWDFILE_NAME_VALUE_PAIRS = 1;
    private static final int NAMING_CONTEXT_NAME_VALUE_PAIRS = 2;
    private static final int MANDATORY_NAME_VALUE_PAIRS = 4;
    private static final int REWRAP_NAME_VALUE_PAIRS = 4;
    private static final int ID_OFFSET_ARGS = 10;
    private static final int REWRAP_ARGS = 16;
    private static final int REWRAP_AND_ID_OFFSET_ARGS = 18;

    // Constants:  Command-line Options (Mandatory)
    private static final String DRM_TOOL = "DRMTool";

    private static final String DRMTOOL_CFG_FILE = "-drmtool_config_file";

    private static final String DRMTOOL_CFG_DESCRIPTION = " <complete path to the drmtool config file"
                            + NEWLINE
                            + "        "
                            + "  ending with the drmtool config file name>";

    private static final String DRMTOOL_CFG_FILE_EXAMPLE = DRMTOOL_CFG_FILE
                             + " "
                             + "/usr/share/pki/java-tools/DRMTool.cfg";

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
                     + "/export/pki/DRMTool.log";

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
                                      + "Internal Key Storage Token"
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
    private static final String SOURCE_DRM_NAMING_CONTEXT = "-source_drm_naming_context";

    private static final String SOURCE_DRM_NAMING_CONTEXT_DESCRIPTION = "  <source DRM naming context>";

    private static final String SOURCE_DRM_NAMING_CONTEXT_EXAMPLE = SOURCE_DRM_NAMING_CONTEXT
                                      + " "
                                      + TIC
                                      + "alpha.example.com-pki-kra"
                                      + TIC;

    private static final String TARGET_DRM_NAMING_CONTEXT = "-target_drm_naming_context";

    private static final String TARGET_DRM_NAMING_CONTEXT_DESCRIPTION = "  <target DRM naming context>";

    private static final String TARGET_DRM_NAMING_CONTEXT_EXAMPLE = TARGET_DRM_NAMING_CONTEXT
                                      + " "
                                      + TIC
                                      + "omega.example.com-pki-kra"
                                      + TIC;

    private static final String PROCESS_REQUESTS_AND_KEY_RECORDS_ONLY =
            "-process_requests_and_key_records_only";

    // Constants:  DRMTOOL Config File
    private static final String DRMTOOL_CFG_PREFIX = "drmtool.ldif";
    private static final String DRMTOOL_CFG_ENROLLMENT = "caEnrollmentRequest";
    private static final String DRMTOOL_CFG_CA_KEY_RECORD = "caKeyRecord";
    private static final String DRMTOOL_CFG_RECOVERY = "recoveryRequest";
    private static final String DRMTOOL_CFG_TPS_KEY_RECORD = "tpsKeyRecord";
    private static final String DRMTOOL_CFG_KEYGEN = "tpsNetkeyKeygenRequest";

    // Constants:  DRMTOOL Config File (DRM CA Enrollment Request Fields)
    private static final String DRMTOOL_CFG_ENROLLMENT_CN = DRMTOOL_CFG_PREFIX
                                  + DOT
                                  + DRMTOOL_CFG_ENROLLMENT
                                  + DOT
                                  + "cn";
    private static final String DRMTOOL_CFG_ENROLLMENT_DATE_OF_MODIFY = DRMTOOL_CFG_PREFIX
                                              + DOT
                                              + DRMTOOL_CFG_ENROLLMENT
                                              + DOT
                                              + "dateOfModify";
    private static final String DRMTOOL_CFG_ENROLLMENT_DN = DRMTOOL_CFG_PREFIX
                                  + DOT
                                  + DRMTOOL_CFG_ENROLLMENT
                                  + DOT
                                  + "dn";
    private static final String DRMTOOL_CFG_ENROLLMENT_EXTDATA_KEY_RECORD = DRMTOOL_CFG_PREFIX
                                                  + DOT
                                                  + DRMTOOL_CFG_ENROLLMENT
                                                  + DOT
                                                  + "extdata.keyRecord";
    private static final String DRMTOOL_CFG_ENROLLMENT_EXTDATA_REQUEST_NOTES = DRMTOOL_CFG_PREFIX
                                                     + DOT
                                                     + DRMTOOL_CFG_ENROLLMENT
                                                     + DOT
                                                     + "extdata.requestNotes";
    private static final String DRMTOOL_CFG_ENROLLMENT_REQUEST_ID = DRMTOOL_CFG_PREFIX
                                          + DOT
                                          + DRMTOOL_CFG_ENROLLMENT
                                          + DOT
                                          + "requestId";

    // Constants:  DRMTOOL Config File (DRM CA Key Record Fields)
    private static final String DRMTOOL_CFG_CA_KEY_RECORD_CN = DRMTOOL_CFG_PREFIX
                                     + DOT
                                     + DRMTOOL_CFG_CA_KEY_RECORD
                                     + DOT
                                     + "cn";
    private static final String DRMTOOL_CFG_CA_KEY_RECORD_DATE_OF_MODIFY = DRMTOOL_CFG_PREFIX
                                                 + DOT
                                                 + DRMTOOL_CFG_CA_KEY_RECORD
                                                 + DOT
                                                 + "dateOfModify";
    private static final String DRMTOOL_CFG_CA_KEY_RECORD_DN = DRMTOOL_CFG_PREFIX
                                     + DOT
                                     + DRMTOOL_CFG_ENROLLMENT
                                     + DOT
                                     + "dn";
    private static final String DRMTOOL_CFG_CA_KEY_RECORD_PRIVATE_KEY_DATA = DRMTOOL_CFG_PREFIX
                                                   + DOT
                                                   + DRMTOOL_CFG_CA_KEY_RECORD
                                                   + DOT
                                                   + "privateKeyData";
    private static final String DRMTOOL_CFG_CA_KEY_RECORD_SERIAL_NO = DRMTOOL_CFG_PREFIX
                                            + DOT
                                            + DRMTOOL_CFG_CA_KEY_RECORD
                                            + DOT
                                            + "serialno";

    // Constants:  DRMTOOL Config File (DRM CA / TPS Recovery Request Fields)
    private static final String DRMTOOL_CFG_RECOVERY_CN = DRMTOOL_CFG_PREFIX
                                + DOT
                                + DRMTOOL_CFG_RECOVERY
                                + DOT
                                + "cn";
    private static final String DRMTOOL_CFG_RECOVERY_DATE_OF_MODIFY = DRMTOOL_CFG_PREFIX
                                            + DOT
                                            + DRMTOOL_CFG_RECOVERY
                                            + DOT
                                            + "dateOfModify";
    private static final String DRMTOOL_CFG_RECOVERY_DN = DRMTOOL_CFG_PREFIX
                                + DOT
                                + DRMTOOL_CFG_RECOVERY
                                + DOT
                                + "dn";
    private static final String DRMTOOL_CFG_RECOVERY_EXTDATA_REQUEST_ID = DRMTOOL_CFG_PREFIX
                                                + DOT
                                                + DRMTOOL_CFG_RECOVERY
                                                + DOT
                                                + "extdata.requestId";
    private static final String DRMTOOL_CFG_RECOVERY_EXTDATA_REQUEST_NOTES = DRMTOOL_CFG_PREFIX
                                                   + DOT
                                                   + DRMTOOL_CFG_RECOVERY
                                                   + DOT
                                                   + "extdata.requestNotes";
    private static final String DRMTOOL_CFG_RECOVERY_EXTDATA_SERIAL_NUMBER = DRMTOOL_CFG_PREFIX
                                                   + DOT
                                                   + DRMTOOL_CFG_RECOVERY
                                                   + DOT
                                                   + "extdata.serialnumber";
    private static final String DRMTOOL_CFG_RECOVERY_REQUEST_ID = DRMTOOL_CFG_PREFIX
                                        + DOT
                                        + DRMTOOL_CFG_RECOVERY
                                        + DOT
                                        + "requestId";

    // Constants:  DRMTOOL Config File (DRM TPS Key Record Fields)
    private static final String DRMTOOL_CFG_TPS_KEY_RECORD_CN = DRMTOOL_CFG_PREFIX
                                      + DOT
                                      + DRMTOOL_CFG_TPS_KEY_RECORD
                                      + DOT
                                      + "cn";
    private static final String DRMTOOL_CFG_TPS_KEY_RECORD_DATE_OF_MODIFY = DRMTOOL_CFG_PREFIX
                                                  + DOT
                                                  + DRMTOOL_CFG_TPS_KEY_RECORD
                                                  + DOT
                                                  + "dateOfModify";
    private static final String DRMTOOL_CFG_TPS_KEY_RECORD_DN = DRMTOOL_CFG_PREFIX
                                      + DOT
                                      + DRMTOOL_CFG_TPS_KEY_RECORD
                                      + DOT
                                      + "dn";
    private static final String DRMTOOL_CFG_TPS_KEY_RECORD_PRIVATE_KEY_DATA = DRMTOOL_CFG_PREFIX
                                                    + DOT
                                                    + DRMTOOL_CFG_TPS_KEY_RECORD
                                                    + DOT
                                                    + "privateKeyData";
    private static final String DRMTOOL_CFG_TPS_KEY_RECORD_SERIAL_NO = DRMTOOL_CFG_PREFIX
                                             + DOT
                                             + DRMTOOL_CFG_TPS_KEY_RECORD
                                             + DOT
                                             + "serialno";

    // Constants:  DRMTOOL Config File (DRM TPS Netkey Keygen Request Fields)
    private static final String DRMTOOL_CFG_KEYGEN_CN = DRMTOOL_CFG_PREFIX
                              + DOT
                              + DRMTOOL_CFG_KEYGEN
                              + DOT
                              + "cn";
    private static final String DRMTOOL_CFG_KEYGEN_DATE_OF_MODIFY = DRMTOOL_CFG_PREFIX
                                          + DOT
                                          + DRMTOOL_CFG_KEYGEN
                                          + DOT
                                          + "dateOfModify";
    private static final String DRMTOOL_CFG_KEYGEN_DN = DRMTOOL_CFG_PREFIX
                              + DOT
                              + DRMTOOL_CFG_KEYGEN
                              + DOT
                              + "dn";
    private static final String DRMTOOL_CFG_KEYGEN_EXTDATA_KEY_RECORD = DRMTOOL_CFG_PREFIX
                                              + DOT
                                              + DRMTOOL_CFG_KEYGEN
                                              + DOT
                                              + "extdata.keyRecord";
    private static final String DRMTOOL_CFG_KEYGEN_EXTDATA_REQUEST_ID = DRMTOOL_CFG_PREFIX
                                              + DOT
                                              + DRMTOOL_CFG_KEYGEN
                                              + DOT
                                              + "extdata.requestId";
    private static final String DRMTOOL_CFG_KEYGEN_EXTDATA_REQUEST_NOTES = DRMTOOL_CFG_PREFIX
                                                 + DOT
                                                 + DRMTOOL_CFG_KEYGEN
                                                 + DOT
                                                 + "extdata.requestNotes";
    private static final String DRMTOOL_CFG_KEYGEN_REQUEST_ID = DRMTOOL_CFG_PREFIX
                                      + DOT
                                      + DRMTOOL_CFG_KEYGEN
                                      + DOT
                                      + "requestId";

    // Constants:  Target Certificate Information
    private static final String HEADER = "-----BEGIN";
    private static final String TRAILER = "-----END";

    // Constants:  DRM LDIF Record Fields
    private static final String DRM_LDIF_ARCHIVED_BY = "archivedBy:";
    private static final String DRM_LDIF_CN = "cn:";
    private static final String DRM_LDIF_DATE_OF_MODIFY = "dateOfModify:";
    private static final String DRM_LDIF_DN = "dn:";
    private static final String DRM_LDIF_DN_EMBEDDED_CN_DATA = "dn: cn";
    private static final String DRM_LDIF_EXTDATA_AUTH_TOKEN_USER = "extdata-auth--005ftoken;user:";
    private static final String DRM_LDIF_EXTDATA_AUTH_TOKEN_USER_DN = "extdata-auth--005ftoken;userdn:";
    private static final String DRM_LDIF_EXTDATA_KEY_RECORD = "extdata-keyrecord:";
    private static final String DRM_LDIF_EXTDATA_REQUEST_ID = "extdata-requestid:";
    private static final String DRM_LDIF_EXTDATA_REQUEST_NOTES = "extdata-requestnotes:";
    private static final String DRM_LDIF_EXTDATA_REQUEST_TYPE = "extdata-requesttype:";
    private static final String DRM_LDIF_EXTDATA_SERIAL_NUMBER = "extdata-serialnumber:";
    private static final String DRM_LDIF_PRIVATE_KEY_DATA = "privateKeyData::";
    private static final String DRM_LDIF_REQUEST_ID = "requestId:";
    private static final String DRM_LDIF_REQUEST_TYPE = "requestType:";
    private static final String DRM_LDIF_SERIAL_NO = "serialno:";

    // Constants:  DRM LDIF Record Values
    private static final int INITIAL_LDIF_RECORD_CAPACITY = 0;
    private static final int EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH = 56;
    private static final int PRIVATE_KEY_DATA_FIRST_LINE_DATA_LENGTH = 60;
    private static final String DRM_LDIF_RECORD = "Generic";
    private static final String DRM_LDIF_CA_KEY_RECORD = "CA";
    private static final String DRM_LDIF_ENROLLMENT = "enrollment";
    private static final String DRM_LDIF_KEYGEN = "netkeyKeygen";
    private static final String DRM_LDIF_RECOVERY = "recovery";
    private static final String DRM_LDIF_TPS_KEY_RECORD = "TPS";

    // Constants:  DRM LDIF Record Messages
    private static final String DRM_LDIF_REWRAP_MESSAGE = "REWRAPPED the '"
                                                         + "existing DES3 "
                                                         + "symmetric "
                                                         + "session key"
                                                         + "' with the '";
    private static final String DRM_LDIF_RSA_MESSAGE = "-bit RSA public key' "
                                                     + "obtained from the "
                                                     + "target storage "
                                                     + "certificate";
    private static final String DRM_LDIF_USED_PWDFILE_MESSAGE =
                                    "USED source PKI security database "
                                            + "password file";
    private static final String DRM_LDIF_APPENDED_ID_OFFSET_MESSAGE =
                                    "APPENDED ID offset";
    private static final String DRM_LDIF_REMOVED_ID_OFFSET_MESSAGE =
                                    "REMOVED ID offset";
    private static final String DRM_LDIF_SOURCE_NAME_CONTEXT_MESSAGE =
                                    "RENAMED source DRM naming context '";
    private static final String DRM_LDIF_TARGET_NAME_CONTEXT_MESSAGE =
                                    "' to target DRM naming context '";
    private static final String DRM_LDIF_PROCESS_REQUESTS_AND_KEY_RECORDS_ONLY_MESSAGE =
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
    private static boolean mDrmNamingContextsFlag = false;
    private static boolean mProcessRequestsAndKeyRecordsOnlyFlag = false;
    private static int mMandatoryNameValuePairs = 0;
    private static int mRewrapNameValuePairs = 0;
    private static int mPKISecurityDatabasePwdfileNameValuePairs = 0;
    private static int mAppendIdOffsetNameValuePairs = 0;
    private static int mRemoveIdOffsetNameValuePairs = 0;
    private static int mDrmNamingContextNameValuePairs = 0;

    // Variables: Command-Line Values (Mandatory)
    private static String mDrmtoolCfgFilename = null;
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

    // Variables: Command-Line Values (ID Offset)
    private static BigInteger mAppendIdOffset = null;
    private static BigInteger mRemoveIdOffset = null;

    // Variables: Command-Line Values (DRM Naming Contexts)
    private static String mSourceDrmNamingContext = null;
    private static String mTargetDrmNamingContext = null;

    // Variables:  DRMTOOL Config File Parameters of Interest
    private static Hashtable<String, Boolean> drmtoolCfg = null;

    // Variables:  DRMTOOL LDIF File Parameters of Interest
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

    // Variables:  DRM LDIF Record Messages
    private static String mSourcePKISecurityDatabasePwdfileMessage = null;
    private static String mDrmNamingContextMessage = null;
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
     * execute DRMTool.
     */
    private static void printUsage() {
        System.out.println("Usage:  "
                          + DRM_TOOL
                          + NEWLINE
                          + "        "
                          + DRMTOOL_CFG_FILE
                          + NEWLINE
                          + "        "
                          + DRMTOOL_CFG_DESCRIPTION
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
                          + SOURCE_DRM_NAMING_CONTEXT
                          + NEWLINE
                          + "        "
                          + SOURCE_DRM_NAMING_CONTEXT_DESCRIPTION
                          + "]"
                          + NEWLINE
                          + "        "
                          + "["
                          + TARGET_DRM_NAMING_CONTEXT
                          + NEWLINE
                          + "        "
                          + TARGET_DRM_NAMING_CONTEXT_DESCRIPTION
                          + "]"
                          + NEWLINE
                          + "        "
                          + "["
                          + PROCESS_REQUESTS_AND_KEY_RECORDS_ONLY
                          + "]"
                          + NEWLINE);

        System.out.println("Example of 'Rewrap and Append ID Offset':"
                          + NEWLINE
                          + NEWLINE
                          + "        "
                          + DRM_TOOL
                          + NEWLINE
                          + "        "
                          + DRMTOOL_CFG_FILE_EXAMPLE
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
                          + APPEND_ID_OFFSET_EXAMPLE
                          + NEWLINE
                          + "        "
                          + SOURCE_DRM_NAMING_CONTEXT_EXAMPLE
                          + NEWLINE
                          + "        "
                          + TARGET_DRM_NAMING_CONTEXT_EXAMPLE
                          + NEWLINE
                          + "        "
                          + PROCESS_REQUESTS_AND_KEY_RECORDS_ONLY
                          + NEWLINE);

        System.out.println("Example of 'Rewrap and Remove ID Offset':"
                          + NEWLINE
                          + NEWLINE
                          + "        "
                          + DRM_TOOL
                          + NEWLINE
                          + "        "
                          + DRMTOOL_CFG_FILE_EXAMPLE
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
                          + SOURCE_DRM_NAMING_CONTEXT_EXAMPLE
                          + NEWLINE
                          + "        "
                          + TARGET_DRM_NAMING_CONTEXT_EXAMPLE
                          + NEWLINE
                          + "        "
                          + PROCESS_REQUESTS_AND_KEY_RECORDS_ONLY
                          + NEWLINE);

        System.out.println("Example of 'Rewrap':"
                          + NEWLINE
                          + NEWLINE
                          + "        "
                          + DRM_TOOL
                          + NEWLINE
                          + "        "
                          + DRMTOOL_CFG_FILE_EXAMPLE
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
                          + SOURCE_DRM_NAMING_CONTEXT_EXAMPLE
                          + NEWLINE
                          + "        "
                          + TARGET_DRM_NAMING_CONTEXT_EXAMPLE
                          + NEWLINE
                          + "        "
                          + PROCESS_REQUESTS_AND_KEY_RECORDS_ONLY
                          + NEWLINE);

        System.out.println("Example of 'Append ID Offset':"
                          + NEWLINE
                          + NEWLINE
                          + "        "
                          + DRM_TOOL
                          + NEWLINE
                          + "        "
                          + DRMTOOL_CFG_FILE_EXAMPLE
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
                          + SOURCE_DRM_NAMING_CONTEXT_EXAMPLE
                          + NEWLINE
                          + "        "
                          + TARGET_DRM_NAMING_CONTEXT_EXAMPLE
                          + NEWLINE
                          + "        "
                          + PROCESS_REQUESTS_AND_KEY_RECORDS_ONLY
                          + NEWLINE);

        System.out.println("Example of 'Remove ID Offset':"
                          + NEWLINE
                          + NEWLINE
                          + "        "
                          + DRM_TOOL
                          + NEWLINE
                          + "        "
                          + DRMTOOL_CFG_FILE_EXAMPLE
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
                          + SOURCE_DRM_NAMING_CONTEXT_EXAMPLE
                          + NEWLINE
                          + "        "
                          + TARGET_DRM_NAMING_CONTEXT_EXAMPLE
                          + NEWLINE
                          + "        "
                          + PROCESS_REQUESTS_AND_KEY_RECORDS_ONLY
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
     * the "source" DRM instance's security databases.
     *
     * This method is based upon code from 'com.netscape.kra.StorageKeyUnit'.
     * <P>
     *
     * @return the private RSA storage key from the "source" DRM
     */
    private static PrivateKey getPrivateKey() {
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
            log("ERROR:  Getting private key - "
                    + "TokenException: '"
                    + exToken.toString()
                    + "'"
                    + NEWLINE, true);
            System.exit(0);
        }

        return null;
    }

    /**
     * This method gets the public key from the certificate stored
     * in the "target" DRM storage certificate file. It also obtains
     * the keysize of this RSA key.
     *
     * This method is based upon code from
     * 'com.netscape.cmstools.PrettyPrintCert'.
     * <P>
     *
     * @return the public RSA storage key from the "target" DRM
     */
    private static PublicKey getPublicKey() {
        BufferedReader inputCert = null;
        String encodedBASE64CertChunk;
        StringBuffer encodedBASE64Cert = new StringBuffer();
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
     * from the "source" DRM instance's security databases and
     * the public RSA storage key from the certificate stored in
     * the "target" DRM storage certificate file.
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
            cm = CryptoManager.getInstance();

            log("Retrieving source storage token called '"
                    + mSourceStorageTokenName
                    + "'."
                    + NEWLINE, true);

            if (mSourceStorageTokenName.equals(INTERNAL_TOKEN)) {
                mSourceToken = cm.getInternalKeyStorageToken();
            } else {
                mSourceToken = cm.getTokenByName(mSourceStorageTokenName);
            }

            if (mSourceToken == null) {
                return FAILURE;
            }

            if (mPwdfileFlag) {
                BufferedReader in = null;
                String pwd = null;
                Password mPwd = null;

                try {
                    in = new BufferedReader(
                             new FileReader(
                                     mSourcePKISecurityDatabasePwdfile));
                    pwd = in.readLine();
                    if (pwd == null) {
                        pwd = "";
                    }
                    mPwd = new Password(pwd.toCharArray());

                    mSourceToken.login(mPwd);
                } catch (Exception exReadPwd) {
                    log("ERROR:  Failed to read the keydb password from "
                            + "the file '"
                            + mSourcePKISecurityDatabasePwdfile
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
                            e.printStackTrace();
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
            if (mSourceStorageTokenName.equals(INTERNAL_TOKEN)) {
                log("Retrieving source storage cert with nickname of '"
                        + mSourceStorageCertNickname
                        + "'."
                        + NEWLINE, true);

                mUnwrapCert = cm.findCertByNickname(mSourceStorageCertNickname
                                                   );
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
            if (mSourceStorageTokenName.equals(INTERNAL_TOKEN)) {
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
            if (mSourceStorageTokenName.equals(INTERNAL_TOKEN)) {
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

        mUnwrapPrivateKey = getPrivateKey();

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
                     getPublicKey().getEncoded());

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
            source_rsaWrap = mSourceToken.getKeyWrapper(
                                 KeyWrapAlgorithm.RSA);
            source_rsaWrap.initUnwrap(mUnwrapPrivateKey, null);
            sk = source_rsaWrap.unwrapSymmetric(source_session,
                                                 SymmetricKey.DES3,
                                                 SymmetricKey.Usage.DECRYPT,
                                                 0);
            if (mDebug) {
                log("DEBUG: sk = '"
                        + Utils.base64encode(sk.getEncoded())
                        + "' length = '"
                        + sk.getEncoded().length
                        + "'"
                        + NEWLINE, false);
                log("DEBUG: pri = '"
                        + Utils.base64encode(pri)
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
        try (DerOutputStream out = new DerOutputStream()) {
            // Use "mSourceToken" to get "KeyWrapAlgorithm.RSA"
            target_rsaWrap = mSourceToken.getKeyWrapper(
                                 KeyWrapAlgorithm.RSA);
            target_rsaWrap.initWrap(mWrapPublicKey, null);
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
     * Helper method used to remove all EOLs ('\n' and '\r')
     * from the passed in string.
     * <P>
     *
     * @param data consisting of a string containing EOLs
     * @return a string consisting of a string with no EOLs
     */
    private static String stripEOL(String data) {
        StringBuffer buffer = new StringBuffer();
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
        StringBuffer revised_data = new StringBuffer();

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
     *     DRM_LDIF_CN = "cn:";
     *     DRM_LDIF_DN_EMBEDDED_CN_DATA = "dn: cn";
     *     DRM_LDIF_EXTDATA_KEY_RECORD = "extdata-keyrecord:";
     *     DRM_LDIF_EXTDATA_REQUEST_ID = "extdata-requestid:";
     *     DRM_LDIF_EXTDATA_SERIAL_NUMBER = "extdata-serialnumber:";
     *     DRM_LDIF_REQUEST_ID = "requestId:";
     *     DRM_LDIF_SERIAL_NO = "serialno:";
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
                    if (mAppendIdOffset.compareTo(value) == 1) {
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
     * Helper method which composes the output line for DRM_LDIF_CN.
     * <P>
     *
     * @param record_type the string representation of the input record type
     * @param line the string representation of the input line
     * @return the composed output line
     */
    private static String output_cn(String record_type,
                                     String line) {
        String output = null;

        if (record_type.equals(DRM_LDIF_ENROLLMENT)) {
            if (drmtoolCfg.get(DRMTOOL_CFG_ENROLLMENT_CN)) {
                output = compose_numeric_line(DRM_LDIF_CN,
                                               SPACE,
                                               line,
                                               false);
            } else {
                output = line;
            }
        } else if (record_type.equals(DRM_LDIF_CA_KEY_RECORD)) {
            if (drmtoolCfg.get(DRMTOOL_CFG_CA_KEY_RECORD_CN)) {
                output = compose_numeric_line(DRM_LDIF_CN,
                                               SPACE,
                                               line,
                                               false);
            } else {
                output = line;
            }
        } else if (record_type.equals(DRM_LDIF_RECOVERY)) {
            if (drmtoolCfg.get(DRMTOOL_CFG_RECOVERY_CN)) {
                output = compose_numeric_line(DRM_LDIF_CN,
                                               SPACE,
                                               line,
                                               false);
            } else {
                output = line;
            }
        } else if (record_type.equals(DRM_LDIF_TPS_KEY_RECORD)) {
            if (drmtoolCfg.get(DRMTOOL_CFG_TPS_KEY_RECORD_CN)) {
                output = compose_numeric_line(DRM_LDIF_CN,
                                               SPACE,
                                               line,
                                               false);
            } else {
                output = line;
            }
        } else if (record_type.equals(DRM_LDIF_KEYGEN)) {
            if (drmtoolCfg.get(DRMTOOL_CFG_KEYGEN_CN)) {
                output = compose_numeric_line(DRM_LDIF_CN,
                                               SPACE,
                                               line,
                                               false);
            } else {
                output = line;
            }
        } else if (record_type.equals(DRM_LDIF_RECORD)) {
            // Non-Request / Non-Key Record:
            //     Pass through the original
            //     'cn' line UNCHANGED
            //     so that it is ALWAYS written
            output = line;
        } else {
            log("ERROR:  Mismatched record field='"
                    + DRM_LDIF_CN
                    + "' for record type='"
                    + record_type
                    + "'!"
                    + NEWLINE, true);
        }

        return output;
    }

    /**
     * Helper method which composes the output line for DRM_LDIF_DATE_OF_MODIFY.
     * <P>
     *
     * @param record_type the string representation of the input record type
     * @param line the string representation of the input line
     * @return the composed output line
     */
    private static String output_date_of_modify(String record_type,
                                                 String line) {
        String output = null;

        if (record_type.equals(DRM_LDIF_ENROLLMENT)) {
            if (drmtoolCfg.get(DRMTOOL_CFG_ENROLLMENT_DATE_OF_MODIFY)) {
                output = DRM_LDIF_DATE_OF_MODIFY
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
        } else if (record_type.equals(DRM_LDIF_CA_KEY_RECORD)) {
            if (drmtoolCfg.get(DRMTOOL_CFG_CA_KEY_RECORD_DATE_OF_MODIFY)) {
                output = DRM_LDIF_DATE_OF_MODIFY
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
        } else if (record_type.equals(DRM_LDIF_RECOVERY)) {
            if (drmtoolCfg.get(DRMTOOL_CFG_RECOVERY_DATE_OF_MODIFY)) {
                output = DRM_LDIF_DATE_OF_MODIFY
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
        } else if (record_type.equals(DRM_LDIF_TPS_KEY_RECORD)) {
            if (drmtoolCfg.get(DRMTOOL_CFG_TPS_KEY_RECORD_DATE_OF_MODIFY)) {
                output = DRM_LDIF_DATE_OF_MODIFY
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
        } else if (record_type.equals(DRM_LDIF_KEYGEN)) {
            if (drmtoolCfg.get(DRMTOOL_CFG_KEYGEN_DATE_OF_MODIFY)) {
                output = DRM_LDIF_DATE_OF_MODIFY
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
        } else {
            log("ERROR:  Mismatched record field='"
                    + DRM_LDIF_DATE_OF_MODIFY
                    + "' for record type='"
                    + record_type
                    + "'!"
                    + NEWLINE, true);
        }

        return output;
    }

    /**
     * Helper method which composes the output line for DRM_LDIF_DN.
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
            if (record_type.equals(DRM_LDIF_ENROLLMENT)) {
                if (drmtoolCfg.get(DRMTOOL_CFG_ENROLLMENT_DN)) {

                    // First check for an embedded "cn=<value>"
                    // name-value pair
                    if (line.startsWith(DRM_LDIF_DN_EMBEDDED_CN_DATA)) {
                        // At this point, always extract
                        // the embedded "cn=<value>" name-value pair
                        // which will ALWAYS be the first
                        // portion of the "dn: " attribute
                        embedded_cn_data = line.split(COMMA, 2);

                        embedded_cn_output = compose_numeric_line(
                                                 DRM_LDIF_DN_EMBEDDED_CN_DATA,
                                                 EQUAL_SIGN,
                                                 embedded_cn_data[0],
                                                 false);

                        input = embedded_cn_output
                                + COMMA
                                + embedded_cn_data[1];
                    } else {
                        input = line;
                    }

                    // Since "-source_drm_naming_context", and
                    // "-target_drm_naming_context" are OPTIONAL
                    // parameters, ONLY process this portion of the field
                    // if both of these options have been selected
                    if (mDrmNamingContextsFlag) {
                        output = input.replace(mSourceDrmNamingContext,
                                                mTargetDrmNamingContext);
                    } else {
                        output = input;
                    }
                } else {
                    output = line;
                }
            } else if (record_type.equals(DRM_LDIF_CA_KEY_RECORD)) {
                if (drmtoolCfg.get(DRMTOOL_CFG_CA_KEY_RECORD_DN)) {

                    // First check for an embedded "cn=<value>"
                    // name-value pair
                    if (line.startsWith(DRM_LDIF_DN_EMBEDDED_CN_DATA)) {
                        // At this point, always extract
                        // the embedded "cn=<value>" name-value pair
                        // which will ALWAYS be the first
                        // portion of the "dn: " attribute
                        embedded_cn_data = line.split(COMMA, 2);

                        embedded_cn_output = compose_numeric_line(
                                                 DRM_LDIF_DN_EMBEDDED_CN_DATA,
                                                 EQUAL_SIGN,
                                                 embedded_cn_data[0],
                                                 false);

                        input = embedded_cn_output
                                + COMMA
                                + embedded_cn_data[1];
                    } else {
                        input = line;
                    }

                    // Since "-source_drm_naming_context", and
                    // "-target_drm_naming_context" are OPTIONAL
                    // parameters, ONLY process this portion of the field
                    // if both of these options have been selected
                    if (mDrmNamingContextsFlag) {
                        output = input.replace(mSourceDrmNamingContext,
                                                mTargetDrmNamingContext);
                    } else {
                        output = input;
                    }
                } else {
                    output = line;
                }
            } else if (record_type.equals(DRM_LDIF_RECOVERY)) {
                if (drmtoolCfg.get(DRMTOOL_CFG_RECOVERY_DN)) {

                    // First check for an embedded "cn=<value>"
                    // name-value pair
                    if (line.startsWith(DRM_LDIF_DN_EMBEDDED_CN_DATA)) {
                        // At this point, always extract
                        // the embedded "cn=<value>" name-value pair
                        // which will ALWAYS be the first
                        // portion of the "dn: " attribute
                        embedded_cn_data = line.split(COMMA, 2);

                        embedded_cn_output = compose_numeric_line(
                                                 DRM_LDIF_DN_EMBEDDED_CN_DATA,
                                                 EQUAL_SIGN,
                                                 embedded_cn_data[0],
                                                 false);

                        input = embedded_cn_output
                                + COMMA
                                + embedded_cn_data[1];
                    } else {
                        input = line;
                    }

                    // Since "-source_drm_naming_context", and
                    // "-target_drm_naming_context" are OPTIONAL
                    // parameters, ONLY process this portion of the field
                    // if both of these options have been selected
                    if (mDrmNamingContextsFlag) {
                        output = input.replace(mSourceDrmNamingContext,
                                                mTargetDrmNamingContext);
                    } else {
                        output = input;
                    }
                } else {
                    output = line;
                }
            } else if (record_type.equals(DRM_LDIF_TPS_KEY_RECORD)) {
                if (drmtoolCfg.get(DRMTOOL_CFG_TPS_KEY_RECORD_DN)) {

                    // First check for an embedded "cn=<value>"
                    // name-value pair
                    if (line.startsWith(DRM_LDIF_DN_EMBEDDED_CN_DATA)) {
                        // At this point, always extract
                        // the embedded "cn=<value>" name-value pair
                        // which will ALWAYS be the first
                        // portion of the "dn: " attribute
                        embedded_cn_data = line.split(COMMA, 2);

                        embedded_cn_output = compose_numeric_line(
                                                 DRM_LDIF_DN_EMBEDDED_CN_DATA,
                                                 EQUAL_SIGN,
                                                 embedded_cn_data[0],
                                                 false);

                        input = embedded_cn_output
                                + COMMA
                                + embedded_cn_data[1];
                    } else {
                        input = line;
                    }

                    // Since "-source_drm_naming_context", and
                    // "-target_drm_naming_context" are OPTIONAL
                    // parameters, ONLY process this portion of the field
                    // if both of these options have been selected
                    if (mDrmNamingContextsFlag) {
                        output = input.replace(mSourceDrmNamingContext,
                                                mTargetDrmNamingContext);
                    } else {
                        output = input;
                    }
                } else {
                    output = line;
                }
            } else if (record_type.equals(DRM_LDIF_KEYGEN)) {
                if (drmtoolCfg.get(DRMTOOL_CFG_KEYGEN_DN)) {

                    // First check for an embedded "cn=<value>"
                    // name-value pair
                    if (line.startsWith(DRM_LDIF_DN_EMBEDDED_CN_DATA)) {
                        // At this point, always extract
                        // the embedded "cn=<value>" name-value pair
                        // which will ALWAYS be the first
                        // portion of the "dn: " attribute
                        embedded_cn_data = line.split(COMMA, 2);

                        embedded_cn_output = compose_numeric_line(
                                                 DRM_LDIF_DN_EMBEDDED_CN_DATA,
                                                 EQUAL_SIGN,
                                                 embedded_cn_data[0],
                                                 false);

                        input = embedded_cn_output
                                + COMMA
                                + embedded_cn_data[1];
                    } else {
                        input = line;
                    }

                    // Since "-source_drm_naming_context", and
                    // "-target_drm_naming_context" are OPTIONAL
                    // parameters, ONLY process this portion of the field
                    // if both of these options have been selected
                    if (mDrmNamingContextsFlag) {
                        output = input.replace(mSourceDrmNamingContext,
                                                mTargetDrmNamingContext);
                    } else {
                        output = input;
                    }
                } else {
                    output = line;
                }
            } else if (record_type.equals(DRM_LDIF_RECORD)) {
                // Non-Request / Non-Key Record:
                //     Pass through the original
                //     'dn' line UNCHANGED
                //     so that it is ALWAYS written
                output = line;
            } else {
                log("ERROR:  Mismatched record field='"
                        + DRM_LDIF_DN
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
            log("ERROR:  Unable to replace source DRM naming context '"
                    + mSourceDrmNamingContext
                    + "' with target DRM naming context '"
                    + mTargetDrmNamingContext
                    + "' NullPointerException: '"
                    + exNullPointerException.toString()
                    + "'"
                    + NEWLINE, true);
        }

        return output;
    }

    /**
     * Helper method which composes the output line for
     * DRM_LDIF_EXTDATA_KEY_RECORD.
     * <P>
     *
     * @param record_type the string representation of the input record type
     * @param line the string representation of the input line
     * @return the composed output line
     */
    private static String output_extdata_key_record(String record_type,
                                                     String line) {
        String output = null;

        if (record_type.equals(DRM_LDIF_ENROLLMENT)) {
            if (drmtoolCfg.get(DRMTOOL_CFG_ENROLLMENT_EXTDATA_KEY_RECORD)) {
                output = compose_numeric_line(DRM_LDIF_EXTDATA_KEY_RECORD,
                                               SPACE,
                                               line,
                                               false);
            } else {
                output = line;
            }
        } else if (record_type.equals(DRM_LDIF_KEYGEN)) {
            if (drmtoolCfg.get(DRMTOOL_CFG_KEYGEN_EXTDATA_KEY_RECORD)) {
                output = compose_numeric_line(DRM_LDIF_EXTDATA_KEY_RECORD,
                                               SPACE,
                                               line,
                                               false);
            } else {
                output = line;
            }
        } else {
            log("ERROR:  Mismatched record field='"
                    + DRM_LDIF_EXTDATA_KEY_RECORD
                    + "' for record type='"
                    + record_type
                    + "'!"
                    + NEWLINE, true);
        }

        return output;
    }

    /**
     * Helper method which composes the output line for
     * DRM_LDIF_EXTDATA_REQUEST_ID.
     * <P>
     *
     * @param record_type the string representation of the input record type
     * @param line the string representation of the input line
     * @return the composed output line
     */
    private static String output_extdata_request_id(String record_type,
                                                     String line) {
        String output = null;

        if (record_type.equals(DRM_LDIF_ENROLLMENT)) {
            // ALWAYS pass-through "extdata-requestId" for
            // DRM_LDIF_ENROLLMENT records UNCHANGED because the
            // value in this field is associated with the issuing CA!
            output = line;
        } else if (record_type.equals(DRM_LDIF_RECOVERY)) {
            if (drmtoolCfg.get(DRMTOOL_CFG_RECOVERY_EXTDATA_REQUEST_ID)) {
                output = compose_numeric_line(DRM_LDIF_EXTDATA_REQUEST_ID,
                                               SPACE,
                                               line,
                                               false);
            } else {
                output = line;
            }
        } else if (record_type.equals(DRM_LDIF_KEYGEN)) {
            if (drmtoolCfg.get(DRMTOOL_CFG_KEYGEN_EXTDATA_REQUEST_ID)) {
                output = compose_numeric_line(DRM_LDIF_EXTDATA_REQUEST_ID,
                                               SPACE,
                                               line,
                                               false);
            } else {
                output = line;
            }
        } else {
            log("ERROR:  Mismatched record field='"
                    + DRM_LDIF_EXTDATA_REQUEST_ID
                    + "' for record type='"
                    + record_type
                    + "'!"
                    + NEWLINE, true);
        }

        return output;
    }

    /**
     * Helper method which composes the output line for
     * DRM_LDIF_EXTDATA_REQUEST_NOTES.
     * <P>
     *
     * @param record_type the string representation of the input record type
     * @param line the string representation of the input line
     * @return the composed output line
     */
    private static String output_extdata_request_notes(String record_type,
            String line) {
        StringBuffer input = new StringBuffer();

        String data = null;
        String unformatted_data = null;
        String output = null;
        String next_line = null;

        // extract the data
        if (line.length() > DRM_LDIF_EXTDATA_REQUEST_NOTES.length()) {
            input.append(line.substring(
                        DRM_LDIF_EXTDATA_REQUEST_NOTES.length() + 1
                    ).trim());
        } else {
            input.append(line.substring(
                        DRM_LDIF_EXTDATA_REQUEST_NOTES.length()
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

        if (record_type.equals(DRM_LDIF_ENROLLMENT)) {
            if (drmtoolCfg.get(DRMTOOL_CFG_ENROLLMENT_EXTDATA_REQUEST_NOTES)) {
                // write out a revised 'extdata-requestnotes' line
                if (mRewrapFlag && mAppendIdOffsetFlag) {
                    data = input.toString()
                            + SPACE
                            + LEFT_BRACE
                            + mDateOfModify
                            + RIGHT_BRACE
                            + COLON + SPACE
                            + DRM_LDIF_REWRAP_MESSAGE
                            + mPublicKeySize
                            + DRM_LDIF_RSA_MESSAGE
                            + mSourcePKISecurityDatabasePwdfileMessage
                            + SPACE
                            + PLUS + SPACE
                            + DRM_LDIF_APPENDED_ID_OFFSET_MESSAGE
                            + SPACE
                            + TIC
                            + mAppendIdOffset.toString()
                            + TIC
                            + mDrmNamingContextMessage
                            + mProcessRequestsAndKeyRecordsOnlyMessage;

                    // Unformat the data
                    unformatted_data = stripEOL(data);

                    // Format the unformatted_data
                    // to match the desired LDIF format
                    output = DRM_LDIF_EXTDATA_REQUEST_NOTES
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
                            + DRM_LDIF_REWRAP_MESSAGE
                            + mPublicKeySize
                            + DRM_LDIF_RSA_MESSAGE
                            + mSourcePKISecurityDatabasePwdfileMessage
                            + SPACE
                            + PLUS + SPACE
                            + DRM_LDIF_REMOVED_ID_OFFSET_MESSAGE
                            + SPACE
                            + TIC
                            + mRemoveIdOffset.toString()
                            + TIC
                            + mDrmNamingContextMessage
                            + mProcessRequestsAndKeyRecordsOnlyMessage;

                    // Unformat the data
                    unformatted_data = stripEOL(data);

                    // Format the unformatted_data
                    // to match the desired LDIF format
                    output = DRM_LDIF_EXTDATA_REQUEST_NOTES
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
                            + DRM_LDIF_REWRAP_MESSAGE
                            + mPublicKeySize
                            + DRM_LDIF_RSA_MESSAGE
                            + mSourcePKISecurityDatabasePwdfileMessage
                            + mDrmNamingContextMessage
                            + mProcessRequestsAndKeyRecordsOnlyMessage;

                    // Unformat the data
                    unformatted_data = stripEOL(data);

                    // Format the unformatted_data
                    // to match the desired LDIF format
                    output = DRM_LDIF_EXTDATA_REQUEST_NOTES
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
                            + DRM_LDIF_APPENDED_ID_OFFSET_MESSAGE
                            + SPACE
                            + TIC
                            + mAppendIdOffset.toString()
                            + TIC
                            + mDrmNamingContextMessage
                            + mProcessRequestsAndKeyRecordsOnlyMessage;

                    // Unformat the data
                    unformatted_data = stripEOL(data);

                    // Format the unformatted_data
                    // to match the desired LDIF format
                    output = DRM_LDIF_EXTDATA_REQUEST_NOTES
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
                            + DRM_LDIF_REMOVED_ID_OFFSET_MESSAGE
                            + SPACE
                            + TIC
                            + mRemoveIdOffset.toString()
                            + TIC
                            + mDrmNamingContextMessage
                            + mProcessRequestsAndKeyRecordsOnlyMessage;

                    // Unformat the data
                    unformatted_data = stripEOL(data);

                    // Format the unformatted_data
                    // to match the desired LDIF format
                    output = DRM_LDIF_EXTDATA_REQUEST_NOTES
                            + SPACE
                            + format_ldif_data(
                                    EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                    unformatted_data);
                }

                // log this information
                log("Changed:"
                        + NEWLINE
                        + TIC
                        + DRM_LDIF_EXTDATA_REQUEST_NOTES
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
        } else if (record_type.equals(DRM_LDIF_RECOVERY)) {
            if (drmtoolCfg.get(DRMTOOL_CFG_RECOVERY_EXTDATA_REQUEST_NOTES)) {
                // write out a revised 'extdata-requestnotes' line
                if (mRewrapFlag && mAppendIdOffsetFlag) {
                    data = input.toString()
                            + SPACE
                            + LEFT_BRACE
                            + mDateOfModify
                            + RIGHT_BRACE
                            + COLON + SPACE
                            + DRM_LDIF_REWRAP_MESSAGE
                            + mPublicKeySize
                            + DRM_LDIF_RSA_MESSAGE
                            + mSourcePKISecurityDatabasePwdfileMessage
                            + SPACE
                            + PLUS + SPACE
                            + DRM_LDIF_APPENDED_ID_OFFSET_MESSAGE
                            + SPACE
                            + TIC
                            + mAppendIdOffset.toString()
                            + TIC
                            + mDrmNamingContextMessage
                            + mProcessRequestsAndKeyRecordsOnlyMessage;

                    // Unformat the data
                    unformatted_data = stripEOL(data);

                    // Format the unformatted_data
                    // to match the desired LDIF format
                    output = DRM_LDIF_EXTDATA_REQUEST_NOTES
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
                            + DRM_LDIF_REWRAP_MESSAGE
                            + mPublicKeySize
                            + DRM_LDIF_RSA_MESSAGE
                            + mSourcePKISecurityDatabasePwdfileMessage
                            + SPACE
                            + PLUS + SPACE
                            + DRM_LDIF_REMOVED_ID_OFFSET_MESSAGE
                            + SPACE
                            + TIC
                            + mRemoveIdOffset.toString()
                            + TIC
                            + mDrmNamingContextMessage
                            + mProcessRequestsAndKeyRecordsOnlyMessage;

                    // Unformat the data
                    unformatted_data = stripEOL(data);

                    // Format the unformatted_data
                    // to match the desired LDIF format
                    output = DRM_LDIF_EXTDATA_REQUEST_NOTES
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
                            + DRM_LDIF_REWRAP_MESSAGE
                            + mPublicKeySize
                            + DRM_LDIF_RSA_MESSAGE
                            + mSourcePKISecurityDatabasePwdfileMessage
                            + mDrmNamingContextMessage
                            + mProcessRequestsAndKeyRecordsOnlyMessage;

                    // Unformat the data
                    unformatted_data = stripEOL(data);

                    // Format the unformatted_data
                    // to match the desired LDIF format
                    output = DRM_LDIF_EXTDATA_REQUEST_NOTES
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
                            + DRM_LDIF_APPENDED_ID_OFFSET_MESSAGE
                            + SPACE
                            + TIC
                            + mAppendIdOffset.toString()
                            + TIC
                            + mDrmNamingContextMessage
                            + mProcessRequestsAndKeyRecordsOnlyMessage;

                    // Unformat the data
                    unformatted_data = stripEOL(data);

                    // Format the unformatted_data
                    // to match the desired LDIF format
                    output = DRM_LDIF_EXTDATA_REQUEST_NOTES
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
                            + DRM_LDIF_REMOVED_ID_OFFSET_MESSAGE
                            + SPACE
                            + TIC
                            + mRemoveIdOffset.toString()
                            + TIC
                            + mDrmNamingContextMessage
                            + mProcessRequestsAndKeyRecordsOnlyMessage;

                    // Unformat the data
                    unformatted_data = stripEOL(data);

                    // Format the unformatted_data
                    // to match the desired LDIF format
                    output = DRM_LDIF_EXTDATA_REQUEST_NOTES
                            + SPACE
                            + format_ldif_data(
                                    EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                    unformatted_data);
                }

                // log this information
                log("Changed:"
                        + NEWLINE
                        + TIC
                        + DRM_LDIF_EXTDATA_REQUEST_NOTES
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
        } else if (record_type.equals(DRM_LDIF_KEYGEN)) {
            if (drmtoolCfg.get(DRMTOOL_CFG_KEYGEN_EXTDATA_REQUEST_NOTES)) {
                // write out a revised 'extdata-requestnotes' line
                if (mRewrapFlag && mAppendIdOffsetFlag) {
                    data = input.toString()
                            + SPACE
                            + LEFT_BRACE
                            + mDateOfModify
                            + RIGHT_BRACE
                            + COLON + SPACE
                            + DRM_LDIF_REWRAP_MESSAGE
                            + mPublicKeySize
                            + DRM_LDIF_RSA_MESSAGE
                            + mSourcePKISecurityDatabasePwdfileMessage
                            + SPACE
                            + PLUS + SPACE
                            + DRM_LDIF_APPENDED_ID_OFFSET_MESSAGE
                            + SPACE
                            + TIC
                            + mAppendIdOffset.toString()
                            + TIC
                            + mDrmNamingContextMessage
                            + mProcessRequestsAndKeyRecordsOnlyMessage;

                    // Unformat the data
                    unformatted_data = stripEOL(data);

                    // Format the unformatted_data
                    // to match the desired LDIF format
                    output = DRM_LDIF_EXTDATA_REQUEST_NOTES
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
                            + DRM_LDIF_REWRAP_MESSAGE
                            + mPublicKeySize
                            + DRM_LDIF_RSA_MESSAGE
                            + mSourcePKISecurityDatabasePwdfileMessage
                            + SPACE
                            + PLUS + SPACE
                            + DRM_LDIF_REMOVED_ID_OFFSET_MESSAGE
                            + SPACE
                            + TIC
                            + mRemoveIdOffset.toString()
                            + TIC
                            + mDrmNamingContextMessage
                            + mProcessRequestsAndKeyRecordsOnlyMessage;

                    // Unformat the data
                    unformatted_data = stripEOL(data);

                    // Format the unformatted_data
                    // to match the desired LDIF format
                    output = DRM_LDIF_EXTDATA_REQUEST_NOTES
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
                            + DRM_LDIF_REWRAP_MESSAGE
                            + mPublicKeySize
                            + DRM_LDIF_RSA_MESSAGE
                            + mSourcePKISecurityDatabasePwdfileMessage
                            + mDrmNamingContextMessage
                            + mProcessRequestsAndKeyRecordsOnlyMessage;

                    // Unformat the data
                    unformatted_data = stripEOL(data);

                    // Format the unformatted_data
                    // to match the desired LDIF format
                    output = DRM_LDIF_EXTDATA_REQUEST_NOTES
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
                            + DRM_LDIF_APPENDED_ID_OFFSET_MESSAGE
                            + SPACE
                            + TIC
                            + mAppendIdOffset.toString()
                            + TIC
                            + mDrmNamingContextMessage
                            + mProcessRequestsAndKeyRecordsOnlyMessage;

                    // Unformat the data
                    unformatted_data = stripEOL(data);

                    // Format the unformatted_data
                    // to match the desired LDIF format
                    output = DRM_LDIF_EXTDATA_REQUEST_NOTES
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
                            + DRM_LDIF_REMOVED_ID_OFFSET_MESSAGE
                            + SPACE
                            + TIC
                            + mRemoveIdOffset.toString()
                            + TIC
                            + mDrmNamingContextMessage
                            + mProcessRequestsAndKeyRecordsOnlyMessage;

                    // Unformat the data
                    unformatted_data = stripEOL(data);

                    // Format the unformatted_data
                    // to match the desired LDIF format
                    output = DRM_LDIF_EXTDATA_REQUEST_NOTES
                            + SPACE
                            + format_ldif_data(
                                    EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                    unformatted_data);
                }

                // log this information
                log("Changed:"
                        + NEWLINE
                        + TIC
                        + DRM_LDIF_EXTDATA_REQUEST_NOTES
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
        } else {
            log("ERROR:  Mismatched record field='"
                    + DRM_LDIF_EXTDATA_REQUEST_NOTES
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
     * DRM_LDIF_EXTDATA_REQUEST_NOTES.
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

        if (record_type.equals(DRM_LDIF_RECOVERY)) {
            if (drmtoolCfg.get(DRMTOOL_CFG_RECOVERY_EXTDATA_REQUEST_NOTES)) {
                if (!previous_line.startsWith(DRM_LDIF_EXTDATA_REQUEST_NOTES)) {
                    // write out the missing 'extdata-requestnotes' line
                    if (mRewrapFlag && mAppendIdOffsetFlag) {
                        data = LEFT_BRACE
                                + mDateOfModify
                                + RIGHT_BRACE
                                + COLON + SPACE
                                + DRM_LDIF_REWRAP_MESSAGE
                                + mPublicKeySize
                                + DRM_LDIF_RSA_MESSAGE
                                + mSourcePKISecurityDatabasePwdfileMessage
                                + SPACE
                                + PLUS + SPACE
                                + DRM_LDIF_APPENDED_ID_OFFSET_MESSAGE
                                + SPACE
                                + TIC
                                + mAppendIdOffset.toString()
                                + TIC
                                + mDrmNamingContextMessage
                                + mProcessRequestsAndKeyRecordsOnlyMessage;

                        // Unformat the data
                        unformatted_data = stripEOL(data);

                        // Format the unformatted_data
                        // to match the desired LDIF format
                        output = DRM_LDIF_EXTDATA_REQUEST_NOTES
                                + SPACE
                                + format_ldif_data(
                                        EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                        unformatted_data);
                    } else if (mRewrapFlag && mRemoveIdOffsetFlag) {
                        data = LEFT_BRACE
                                + mDateOfModify
                                + RIGHT_BRACE
                                + COLON + SPACE
                                + DRM_LDIF_REWRAP_MESSAGE
                                + mPublicKeySize
                                + DRM_LDIF_RSA_MESSAGE
                                + mSourcePKISecurityDatabasePwdfileMessage
                                + SPACE
                                + PLUS + SPACE
                                + DRM_LDIF_REMOVED_ID_OFFSET_MESSAGE
                                + SPACE
                                + TIC
                                + mRemoveIdOffset.toString()
                                + TIC
                                + mDrmNamingContextMessage
                                + mProcessRequestsAndKeyRecordsOnlyMessage;

                        // Unformat the data
                        unformatted_data = stripEOL(data);

                        // Format the unformatted_data
                        // to match the desired LDIF format
                        output = DRM_LDIF_EXTDATA_REQUEST_NOTES
                                + SPACE
                                + format_ldif_data(
                                        EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                        unformatted_data);
                    } else if (mRewrapFlag) {
                        data = LEFT_BRACE
                                + mDateOfModify
                                + RIGHT_BRACE
                                + COLON + SPACE
                                + DRM_LDIF_REWRAP_MESSAGE
                                + mPublicKeySize
                                + DRM_LDIF_RSA_MESSAGE
                                + mSourcePKISecurityDatabasePwdfileMessage
                                + mDrmNamingContextMessage
                                + mProcessRequestsAndKeyRecordsOnlyMessage;

                        // Unformat the data
                        unformatted_data = stripEOL(data);

                        // Format the unformatted_data
                        // to match the desired LDIF format
                        output = DRM_LDIF_EXTDATA_REQUEST_NOTES
                                + SPACE
                                + format_ldif_data(
                                        EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                        unformatted_data);
                    } else if (mAppendIdOffsetFlag) {
                        data = LEFT_BRACE
                                + mDateOfModify
                                + RIGHT_BRACE
                                + COLON + SPACE
                                + DRM_LDIF_APPENDED_ID_OFFSET_MESSAGE
                                + SPACE
                                + TIC
                                + mAppendIdOffset.toString()
                                + TIC
                                + mDrmNamingContextMessage
                                + mProcessRequestsAndKeyRecordsOnlyMessage;

                        // Unformat the data
                        unformatted_data = stripEOL(data);

                        // Format the unformatted_data
                        // to match the desired LDIF format
                        output = DRM_LDIF_EXTDATA_REQUEST_NOTES
                                + SPACE
                                + format_ldif_data(
                                        EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                        unformatted_data);
                    } else if (mRemoveIdOffsetFlag) {
                        data = LEFT_BRACE
                                + mDateOfModify
                                + RIGHT_BRACE
                                + COLON + SPACE
                                + DRM_LDIF_REMOVED_ID_OFFSET_MESSAGE
                                + SPACE
                                + TIC
                                + mRemoveIdOffset.toString()
                                + TIC
                                + mDrmNamingContextMessage
                                + mProcessRequestsAndKeyRecordsOnlyMessage;

                        // Unformat the data
                        unformatted_data = stripEOL(data);

                        // Format the unformatted_data
                        // to match the desired LDIF format
                        output = DRM_LDIF_EXTDATA_REQUEST_NOTES
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
        } else if (record_type.equals(DRM_LDIF_KEYGEN)) {
            if (drmtoolCfg.get(DRMTOOL_CFG_KEYGEN_EXTDATA_REQUEST_NOTES)) {
                if (!previous_line.startsWith(DRM_LDIF_EXTDATA_REQUEST_NOTES)) {
                    // write out the missing 'extdata-requestnotes' line
                    if (mRewrapFlag && mAppendIdOffsetFlag) {
                        data = LEFT_BRACE
                                + mDateOfModify
                                + RIGHT_BRACE
                                + COLON + SPACE
                                + DRM_LDIF_REWRAP_MESSAGE
                                + mPublicKeySize
                                + DRM_LDIF_RSA_MESSAGE
                                + mSourcePKISecurityDatabasePwdfileMessage
                                + SPACE
                                + PLUS + SPACE
                                + DRM_LDIF_APPENDED_ID_OFFSET_MESSAGE
                                + SPACE
                                + TIC
                                + mAppendIdOffset.toString()
                                + TIC
                                + mDrmNamingContextMessage
                                + mProcessRequestsAndKeyRecordsOnlyMessage;

                        // Unformat the data
                        unformatted_data = stripEOL(data);

                        // Format the unformatted_data
                        // to match the desired LDIF format
                        output = DRM_LDIF_EXTDATA_REQUEST_NOTES
                                + SPACE
                                + format_ldif_data(
                                        EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                        unformatted_data);
                    } else if (mRewrapFlag && mRemoveIdOffsetFlag) {
                        data = LEFT_BRACE
                                + mDateOfModify
                                + RIGHT_BRACE
                                + COLON + SPACE
                                + DRM_LDIF_REWRAP_MESSAGE
                                + mPublicKeySize
                                + DRM_LDIF_RSA_MESSAGE
                                + mSourcePKISecurityDatabasePwdfileMessage
                                + SPACE
                                + PLUS + SPACE
                                + DRM_LDIF_REMOVED_ID_OFFSET_MESSAGE
                                + SPACE
                                + TIC
                                + mRemoveIdOffset.toString()
                                + TIC
                                + mDrmNamingContextMessage
                                + mProcessRequestsAndKeyRecordsOnlyMessage;

                        // Unformat the data
                        unformatted_data = stripEOL(data);

                        // Format the unformatted_data
                        // to match the desired LDIF format
                        output = DRM_LDIF_EXTDATA_REQUEST_NOTES
                                + SPACE
                                + format_ldif_data(
                                        EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                        unformatted_data);
                    } else if (mRewrapFlag) {
                        data = LEFT_BRACE
                                + mDateOfModify
                                + RIGHT_BRACE
                                + COLON + SPACE
                                + DRM_LDIF_REWRAP_MESSAGE
                                + mPublicKeySize
                                + DRM_LDIF_RSA_MESSAGE
                                + mSourcePKISecurityDatabasePwdfileMessage
                                + mDrmNamingContextMessage
                                + mProcessRequestsAndKeyRecordsOnlyMessage;

                        // Unformat the data
                        unformatted_data = stripEOL(data);

                        // Format the unformatted_data
                        // to match the desired LDIF format
                        output = DRM_LDIF_EXTDATA_REQUEST_NOTES
                                + SPACE
                                + format_ldif_data(
                                        EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                        unformatted_data);
                    } else if (mAppendIdOffsetFlag) {
                        data = LEFT_BRACE
                                + mDateOfModify
                                + RIGHT_BRACE
                                + COLON + SPACE
                                + DRM_LDIF_APPENDED_ID_OFFSET_MESSAGE
                                + SPACE
                                + TIC
                                + mAppendIdOffset.toString()
                                + TIC
                                + mDrmNamingContextMessage
                                + mProcessRequestsAndKeyRecordsOnlyMessage;

                        // Unformat the data
                        unformatted_data = stripEOL(data);

                        // Format the unformatted_data
                        // to match the desired LDIF format
                        output = DRM_LDIF_EXTDATA_REQUEST_NOTES
                                + SPACE
                                + format_ldif_data(
                                        EXTDATA_REQUEST_NOTES_FIRST_LINE_DATA_LENGTH,
                                        unformatted_data);
                    } else if (mRemoveIdOffsetFlag) {
                        data = LEFT_BRACE
                                + mDateOfModify
                                + RIGHT_BRACE
                                + COLON + SPACE
                                + DRM_LDIF_REMOVED_ID_OFFSET_MESSAGE
                                + SPACE
                                + TIC
                                + mRemoveIdOffset.toString()
                                + TIC
                                + mDrmNamingContextMessage
                                + mProcessRequestsAndKeyRecordsOnlyMessage;

                        // Unformat the data
                        unformatted_data = stripEOL(data);

                        // Format the unformatted_data
                        // to match the desired LDIF format
                        output = DRM_LDIF_EXTDATA_REQUEST_NOTES
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
        }
    }

    /**
     * Helper method which composes the output line for
     * DRM_LDIF_EXTDATA_SERIAL_NUMBER.
     * <P>
     *
     * @param record_type the string representation of the input record type
     * @param line the string representation of the input line
     * @return the composed output line
     */
    private static String output_extdata_serial_number(String record_type,
                                                        String line) {
        String output = null;

        if (record_type.equals(DRM_LDIF_RECOVERY)) {
            if (drmtoolCfg.get(DRMTOOL_CFG_RECOVERY_EXTDATA_SERIAL_NUMBER)) {
                output = compose_numeric_line(DRM_LDIF_EXTDATA_SERIAL_NUMBER,
                                               SPACE,
                                               line,
                                               false);
            } else {
                output = line;
            }
        } else {
            log("ERROR:  Mismatched record field='"
                    + DRM_LDIF_EXTDATA_SERIAL_NUMBER
                    + "' for record type='"
                    + record_type
                    + "'!"
                    + NEWLINE, true);
        }

        return output;
    }

    /**
     * Helper method which composes the output line for
     * DRM_LDIF_PRIVATE_KEY_DATA.
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
        StringBuffer data = new StringBuffer();
        String revised_data = null;
        String unformatted_data = null;
        String formatted_data = null;
        String output = null;

        try {
            if (record_type.equals(DRM_LDIF_CA_KEY_RECORD)) {
                if (drmtoolCfg.get(DRMTOOL_CFG_CA_KEY_RECORD_PRIVATE_KEY_DATA)) {
                    // Since "-source_pki_security_database_path",
                    // "-source_storage_token_name",
                    // "-source_storage_certificate_nickname", and
                    // "-target_storage_certificate_file" are OPTIONAL
                    // parameters, ONLY process this field if all of
                    // these options have been selected
                    if (mRewrapFlag) {
                        // extract the data
                        data.append(line.substring(
                                DRM_LDIF_PRIVATE_KEY_DATA.length() + 1
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
                        target_wrappedKeyData = rewrap_wrapped_key_data(
                                                    source_wrappedKeyData);

                        // Encode the BINARY BASE 64 byte[] object
                        // into an ASCII BASE 64 certificate
                        // enclosed in a String() object
                        revised_data = Utils.base64encode(
                                           target_wrappedKeyData);

                        // Unformat the ASCII BASE 64 certificate
                        // for the log file
                        unformatted_data = stripEOL(revised_data);

                        // Format the ASCII BASE 64 certificate
                        // to match the desired LDIF format
                        formatted_data = format_ldif_data(
                                PRIVATE_KEY_DATA_FIRST_LINE_DATA_LENGTH,
                                unformatted_data);

                        // construct a revised 'privateKeyData' line
                        output = DRM_LDIF_PRIVATE_KEY_DATA
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
            } else if (record_type.equals(DRM_LDIF_TPS_KEY_RECORD)) {
                if (drmtoolCfg.get(DRMTOOL_CFG_TPS_KEY_RECORD_PRIVATE_KEY_DATA)) {
                    // Since "-source_pki_security_database_path",
                    // "-source_storage_token_name",
                    // "-source_storage_certificate_nickname", and
                    // "-target_storage_certificate_file" are OPTIONAL
                    // parameters, ONLY process this field if all of
                    // these options have been selected
                    if (mRewrapFlag) {
                        // extract the data
                        data.append(line.substring(
                                   DRM_LDIF_PRIVATE_KEY_DATA.length() + 1
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
                        target_wrappedKeyData = rewrap_wrapped_key_data(
                                                    source_wrappedKeyData);

                        // Encode the BINARY BASE 64 byte[] object
                        // into an ASCII BASE 64 certificate
                        // enclosed in a String() object
                        revised_data = Utils.base64encode(
                                           target_wrappedKeyData);

                        // Unformat the ASCII BASE 64 certificate
                        // for the log file
                        unformatted_data = stripEOL(revised_data);

                        // Format the ASCII BASE 64 certificate
                        // to match the desired LDIF format
                        formatted_data = format_ldif_data(
                                PRIVATE_KEY_DATA_FIRST_LINE_DATA_LENGTH,
                                unformatted_data);

                        // construct a revised 'privateKeyData' line
                        output = DRM_LDIF_PRIVATE_KEY_DATA
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
                        + DRM_LDIF_PRIVATE_KEY_DATA
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
     * Helper method which composes the output line for DRM_LDIF_REQUEST_ID.
     * <P>
     *
     * @param record_type the string representation of the input record type
     * @param line the string representation of the input line
     * @return the composed output line
     */
    private static String output_request_id(String record_type,
                                             String line) {
        String output = null;

        if (record_type.equals(DRM_LDIF_ENROLLMENT)) {
            if (drmtoolCfg.get(DRMTOOL_CFG_ENROLLMENT_REQUEST_ID)) {
                output = compose_numeric_line(DRM_LDIF_REQUEST_ID,
                                               SPACE,
                                               line,
                                               true);
            } else {
                output = line;
            }
        } else if (record_type.equals(DRM_LDIF_RECOVERY)) {
            if (drmtoolCfg.get(DRMTOOL_CFG_RECOVERY_REQUEST_ID)) {
                output = compose_numeric_line(DRM_LDIF_REQUEST_ID,
                                               SPACE,
                                               line,
                                               true);
            } else {
                output = line;
            }
        } else if (record_type.equals(DRM_LDIF_KEYGEN)) {
            if (drmtoolCfg.get(DRMTOOL_CFG_KEYGEN_REQUEST_ID)) {
                output = compose_numeric_line(DRM_LDIF_REQUEST_ID,
                                               SPACE,
                                               line,
                                               true);
            } else {
                output = line;
            }
        } else {
            log("ERROR:  Mismatched record field='"
                    + DRM_LDIF_REQUEST_ID
                    + "' for record type='"
                    + record_type
                    + "'!"
                    + NEWLINE, true);
        }

        return output;
    }

    /**
     * Helper method which composes the output line for DRM_LDIF_SERIAL_NO.
     * <P>
     *
     * @param record_type the string representation of the input record type
     * @param line the string representation of the input line
     * @return the composed output line
     */
    private static String output_serial_no(String record_type,
                                            String line) {
        String output = null;

        if (record_type.equals(DRM_LDIF_CA_KEY_RECORD)) {
            if (drmtoolCfg.get(DRMTOOL_CFG_CA_KEY_RECORD_SERIAL_NO)) {
                output = compose_numeric_line(DRM_LDIF_SERIAL_NO,
                                               SPACE,
                                               line,
                                               true);
            } else {
                output = line;
            }
        } else if (record_type.equals(DRM_LDIF_TPS_KEY_RECORD)) {
            if (drmtoolCfg.get(DRMTOOL_CFG_TPS_KEY_RECORD_SERIAL_NO)) {
                output = compose_numeric_line(DRM_LDIF_SERIAL_NO,
                                               SPACE,
                                               line,
                                               true);
            } else {
                output = line;
            }
        } else if (record_type.equals(DRM_LDIF_RECORD)) {
            // Non-Request / Non-Key Record:
            //     Pass through the original
            //     'serialno' line UNCHANGED
            //     so that it is ALWAYS written
            output = line;
        } else {
            log("ERROR:  Mismatched record field='"
                    + DRM_LDIF_SERIAL_NO
                    + "' for record type='"
                    + record_type
                    + "'!"
                    + NEWLINE, true);
        }

        return output;
    }

    /**
     * Helper method which composes the output line for
     * DRM_LDIF_EXTDATA_AUTH_TOKEN_USER.
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
            if (record_type.equals(DRM_LDIF_ENROLLMENT)) {
                // Since "-source_drm_naming_context", and
                // "-target_drm_naming_context" are OPTIONAL
                // parameters, ONLY process this field if both of
                // these options have been selected
                if (mDrmNamingContextsFlag) {
                    output = line.replace(mSourceDrmNamingContext,
                                           mTargetDrmNamingContext);
                } else {
                    output = line;
                }
            } else {
                log("ERROR:  Mismatched record field='"
                        + DRM_LDIF_EXTDATA_AUTH_TOKEN_USER
                        + "' for record type='"
                        + record_type
                        + "'!"
                        + NEWLINE, true);
            }
        } catch (NullPointerException exNullPointerException) {
            log("ERROR:  Unable to replace source DRM naming context '"
                    + mSourceDrmNamingContext
                    + "' with target DRM naming context '"
                    + mTargetDrmNamingContext
                    + "' NullPointerException: '"
                    + exNullPointerException.toString()
                    + "'"
                    + NEWLINE, true);
        }

        return output;
    }

    /**
     * Helper method which composes the output line for
     * DRM_LDIF_EXTDATA_AUTH_TOKEN_USER_DN.
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
            if (record_type.equals(DRM_LDIF_ENROLLMENT)) {
                // Since "-source_drm_naming_context", and
                // "-target_drm_naming_context" are OPTIONAL
                // parameters, ONLY process this field if both of
                // these options have been selected
                if (mDrmNamingContextsFlag) {
                    output = line.replace(mSourceDrmNamingContext,
                                           mTargetDrmNamingContext);
                } else {
                    output = line;
                }
            } else {
                log("ERROR:  Mismatched record field='"
                        + DRM_LDIF_EXTDATA_AUTH_TOKEN_USER_DN
                        + "' for record type='"
                        + record_type
                        + "'!"
                        + NEWLINE, true);
            }
        } catch (NullPointerException exNullPointerException) {
            log("ERROR:  Unable to replace source DRM naming context '"
                    + mSourceDrmNamingContext
                    + "' with target DRM naming context '"
                    + mTargetDrmNamingContext
                    + "' NullPointerException: '"
                    + exNullPointerException.toString()
                    + "'"
                    + NEWLINE, true);
        }

        return output;
    }

    /**
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
        record = new Vector<String>(INITIAL_LDIF_RECORD_CAPACITY);

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
                    if (input.startsWith(DRM_LDIF_REQUEST_TYPE)) {
                        // set the record type:
                        //
                        //     * DRM_LDIF_ENROLLMENT
                        //     * DRM_LDIF_KEYGEN
                        //     * DRM_LDIF_RECOVERY
                        //
                        record_type = input.substring(
                                          DRM_LDIF_REQUEST_TYPE.length() + 1
                                      ).trim();
                        if (!record_type.equals(DRM_LDIF_ENROLLMENT) &&
                                !record_type.equals(DRM_LDIF_KEYGEN) &&
                                !record_type.equals(DRM_LDIF_RECOVERY)) {
                            log("ERROR:  Unknown LDIF record type='"
                                    + record_type
                                    + "'!"
                                    + NEWLINE, true);
                            return FAILURE;
                        }
                    } else if (input.startsWith(DRM_LDIF_ARCHIVED_BY)) {
                        // extract the data
                        data = input.substring(
                                   DRM_LDIF_ARCHIVED_BY.length() + 1
                                ).trim();

                        // set the record type:
                        //
                        //     * DRM_LDIF_CA_KEY_RECORD
                        //     * DRM_LDIF_TPS_KEY_RECORD
                        //
                        if (data.startsWith(DRM_LDIF_TPS_KEY_RECORD)) {
                            record_type = DRM_LDIF_TPS_KEY_RECORD;
                        } else if (data.startsWith(DRM_LDIF_CA_KEY_RECORD)) {
                            record_type = DRM_LDIF_CA_KEY_RECORD;
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
                    record_type = DRM_LDIF_RECORD;
                }

                ldif_record = record.iterator();

                // Process each line of the record:
                //   * If LDIF Record Type for this line is 'valid'
                //     * If DRMTOOL Configuration File Parameter is 'true'
                //       * Process this data
                //     * Else If DRMTOOL Configuration File Parameter is 'false'
                //       * Pass through this data unchanged
                //   * Else If LDIF Record Type for this line is 'invalid'
                //     * Log error and leave method returning 'false'
                while (ldif_record.hasNext()) {

                    line = ldif_record.next();

                    if (line.startsWith(DRM_LDIF_CN)) {
                        output = output_cn(record_type, line);
                        if (output == null) {
                            return FAILURE;
                        }
                    } else if (line.startsWith(DRM_LDIF_DATE_OF_MODIFY)) {
                        output = output_date_of_modify(record_type, line);
                        if (output == null) {
                            return FAILURE;
                        }
                    } else if (line.startsWith(DRM_LDIF_DN)) {
                        output = output_dn(record_type, line);
                        if (output == null) {
                            return FAILURE;
                        }
                    } else if (line.startsWith(DRM_LDIF_EXTDATA_KEY_RECORD)) {
                        output = output_extdata_key_record(record_type,
                                                            line);
                        if (output == null) {
                            return FAILURE;
                        }
                    } else if (line.startsWith(DRM_LDIF_EXTDATA_REQUEST_ID)) {
                        output = output_extdata_request_id(record_type,
                                                            line);
                        if (output == null) {
                            return FAILURE;
                        }
                    } else if (line.startsWith(DRM_LDIF_EXTDATA_REQUEST_NOTES)) {
                        output = output_extdata_request_notes(record_type,
                                                               line);
                        if (output == null) {
                            return FAILURE;
                        }
                    } else if (line.startsWith(DRM_LDIF_EXTDATA_REQUEST_TYPE)) {
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
                    } else if (line.startsWith(DRM_LDIF_EXTDATA_SERIAL_NUMBER)) {
                        output = output_extdata_serial_number(record_type,
                                                               line);
                        if (output == null) {
                            return FAILURE;
                        }
                    } else if (line.startsWith(DRM_LDIF_PRIVATE_KEY_DATA)) {
                        output = output_private_key_data(record_type,
                                                          line);
                        if (output == null) {
                            return FAILURE;
                        }
                    } else if (line.startsWith(DRM_LDIF_REQUEST_ID)) {
                        output = output_request_id(record_type, line);
                        if (output == null) {
                            return FAILURE;
                        }
                    } else if (line.startsWith(DRM_LDIF_SERIAL_NO)) {
                        output = output_serial_no(record_type, line);
                        if (output == null) {
                            return FAILURE;
                        }
                    } else if (previous_line != null &&
                               previous_line.startsWith(
                                       DRM_LDIF_EXTDATA_AUTH_TOKEN_USER)) {
                        output = output_extdata_auth_token_user(record_type,
                                                                 line);
                        if (output == null) {
                            return FAILURE;
                        }
                    } else if (previous_line != null &&
                               previous_line.startsWith(
                                       DRM_LDIF_EXTDATA_AUTH_TOKEN_USER_DN)) {
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

    /**************************************/
    /* DRMTOOL Config File Parser Methods */
    /**************************************/

    /**
     * This method performs the actual parsing of the DRMTOOL config file
     * and initializes how the DRM Record Fields should be processed.
     * <P>
     *
     * @return true if the DRMTOOL config file is successfully processed
     */
    private static boolean process_drmtool_config_file() {
        BufferedReader reader = null;
        String line = null;
        String name_value_pair[] = null;
        String name = null;
        Boolean value = null;

        // Process each line containing a name/value pair
        // in the DRMTOOL config file
        try {
            // Open DRMTOOL config file for reading
            reader = new BufferedReader(
                         new FileReader(mDrmtoolCfgFilename));

            // Create a hashtable for relevant name/value pairs
            drmtoolCfg = new Hashtable<String, Boolean>();

            System.out.print("PROCESSING DRMTOOL CONFIG FILE: ");
            while ((line = reader.readLine()) != null) {
                if (line.startsWith(DRMTOOL_CFG_PREFIX)) {
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

                    // store relevant DRM LDIF fields for processing
                    if (name.equals(DRMTOOL_CFG_ENROLLMENT_CN)
                            || name.equals(DRMTOOL_CFG_ENROLLMENT_DATE_OF_MODIFY)
                            || name.equals(DRMTOOL_CFG_ENROLLMENT_DN)
                            || name.equals(DRMTOOL_CFG_ENROLLMENT_EXTDATA_KEY_RECORD)
                            || name.equals(DRMTOOL_CFG_ENROLLMENT_EXTDATA_REQUEST_NOTES)
                            || name.equals(DRMTOOL_CFG_ENROLLMENT_REQUEST_ID)
                            || name.equals(DRMTOOL_CFG_CA_KEY_RECORD_CN)
                            || name.equals(DRMTOOL_CFG_CA_KEY_RECORD_DATE_OF_MODIFY)
                            || name.equals(DRMTOOL_CFG_CA_KEY_RECORD_DN)
                            || name.equals(DRMTOOL_CFG_CA_KEY_RECORD_PRIVATE_KEY_DATA)
                            || name.equals(DRMTOOL_CFG_CA_KEY_RECORD_SERIAL_NO)
                            || name.equals(DRMTOOL_CFG_RECOVERY_CN)
                            || name.equals(DRMTOOL_CFG_RECOVERY_DATE_OF_MODIFY)
                            || name.equals(DRMTOOL_CFG_RECOVERY_DN)
                            || name.equals(DRMTOOL_CFG_RECOVERY_EXTDATA_REQUEST_ID)
                            || name.equals(DRMTOOL_CFG_RECOVERY_EXTDATA_REQUEST_NOTES)
                            || name.equals(DRMTOOL_CFG_RECOVERY_EXTDATA_SERIAL_NUMBER)
                            || name.equals(DRMTOOL_CFG_RECOVERY_REQUEST_ID)
                            || name.equals(DRMTOOL_CFG_TPS_KEY_RECORD_CN)
                            || name.equals(DRMTOOL_CFG_TPS_KEY_RECORD_DATE_OF_MODIFY)
                            || name.equals(DRMTOOL_CFG_TPS_KEY_RECORD_DN)
                            || name.equals(DRMTOOL_CFG_TPS_KEY_RECORD_PRIVATE_KEY_DATA)
                            || name.equals(DRMTOOL_CFG_TPS_KEY_RECORD_SERIAL_NO)
                            || name.equals(DRMTOOL_CFG_KEYGEN_CN)
                            || name.equals(DRMTOOL_CFG_KEYGEN_DATE_OF_MODIFY)
                            || name.equals(DRMTOOL_CFG_KEYGEN_DN)
                            || name.equals(DRMTOOL_CFG_KEYGEN_EXTDATA_KEY_RECORD)
                            || name.equals(DRMTOOL_CFG_KEYGEN_EXTDATA_REQUEST_ID)
                            || name.equals(DRMTOOL_CFG_KEYGEN_EXTDATA_REQUEST_NOTES)
                            || name.equals(DRMTOOL_CFG_KEYGEN_REQUEST_ID)) {
                        drmtoolCfg.put(name, value);
                        System.out.print(".");
                    }
                }
            }
            System.out.println(" FINISHED." + NEWLINE);
        } catch (FileNotFoundException exDrmtoolCfgFileNotFound) {
            log("ERROR:  No DRMTOOL config file named '"
                    + mDrmtoolCfgFilename
                    + "' exists!  FileNotFoundException: '"
                    + exDrmtoolCfgFileNotFound.toString()
                    + "'"
                    + NEWLINE, true);
            return FAILURE;
        } catch (IOException exDrmtoolCfgIO) {
            log("ERROR:  line='"
                    + line
                    + "' IOException: '"
                    + exDrmtoolCfgIO.toString()
                    + "'"
                    + NEWLINE, true);
            return FAILURE;
        } catch (PatternSyntaxException exDrmtoolCfgNameValuePattern) {
            log("ERROR:  line='"
                    + line
                    + "' PatternSyntaxException: '"
                    + exDrmtoolCfgNameValuePattern.toString()
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
        }

        return SUCCESS;
    }

    /************/
    /* DRM Tool */
    /************/

    /**
     * The main DRMTool method.
     * <P>
     *
     * @param args DRMTool options
     */
    public static void main(String[] args) {
        // Variables
        String append_id_offset = null;
        String remove_id_offset = null;
        String process_drm_naming_context_fields = null;
        String process_requests_and_key_records_only = null;
        String use_PKI_security_database_pwdfile = null;
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

        // Check that the correct number of arguments were
        // submitted to the program
        if ((args.length != ID_OFFSET_ARGS) &&
                (args.length != (ID_OFFSET_ARGS + 1)) &&
                (args.length != (ID_OFFSET_ARGS + 4)) &&
                (args.length != (ID_OFFSET_ARGS + 5)) &&
                (args.length != REWRAP_ARGS) &&
                (args.length != (REWRAP_ARGS + 1)) &&
                (args.length != (REWRAP_ARGS + 2)) &&
                (args.length != (REWRAP_ARGS + 3)) &&
                (args.length != (REWRAP_ARGS + 4)) &&
                (args.length != (REWRAP_ARGS + 5)) &&
                (args.length != (REWRAP_ARGS + 6)) &&
                (args.length != (REWRAP_ARGS + 7)) &&
                (args.length != REWRAP_AND_ID_OFFSET_ARGS) &&
                (args.length != (REWRAP_AND_ID_OFFSET_ARGS + 1)) &&
                (args.length != (REWRAP_AND_ID_OFFSET_ARGS + 2)) &&
                (args.length != (REWRAP_AND_ID_OFFSET_ARGS + 3)) &&
                (args.length != (REWRAP_AND_ID_OFFSET_ARGS + 4)) &&
                (args.length != (REWRAP_AND_ID_OFFSET_ARGS + 5)) &&
                (args.length != (REWRAP_AND_ID_OFFSET_ARGS + 6)) &&
                (args.length != (REWRAP_AND_ID_OFFSET_ARGS + 7))) {
            System.err.println("ERROR:  Incorrect number of arguments!"
                              + NEWLINE);
            printUsage();
            System.exit(0);
        }

        // Process command-line arguments
        for (int i = 0; i < args.length; i += 2) {
            if (args[i].equals(DRMTOOL_CFG_FILE)) {
                mDrmtoolCfgFilename = args[i + 1];
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
            } else if (args[i].equals(APPEND_ID_OFFSET)) {
                append_id_offset = args[i + 1];
                mAppendIdOffsetNameValuePairs++;
            } else if (args[i].equals(REMOVE_ID_OFFSET)) {
                remove_id_offset = args[i + 1];
                mRemoveIdOffsetNameValuePairs++;
            } else if (args[i].equals(SOURCE_DRM_NAMING_CONTEXT)) {
                mSourceDrmNamingContext = args[i + 1];
                mDrmNamingContextNameValuePairs++;
            } else if (args[i].equals(TARGET_DRM_NAMING_CONTEXT)) {
                mTargetDrmNamingContext = args[i + 1];
                mDrmNamingContextNameValuePairs++;
            } else if (args[i].equals(PROCESS_REQUESTS_AND_KEY_RECORDS_ONLY)) {
                mProcessRequestsAndKeyRecordsOnlyFlag = true;
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
                mDrmtoolCfgFilename == null ||
                mDrmtoolCfgFilename.length() == 0 ||
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
            // Check for a valid DRMTOOL config file
            cfgFile = new File(mDrmtoolCfgFilename);
            if (!cfgFile.exists() ||
                    !cfgFile.isFile() ||
                    (cfgFile.length() == 0)) {
                System.err.println("ERROR:  '"
                                  + mDrmtoolCfgFilename
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
                                             + DRM_LDIF_USED_PWDFILE_MESSAGE;

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

        // Check to see that if the OPTIONAL 'DRM Naming Context' command-line
        // options were specified, that they are all present and accounted for
        if (mDrmNamingContextNameValuePairs > 0) {
            if (mDrmNamingContextNameValuePairs !=
                    NAMING_CONTEXT_NAME_VALUE_PAIRS ||
                    mSourceDrmNamingContext == null ||
                    mSourceDrmNamingContext.length() == 0 ||
                    mTargetDrmNamingContext == null ||
                    mTargetDrmNamingContext.length() == 0) {
                System.err.println("ERROR:  Both 'source DRM naming context' "
                                  + "and 'target DRM naming context' "
                                  + "options MUST be specified!"
                                  + NEWLINE);
                printUsage();
                System.exit(0);
            } else {
                process_drm_naming_context_fields = SPACE
                                                  + SOURCE_DRM_NAMING_CONTEXT
                                                  + SPACE
                                                  + TIC
                                                  + mSourceDrmNamingContext
                                                  + TIC
                                                  + SPACE
                                                  + TARGET_DRM_NAMING_CONTEXT
                                                  + SPACE
                                                  + TIC
                                                  + mTargetDrmNamingContext
                                                  + TIC;

                mDrmNamingContextMessage = SPACE
                                         + PLUS
                                         + SPACE
                                         + DRM_LDIF_SOURCE_NAME_CONTEXT_MESSAGE
                                         + mSourceDrmNamingContext
                                         + DRM_LDIF_TARGET_NAME_CONTEXT_MESSAGE
                                         + mTargetDrmNamingContext
                                         + TIC;

                // Mark the 'DRM Naming Contexts' flag true
                mDrmNamingContextsFlag = true;
            }
        } else {
            process_drm_naming_context_fields = "";
            mDrmNamingContextMessage = "";
        }

        // Check for OPTIONAL "Process Requests and Key Records ONLY" option
        if (mProcessRequestsAndKeyRecordsOnlyFlag) {
            process_requests_and_key_records_only = SPACE
                                                  + PROCESS_REQUESTS_AND_KEY_RECORDS_ONLY;
            mProcessRequestsAndKeyRecordsOnlyMessage = SPACE + PLUS + SPACE +
                    DRM_LDIF_PROCESS_REQUESTS_AND_KEY_RECORDS_ONLY_MESSAGE;
        } else {
            process_requests_and_key_records_only = "";
            mProcessRequestsAndKeyRecordsOnlyMessage = "";
        }

        // Enable logging process . . .
        open_log(mLogFilename);

        // Begin logging progress . . .
        if (mRewrapFlag && mAppendIdOffsetFlag) {
            log("BEGIN \""
                    + DRM_TOOL + SPACE
                    + DRMTOOL_CFG_FILE + SPACE
                    + mDrmtoolCfgFilename + SPACE
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
                    + process_drm_naming_context_fields
                    + process_requests_and_key_records_only
                    + "\" . . ."
                    + NEWLINE, true);
        } else if (mRewrapFlag && mRemoveIdOffsetFlag) {
            log("BEGIN \""
                    + DRM_TOOL + SPACE
                    + DRMTOOL_CFG_FILE + SPACE
                    + mDrmtoolCfgFilename + SPACE
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
                    + process_drm_naming_context_fields
                    + process_requests_and_key_records_only
                    + "\" . . ."
                    + NEWLINE, true);
        } else if (mRewrapFlag) {
            log("BEGIN \""
                    + DRM_TOOL + SPACE
                    + DRMTOOL_CFG_FILE + SPACE
                    + mDrmtoolCfgFilename + SPACE
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
                    + process_drm_naming_context_fields
                    + process_requests_and_key_records_only
                    + "\" . . ."
                    + NEWLINE, true);
        } else if (mAppendIdOffsetFlag) {
            log("BEGIN \""
                    + DRM_TOOL + SPACE
                    + DRMTOOL_CFG_FILE + SPACE
                    + mDrmtoolCfgFilename + SPACE
                    + SOURCE_LDIF_FILE + SPACE
                    + mSourceLdifFilename + SPACE
                    + TARGET_LDIF_FILE + SPACE
                    + mTargetLdifFilename + SPACE
                    + LOG_FILE + SPACE
                    + mLogFilename + SPACE
                    + APPEND_ID_OFFSET + SPACE
                    + append_id_offset
                    + process_drm_naming_context_fields
                    + process_requests_and_key_records_only
                    + "\" . . ."
                    + NEWLINE, true);
        } else if (mRemoveIdOffsetFlag) {
            log("BEGIN \""
                    + DRM_TOOL + SPACE
                    + DRMTOOL_CFG_FILE + SPACE
                    + mDrmtoolCfgFilename + SPACE
                    + SOURCE_LDIF_FILE + SPACE
                    + mSourceLdifFilename + SPACE
                    + TARGET_LDIF_FILE + SPACE
                    + mTargetLdifFilename + SPACE
                    + LOG_FILE + SPACE
                    + mLogFilename + SPACE
                    + REMOVE_ID_OFFSET + SPACE
                    + remove_id_offset
                    + process_drm_naming_context_fields
                    + process_requests_and_key_records_only
                    + "\" . . ."
                    + NEWLINE, true);
        }

        // Process the DRMTOOL config file
        success = process_drmtool_config_file();
        if (!success) {
            log("FAILED processing drmtool config file!"
                    + NEWLINE, true);
        } else {
            log("SUCCESSFULLY processed drmtool config file!"
                    + NEWLINE, true);

            // Convert the source LDIF file to a target LDIF file
            success = convert_source_ldif_to_target_ldif();
            if (!success) {
                log("FAILED converting source LDIF file --> target LDIF file!"
                        + NEWLINE, true);
            } else {
                log("SUCCESSFULLY converted source LDIF file --> "
                        + "target LDIF file!"
                        + NEWLINE, true);
            }
        }

        // Finish logging progress
        if (mRewrapFlag && mAppendIdOffsetFlag) {
            log("FINISHED \""
                    + DRM_TOOL + SPACE
                    + DRMTOOL_CFG_FILE + SPACE
                    + mDrmtoolCfgFilename + SPACE
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
                    + process_drm_naming_context_fields
                    + process_requests_and_key_records_only
                    + "\"."
                    + NEWLINE, true);
        } else if (mRewrapFlag && mRemoveIdOffsetFlag) {
            log("FINISHED \""
                    + DRM_TOOL + SPACE
                    + DRMTOOL_CFG_FILE + SPACE
                    + mDrmtoolCfgFilename + SPACE
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
                    + process_drm_naming_context_fields
                    + process_requests_and_key_records_only
                    + "\"."
                    + NEWLINE, true);
        } else if (mRewrapFlag) {
            log("FINISHED \""
                    + DRM_TOOL + SPACE
                    + DRMTOOL_CFG_FILE + SPACE
                    + mDrmtoolCfgFilename + SPACE
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
                    + process_drm_naming_context_fields
                    + process_requests_and_key_records_only
                    + "\"."
                    + NEWLINE, true);
        } else if (mAppendIdOffsetFlag) {
            log("FINISHED \""
                    + DRM_TOOL + SPACE
                    + DRMTOOL_CFG_FILE + SPACE
                    + mDrmtoolCfgFilename + SPACE
                    + SOURCE_LDIF_FILE + SPACE
                    + mSourceLdifFilename + SPACE
                    + TARGET_LDIF_FILE + SPACE
                    + mTargetLdifFilename + SPACE
                    + LOG_FILE + SPACE
                    + mLogFilename + SPACE
                    + APPEND_ID_OFFSET + SPACE
                    + append_id_offset
                    + process_drm_naming_context_fields
                    + process_requests_and_key_records_only
                    + "\"."
                    + NEWLINE, true);
        } else if (mRemoveIdOffsetFlag) {
            log("FINISHED \""
                    + DRM_TOOL + SPACE
                    + DRMTOOL_CFG_FILE + SPACE
                    + mDrmtoolCfgFilename + SPACE
                    + SOURCE_LDIF_FILE + SPACE
                    + mSourceLdifFilename + SPACE
                    + TARGET_LDIF_FILE + SPACE
                    + mTargetLdifFilename + SPACE
                    + LOG_FILE + SPACE
                    + mLogFilename + SPACE
                    + REMOVE_ID_OFFSET + SPACE
                    + remove_id_offset
                    + process_drm_naming_context_fields
                    + process_requests_and_key_records_only
                    + "\"."
                    + NEWLINE, true);
        }

        // Shutdown logging process
        close_log(mLogFilename);
    }
}
