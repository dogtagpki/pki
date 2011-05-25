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

import java.io.*;
import java.lang.*;
import java.math.*;
import java.security.cert.CertificateException;
import java.security.*;
import java.text.MessageFormat;
import java.text.SimpleDateFormat;
import java.util.regex.PatternSyntaxException;
import java.util.*;
import netscape.security.provider.RSAPublicKey;
import netscape.security.util.*;
import netscape.security.x509.*;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.pkcs11.PK11PubKey;
import org.mozilla.jss.*;

/**
 * The DRMTool class is a utility program designed to operate on an LDIF file
 * to perform one or more of the following tasks:
 * <PRE>
 *     (A) Use a new storage key (e. g. - a 2048-bit key to replace a
 *         1024-bit key) to rewrap the existing triple DES symmetric key
 *         that was used to wrap a user's private key.
 *
 *         STARTING INVENTORY:
 *
 *             (1) an LDIF file containing 'exported' DRM data
 *                 (referred to as the "source" DRM)
 *
 *                 NOTE:  If this LDIF file contains data that was originally
 *                        from a DRM instance that was prior to RHCS 8, it
 *                        must have previously undergone the appropriate
 *                        migration steps.
 *
 *             (2) the NSS security databases (e. g. - cert8.db, key3.db,
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
 *             (3) a file containing the ASCII BASE-64 storage certificate
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
 *             (1) the name of the input LDIF file containing data which was
 *                 'exported' from the source DRM instance
 *
 *             (2) the name of the output LDIF file intended to contain the
 *                 revised data suitable for 'import' to a target DRM instance
 *
 *             (3) the name of the log file that may be used for auditing
 *                 purposes
 *
 *             (4) the path to the security databases that were used by
 *                 the source DRM instance
 *
 *             (5) the name of the token that was used by
 *                 the source DRM instance
 *
 *             (6) the name of the storage certificate that was used by
 *                 the source DRM instance
 *
 *             (7) the name of the file containing the ASCII BASE-64 storage
 *                 certificate from the target DRM instance for which the
 *                 output LDIF file is intended
 *
 *         DATA FIELDS AFFECTED:
 *
 *             (1) CA DRM enrollment request
 *
 *                 (a) dateOfModify
 *                 (b) extdata-requestnotes
 *
 *             (2) CA DRM keyrecord
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
 *             (5) TPS DRM keyrecord
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
 *             (1) an LDIF file containing 'exported' DRM data
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
 *             (1) the name of the input LDIF file containing data which was
 *                 'exported' from the source DRM instance
 *
 *             (2) the name of the output LDIF file intended to contain the
 *                 revised data suitable for 'import' to a target DRM instance
 *
 *             (3) the name of the log file that may be used for auditing
 *                 purposes
 *
 *             (4) a large numeric ID offset (mask) to be appended to existing
 *                 numeric data in the source DRM instance's LDIF file
 *
 *         DATA FIELDS AFFECTED:
 *
 *             (1) CA DRM enrollment request
 *
 *                 (a) cn
 *                 (b) dateOfModify
 *                 (c) extdata-keyrecord
 *                 (d) extdata-requestid
 *                 (e) extdata-requestnotes
 *                 (f) requestId
 *
 *             (2) CA DRM keyrecord
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
 *                 (e) extdata-serialno
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
 *             (5) TPS DRM keyrecord
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
 *                 (e) extdata-serialno
 *                 (f) requestId
 *
 *     (C) Specify an ID offset to be removed from existing numeric data
 *         (e. g. - to undo renumbering used in DRM consolidation efforts).
 *
 *         STARTING INVENTORY:
 *
 *             (1) an LDIF file containing 'exported' DRM data
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
 *             (1) the name of the input LDIF file containing data which was
 *                 'exported' from the source DRM instance
 *
 *             (2) the name of the output LDIF file intended to contain the
 *                 revised data suitable for 'import' to a target DRM instance
 *
 *             (3) the name of the log file that may be used for auditing
 *                 purposes
 *
 *             (4) a large numeric ID offset (mask) to be removed from existing
 *                 numeric data in the source DRM instance's LDIF file
 *
 *         DATA FIELDS AFFECTED:
 *
 *             (1) CA DRM enrollment request
 *
 *                 (a) cn
 *                 (b) dateOfModify
 *                 (c) extdata-keyrecord
 *                 (d) extdata-requestid
 *                 (e) extdata-requestnotes
 *                 (f) requestId
 *
 *             (2) CA DRM keyrecord
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
 *                 (e) extdata-serialno
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
 *             (5) TPS DRM keyrecord
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
 *                 (e) extdata-serialno
 *                 (f) requestId
 *
 * </PRE>
 *
 * <P>
 * DRMTool may be invoked as follows:
 * <PRE>
 *
 *    DRMTool
 *    -source_ldif_file &lt;path + source ldif file&gt;
 *    -target_ldif_file &lt;path + target ldif file&gt;
 *    -log_file &lt;path + log file&gt;
 *    [-source_pki_security_database_path &lt;path to PKI source database&gt;]
 *    [-source_storage_token_name '&lt;source token&gt;']
 *    [-source_storage_certificate_nickname '&lt;source nickname&gt;']
 *    [-target_storage_certificate_file &lt;path to target certificate file&gt;]
 *    [-append_id_offset &lt;numeric offset&gt;]
 *    [-remove_id_offset &lt;numeric offset&gt;]
 *
 *    where the following options are 'Mandatory':
 *
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
 *        (b) option for appending the specified numeric ID offset
 *            to existing numerical data:
 *
 *            [-append_id_offset &lt;numeric offset&gt;]
 *
 *        (c) option for removing the specified numeric ID offset
 *            from existing numerical data:
 *
 *            [-remove_id_offset &lt;numeric offset&gt;]
 *
 *        (d) (a) rewrap AND (b) append ID offset
 *
 *        (e) (a) rewrap AND (c) remove ID offset
 *
 *        NOTE:  Options (b) and (c) are mutually exclusive!
 *
 * </PRE>
 *
 * @author mharmsen
 * @version $Revision$, $Date$
 */
public class DRMTool
{
    /*************/
    /* Constants */
    /*************/

    // Constants:  Miscellaneous
    private static final boolean FAILURE = false;
    private static final boolean SUCCESS = true;
    private static final String COLON = ":";
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
    private static final String STORAGE_NICKNAME = "storageCert cert-pki-kra";
    private static final String TARGET_STORAGE_CERT = "target_storage.cert";
    private static final String ID_OFFSET_VALUE = "10000000";


    // Constants:  Command-line Options
    private static final int ID_OFFSET_NAME_VALUE_PAIRS = 1;
    private static final int MANDATORY_NAME_VALUE_PAIRS = 3;
    private static final int REWRAP_NAME_VALUE_PAIRS = 4;
    private static final int ID_OFFSET_ARGS = 8;
    private static final int REWRAP_ARGS = 14;
    private static final int REWRAP_AND_ID_OFFSET_ARGS = 16;


    // Constants:  Command-line Options (Mandatory)
    private static final String DRM_TOOL = "DRMTool";

    private static final String
    SOURCE_LDIF_FILE = "-source_ldif_file";

    private static final String
    SOURCE_LDIF_DESCRIPTION = " <complete path to the source LDIF input file"
                            + NEWLINE
                            + "        "
                            + "  ending with the source LDIF file name>";

    private static final String
    SOURCE_LDIF_FILE_EXAMPLE = "-source_ldif_file /export/pki/source.ldif";

    private static final String
    TARGET_LDIF_FILE = "-target_ldif_file";

    private static final String
    TARGET_LDIF_DESCRIPTION = " <complete path to the target LDIF output file"
                            + NEWLINE
                            + "        "
                            + "  ending with the target LDIF file name>";

    private static final String
    TARGET_LDIF_FILE_EXAMPLE = "-target_ldif_file /export/pki/target.ldif";

    private static final String
    LOG_FILE = "-log_file";

    private static final String
    LOG_DESCRIPTION = " <complete path to the log file"
                    + NEWLINE
                    + "        "
                    + "  ending with the log file name>";

    private static final String
    LOG_FILE_EXAMPLE = "-log_file /export/pki/drmtool.log";


    // Constants:  Command-line Options (Rewrap)
    private static final String
    SOURCE_NSS_DB_PATH = "-source_pki_security_database_path";

    private static final String
    SOURCE_NSS_DB_DESCRIPTION = "  <complete path to the "
                              + "source security databases"
                              + NEWLINE
                              + "        "
                              + "   used by data in the source LDIF file>";

    private static final String
    SOURCE_NSS_DB_PATH_EXAMPLE = "-source_pki_security_database_path "
                               + "/export/pki";

    private static final String
    SOURCE_STORAGE_TOKEN_NAME = "-source_storage_token_name";

    private static final String
    SOURCE_STORAGE_TOKEN_DESCRIPTION = "  <name of the token containing "
                                     + "the source storage token>";

    private static final String
    SOURCE_STORAGE_TOKEN_NAME_EXAMPLE = "-source_storage_token_name "
                                      + "\'"
                                      + INTERNAL_TOKEN
                                      + "\'";

    private static final String
    SOURCE_STORAGE_CERT_NICKNAME = "-source_storage_certificate_nickname";

    private static final String
    SOURCE_STORAGE_CERT_NICKNAME_DESCRIPTION = "  <nickname of the source "
                                             + "storage certificate>";

    private static final String
    SOURCE_STORAGE_CERT_NICKNAME_EXAMPLE =
                                         "-source_storage_certificate_nickname"
                                         + " \'"
                                         + STORAGE_NICKNAME
                                         + "\'";

    private static final String
    TARGET_STORAGE_CERTIFICATE_FILE = "-target_storage_certificate_file";

    private static final String
    TARGET_STORAGE_CERTIFICATE_DESCRIPTION = "  <complete path to the target "
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

    private static final String
    TARGET_STORAGE_CERTIFICATE_FILE_EXAMPLE = "-target_storage_certificate_file"
                                            + " /export/pki/"
                                            + TARGET_STORAGE_CERT;


    // Constants:  Command-line Options (ID Offset)
    private static final String
    APPEND_ID_OFFSET = "-append_id_offset";

    private static final String
    APPEND_ID_OFFSET_DESCRIPTION = "  <ID offset that is appended to "
                                 + "each record's source ID>";

    private static final String
    APPEND_ID_OFFSET_EXAMPLE = "-append_id_offset "
                             + ID_OFFSET_VALUE;

    private static final String
    REMOVE_ID_OFFSET = "-remove_id_offset";

    private static final String
    REMOVE_ID_OFFSET_DESCRIPTION = "  <ID offset that is removed from "
                                 + "each record's source ID>";

    private static final String
    REMOVE_ID_OFFSET_EXAMPLE = "-remove_id_offset "
                             + ID_OFFSET_VALUE;


    // Constants:  Target Certificate Information
    private static final String HEADER = "-----BEGIN";
    private static final String TRAILER = "-----END";
    private static final String X509_INFO = "x509.INFO";


    // Constants:  DRM LDIF Record Fields (always include trailing space)
    private static final String CN = "cn:";
    private static final String DATE_OF_MODIFY = "dateOfModify:";
    private static final String EXTDATA_KEYRECORD = "extdata-keyrecord:";
    private static final String EXTDATA_REQUESTID = "extdata-requestid:";
    private static final String EXTDATA_REQUESTNOTES = "extdata-requestnotes:";
    private static final String EXTDATA_REQUEST_TYPE = "extdata-requesttype:";
    private static final String EXTDATA_SERIALNUMBER = "extdata-serialnumber:";
    private static final String PRIVATE_KEY_DATA = "privateKeyData::";
    private static final String REQUESTID = "requestId:";
    private static final String SERIALNO = "serialno:";


    // Constants:  DRM LDIF Record Values
    private static final String NETKEY_KEYGEN = "netkeyKeygen";
    private static final String RECOVERY = "recovery";
    private static final String REWRAP_MESSAGE = "REWRAPPED the existing '"
                                               + "DES3 symmetric session key"
                                               + "' with the '";
    private static final String RSA_MESSAGE = "-bit RSA public key' obtained "
                                            + "from the target storage "
                                            + "certificate";
    private static final String APPENDED_ID_OFFSET_MESSAGE = "APPENDED "
                                                           + "ID OFFSET";
    private static final String REMOVED_ID_OFFSET_MESSAGE = "REMOVED "
                                                          + "ID OFFSET";


    /*************/
    /* Variables */
    /*************/

    // Variables:  Calendar
    private static String mDateOfModify = null;


    // Variables: Command-Line Options
    private static boolean mMandatoryFlag = false;
    private static boolean mRewrapFlag = false;
    private static boolean mAppendIdOffsetFlag = false;
    private static boolean mRemoveIdOffsetFlag = false;
    private static int mMandatoryNameValuePairs = 0;
    private static int mRewrapNameValuePairs = 0;
    private static int mAppendIdOffsetNameValuePairs = 0;
    private static int mRemoveIdOffsetNameValuePairs = 0;


    // Variables: Command-Line Values (Mandatory)
    private static String mSourceLdifFilename = null;
    private static String mTargetLdifFilename = null;
    private static String mLogFilename = null;


    // Variables: Command-Line Values (Rewrap)
    private static String mSourcePKISecurityDatabasePath = null;
    private static String mSourceStorageTokenName = null;
    private static String mSourceStorageCertNickname = null;
    private static String mTargetStorageCertificateFilename = null;


    // Variables: Command-Line Values (ID Offset)
    private static BigInteger mAppendIdOffset = null;
    private static BigInteger mRemoveIdOffset = null;


    // Variables:  Logging
    private static boolean mDebug = false;  // set 'true' for debug messages
    private static PrintWriter logger = null;
    private static String current_date_and_time = null;


    // Variables:  PKCS #11 Information
    private static CryptoToken mInternalToken = null;
    private static CryptoToken mSourceToken = null;
    private static X509Certificate mUnwrapCert = null;
    private static PrivateKey mUnwrapPrivateKey = null;
    private static PublicKey mWrapPublicKey = null;
    private static int mPublicKeySize = 0;


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
    private static String now( String pattern ) {
        Calendar cal = Calendar.getInstance();
        SimpleDateFormat sdf = new SimpleDateFormat( pattern );
        return sdf.format( cal.getTime() );
    }


    /*****************/
    /* Usage Methods */
    /*****************/

    /**
     * This method prints out the proper command-line usage required to
     * execute DRMTool.
     */
    private static void printUsage() {
        System.out.println( "Usage:  "
                          + DRM_TOOL
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
                          + NEWLINE );

        System.out.println( "Example of 'Rewrap and Append ID Offset':"
                          + NEWLINE
                          + NEWLINE
                          + "        "
                          + DRM_TOOL
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
                          + APPEND_ID_OFFSET_EXAMPLE
                          + NEWLINE );

        System.out.println( "Example of 'Rewrap and Remove ID Offset':"
                          + NEWLINE
                          + NEWLINE
                          + "        "
                          + DRM_TOOL
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
                          + REMOVE_ID_OFFSET_EXAMPLE
                          + NEWLINE );

        System.out.println( "Example of 'Rewrap':"
                          + NEWLINE
                          + NEWLINE
                          + "        "
                          + DRM_TOOL
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
                          + NEWLINE );

        System.out.println( "Example of 'Append ID Offset':"
                          + NEWLINE
                          + NEWLINE
                          + "        "
                          + DRM_TOOL
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
                          + NEWLINE );

        System.out.println( "Example of 'Remove ID Offset':"
                          + NEWLINE
                          + NEWLINE
                          + "        "
                          + DRM_TOOL
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
                          + NEWLINE );
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
    private static void open_log( String logfile ) {
        try {
            logger = new PrintWriter(
                         new BufferedWriter(
                             new FileWriter( logfile ) ) );
        } catch( IOException eFile ) {
            System.err.println( "ERROR:  Unable to open file '"
                              + logfile
                              + "' for writing: '"
                              + eFile
                              + "'"
                              + NEWLINE );
            System.exit( 0 );
        }
    }


    /**
     * This method closes the specified log file.
     * <P>
     *
     * @param logfile string containing the name of the log file to be closed
     */
    private static void close_log( String logfile ) {
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
    private static void log( String msg, boolean stderr ) {
        current_date_and_time = now( LOGGING_DATE_PATTERN );
        if( stderr ) {
            System.err.println( msg );
        }
        logger.write( "["
                    + current_date_and_time
                    + "]:  "
                    + msg );
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
    private static boolean arraysEqual( byte[] bytes, byte[] ints ) {
        if( bytes == null || ints == null ) {
            return false;
        }

        if( bytes.length != ints.length ) {
            return false;
        }

        for( int i = 0; i < bytes.length; i++ ) {
            if( bytes[i] != ints[i] ) {
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

             for( int i = 0; i < pk.length; i++ ) {
                 if( arraysEqual( pk[i].getUniqueID(),
                                  ( ( TokenCertificate )
                                    mUnwrapCert ).getUniqueID() ) ) {
                         return pk[i];
                 }
             }
        } catch( TokenException exToken ) {
            log( "ERROR:  Getting private key - "
               + "TokenException: '"
               + exToken
               + "'"
               + NEWLINE, true );
            System.exit( 0 );
        }

        return null;
    }


    /**
     * This method gets the public key from the certificate stored
     * in the "target" DRM storage certificate file.  It also obtains
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
        String encodedBASE64CertChunk = new String();
        String encodedBASE64Cert = new String();
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
                                    ) ) ) );
        } catch( FileNotFoundException exWrapFileNotFound ) {
            log( "ERROR:  No target storage "
               + "certificate file named '"
               + mTargetStorageCertificateFilename
               + "' exists!  FileNotFoundException: '"
               + exWrapFileNotFound
               + "'"
               + NEWLINE, true );
            System.exit( 0 );
        }

        // Read the entire contents of the specified BASE 64 encoded
        // certificate into a String() object throwing away any
        // headers beginning with HEADER and any trailers beginning
        // with TRAILER
        try {
            while( ( encodedBASE64CertChunk = inputCert.readLine() ) != null ) {
                if( !( encodedBASE64CertChunk.startsWith( HEADER ) ) &&
                    !( encodedBASE64CertChunk.startsWith( TRAILER ) ) ) {
                    encodedBASE64Cert += encodedBASE64CertChunk.trim();
                }
            }
        } catch( IOException exWrapReadLineIO ) {
            log( "ERROR:  Unexpected BASE64 "
               + "encoded error encountered while reading '"
               + mTargetStorageCertificateFilename
               + "'!  IOException: '"
               + exWrapReadLineIO
               + "'"
               + NEWLINE, true );
            System.exit( 0 );
        }

        // Close the DataInputStream() object
        try {
            inputCert.close();
        } catch( IOException exWrapCloseIO ) {
            log( "ERROR:  Unexpected BASE64 "
               + "encoded error encountered in closing '"
               + mTargetStorageCertificateFilename
               + "'!  IOException: '"
               + exWrapCloseIO
               + "'"
               + NEWLINE, true );
            System.exit( 0 );
        }

        // Decode the ASCII BASE 64 certificate enclosed in the
        // String() object into a BINARY BASE 64 byte[] object
        decodedBASE64Cert = com.netscape.osutil.OSUtil.AtoB(
                                encodedBASE64Cert );

        // Create an X509CertImpl() object from
        // the BINARY BASE 64 byte[] object
        try {
            cert = new X509CertImpl( decodedBASE64Cert );
            if( cert == null ) {
                log( "ERROR:  Unable to parse "
                   + "certificate from '"
                   + mTargetStorageCertificateFilename
                   + "'."
                   + NEWLINE, true );
                System.exit( 0 );
            }
        } catch( CertificateException exWrapCertificate ) {
            log( "ERROR:  Error encountered "
               + "in parsing certificate in '"
               + mTargetStorageCertificateFilename
               + "'  CertificateException: '"
               + exWrapCertificate
               + "'"
               + NEWLINE, true );
            System.exit( 0 );
        }

        // Extract the Public Key
        key = cert.getPublicKey();
        if( key == null ) {
            log( "ERROR:  Unable to extract public key "
               + "from certificate that was stored in '"
               + mTargetStorageCertificateFilename
               + "'."
               + NEWLINE, true );
            System.exit( 0 );
        }

        // Convert this X.509 public key --> RSA public key
        try {
            rsakey = new RSAPublicKey( key.getEncoded() );
        } catch( InvalidKeyException exInvalidKey ) {
            log( "ERROR:  Converting X.509 public key --> RSA public key - "
               + "InvalidKeyException: '"
               + exInvalidKey
               + "'"
               + NEWLINE, true );
            System.exit( 0 );
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
            log( "Initializing source PKI security databases in '"
               + mSourcePKISecurityDatabasePath + "'."
               + NEWLINE, true );

            CryptoManager.initialize( mSourcePKISecurityDatabasePath );
        } catch( KeyDatabaseException exKey ) {
            log( "ERROR:  source_pki_security_database_path='"
               + mSourcePKISecurityDatabasePath
               + "' KeyDatabaseException: '"
               + exKey
               + "'"
               + NEWLINE, true );
            System.exit( 0 );
        } catch( CertDatabaseException exCert ) {
            log( "ERROR:  source_pki_security_database_path='"
               + mSourcePKISecurityDatabasePath
               + "' CertDatabaseException: '"
               + exCert
               + "'"
               + NEWLINE, true );
            System.exit( 0 );
        } catch( AlreadyInitializedException exAlreadyInitialized ) {
            log( "ERROR:  source_pki_security_database_path='"
               + mSourcePKISecurityDatabasePath
               + "' AlreadyInitializedException: '"
               + exAlreadyInitialized
               + "'"
               + NEWLINE, true );
            System.exit( 0 );
        } catch( GeneralSecurityException exSecurity ) {
            log( "ERROR:  source_pki_security_database_path='"
               + mSourcePKISecurityDatabasePath
               + "' GeneralSecurityException: '"
               + exSecurity
               + "'"
               + NEWLINE, true );
            System.exit( 0 );
        }

        // Retrieve the internal token from the source database
        try {
            log( "Retrieving internal token from CryptoManager."
               + NEWLINE, true );
            cm = CryptoManager.getInstance();

            mInternalToken = cm.getInternalKeyStorageToken();
            if( mInternalToken == null ) {
                return FAILURE;
            }
        } catch( Exception exUninitialized ) {
            log( "ERROR:  Uninitialized CryptoManager - '"
               + exUninitialized
               + "'"
               + NEWLINE, true );
            System.exit( 0 );
        }

        // Retrieve the source storage token by its name
        try {
            log( "Retrieving source storage token called '"
               + mSourceStorageTokenName
               + "'."
               + NEWLINE, true );

            mSourceToken = cm.getTokenByName( mSourceStorageTokenName );
            if( mSourceToken == null ) {
                return FAILURE;
            }
        } catch( NoSuchTokenException exToken ) {
            log( "ERROR:  No source storage token named '"
               + mSourceStorageTokenName
               + "' exists!  NoSuchTokenException: '"
               + exToken
               + "'"
               + NEWLINE, true );
            System.exit( 0 );
        }

        // Retrieve the source storage cert by its nickname
        try {
            if( mSourceStorageTokenName.equals( INTERNAL_TOKEN ) ) {
                log( "Retrieving source storage cert with nickname of '"
                   + mSourceStorageCertNickname
                   + "'."
                   + NEWLINE, true );

                mUnwrapCert = cm.findCertByNickname( mSourceStorageCertNickname
                                                   );
            } else {
                log( "Retrieving source storage cert with nickname of '"
                   + mSourceStorageTokenName
                   + ":"
                   + mSourceStorageCertNickname
                   + "'. "
                   + NEWLINE, true );
                mUnwrapCert = cm.findCertByNickname( mSourceStorageTokenName
                                                   + ":"
                                                   + mSourceStorageCertNickname
                                                   );
            }

            if( mUnwrapCert == null ) {
                return FAILURE;
            }
        } catch( ObjectNotFoundException exUnwrapObjectNotFound ) {
            if( mSourceStorageTokenName.equals( INTERNAL_TOKEN ) ) {
                log( "ERROR:  No internal "
                   + "source storage cert named '"
                   + mSourceStorageCertNickname
                   + "' exists!  ObjectNotFoundException: '"
                   + exUnwrapObjectNotFound
                   + "'"
                   + NEWLINE, true );
            } else {
                log( "ERROR:  No "
                   + "source storage cert named '"
                   + mSourceStorageTokenName
                   + ":"
                   + mSourceStorageCertNickname
                   + "' exists!  ObjectNotFoundException: '"
                   + exUnwrapObjectNotFound
                   + "'"
                   + NEWLINE, true );
            }
            System.exit( 0 );
        } catch( TokenException exUnwrapToken ) {
            if( mSourceStorageTokenName.equals( INTERNAL_TOKEN ) ) {
                log( "ERROR:  No internal "
                   + "source storage cert named '"
                   + mSourceStorageCertNickname
                   + "' exists!  TokenException: '"
                   + exUnwrapToken
                   + "'"
                   + NEWLINE, true );
            } else {
                log( "ERROR:  No "
                   + "source storage cert named '"
                   + mSourceStorageTokenName
                   + ":"
                   + mSourceStorageCertNickname
                   + "' exists!  TokenException: '"
                   + exUnwrapToken
                   + "'"
                   + NEWLINE, true );
            }
            System.exit( 0 );
        }


        // Extract the private key from the source storage token
        log( "BEGIN: Obtaining the private key from "
           + "the source storage token . . ."
           + NEWLINE, true );

        mUnwrapPrivateKey = getPrivateKey();

        if( mUnwrapPrivateKey == null ) {
            log( "ERROR:  Failed extracting "
               + "private key from the source storage token."
               + NEWLINE, true );
            System.exit( 0 );
        }

        log( "FINISHED: Obtaining the private key from "
           + "the source storage token."
           + NEWLINE, true );


        // Extract the public key from the target storage certificate
        try {
            log( "BEGIN: Obtaining the public key from "
               + "the target storage certificate . . ."
               + NEWLINE, true );

            mWrapPublicKey = ( PublicKey )
                             ( PK11PubKey.fromSPKI(
                                 getPublicKey().getEncoded() ) );

            if( mWrapPublicKey == null ) {
                log( "ERROR:  Failed extracting "
                   + "public key from target storage certificate stored in '"
                   + mTargetStorageCertificateFilename
                   + "'"
                   + NEWLINE, true );
                System.exit( 0 );
            }

            log( "FINISHED: Obtaining the public key from "
               + "the target storage certificate."
               + NEWLINE, true );
        } catch( InvalidKeyFormatException exInvalidPublicKey ) {
            log( "ERROR:  Failed extracting "
               + "public key from target storage certificate stored in '"
               + mTargetStorageCertificateFilename
               + "' InvalidKeyFormatException '"
               + exInvalidPublicKey
               + "'"
               + NEWLINE, true );
            System.exit( 0 );
        }

        return SUCCESS;
    }


    /**
     * This method basically rewraps the "wrappedKeyData" by implementiing
     * "mStorageUnit.decryptInternalPrivate( byte wrappedKeyData[] )" and
     * "mStorageUnit.encryptInternalPrivate( byte priKey[] )", where
     * "wrappedKeyData" uses the following structure:
     *
     *     SEQUENCE {
     *         encryptedSession OCTET STRING,
     *         encryptedPrivate OCTET STRING
     *     }
     *
     * This method is based upon code from
     * 'com.netscape.kra.EncryptionUnit'.
     * <P>
     *
     * @return a byte[] containing the rewrappedKeyData
     */
    private static byte[] rewrap_wrapped_key_data( byte[] wrappedKeyData )
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
        DerOutputStream out = null;
        byte[] rewrappedKeyData = null;

        // public byte[]
        // mStorageUnit.decryptInternalPrivate( byte wrappedKeyData[] );
        // throws EBaseException
        try {
            val = new DerValue( wrappedKeyData );
            in = val.data;
            dSession = in.getDerValue();
            source_session = dSession.getOctetString();
            dPri = in.getDerValue();
            pri = dPri.getOctetString();
            source_rsaWrap = mSourceToken.getKeyWrapper(
                                 KeyWrapAlgorithm.RSA );
            source_rsaWrap.initUnwrap( mUnwrapPrivateKey, null );
            sk = source_rsaWrap.unwrapSymmetric( source_session,
                                                 SymmetricKey.DES3,
                                                 SymmetricKey.Usage.DECRYPT,
                                                 0 );
            if( mDebug ) {
                log( "DEBUG: sk = '"
                   + com.netscape.osutil.OSUtil.BtoA( sk.getEncoded() )
                   + "' length = '"
                   + sk.getEncoded().length
                   + "'"
                   + NEWLINE, false );
                log( "DEBUG: pri = '"
                   + com.netscape.osutil.OSUtil.BtoA( pri )
                   + "' length = '"
                   + pri.length
                   + "'"
                   + NEWLINE, false );
            }
        } catch( IOException exUnwrapIO ) {
            log( "ERROR:  Unwrapping key data - "
               + "IOException: '"
               + exUnwrapIO
               + "'"
               + NEWLINE, true );
            System.exit( 0 );
        } catch( NoSuchAlgorithmException exUnwrapAlgorithm ) {
            log( "ERROR:  Unwrapping key data - "
               + "NoSuchAlgorithmException: '"
               + exUnwrapAlgorithm
               + "'"
               + NEWLINE, true );
            System.exit( 0 );
        } catch( TokenException exUnwrapToken ) {
            log( "ERROR:  Unwrapping key data - "
               + "TokenException: '"
               + exUnwrapToken
               + "'"
               + NEWLINE, true );
            System.exit( 0 );
        } catch( InvalidKeyException exUnwrapInvalidKey ) {
            log( "ERROR:  Unwrapping key data - "
               + "InvalidKeyException: '"
               + exUnwrapInvalidKey
               + "'"
               + NEWLINE, true );
            System.exit( 0 );
        } catch( InvalidAlgorithmParameterException exUnwrapInvalidAlgorithm ) {
            log( "ERROR:  Unwrapping key data - "
               + "InvalidAlgorithmParameterException: '"
               + exUnwrapInvalidAlgorithm
               + "'"
               + NEWLINE, true );
            System.exit( 0 );
        } catch( IllegalStateException exUnwrapState ) {
            log( "ERROR:  Unwrapping key data - "
               + "InvalidStateException: '"
               + exUnwrapState
               + "'"
               + NEWLINE, true );
            System.exit( 0 );
        }

        // public byte[]
        // mStorageUnit.encryptInternalPrivate( byte priKey[] )
        // throws EBaseException
        try {
            // Use "mInternalToken" to get "KeyWrapAlgorithm.RSA"
            target_rsaWrap = mInternalToken.getKeyWrapper(
                                 KeyWrapAlgorithm.RSA );
            target_rsaWrap.initWrap( mWrapPublicKey, null );
            target_session = target_rsaWrap.wrap( sk );

            tmp = new DerOutputStream();
            out = new DerOutputStream();

            tmp.putOctetString( target_session );
            tmp.putOctetString( pri );
            out.write( DerValue.tag_Sequence, tmp );

            rewrappedKeyData = out.toByteArray();
        } catch( NoSuchAlgorithmException exWrapAlgorithm ) {
            log( "ERROR:  Wrapping key data - "
               + "NoSuchAlgorithmException: '"
               + exWrapAlgorithm
               + "'"
               + NEWLINE, true );
            System.exit( 0 );
        } catch( TokenException exWrapToken ) {
            log( "ERROR:  Wrapping key data - "
               + "TokenException: '"
               + exWrapToken
               + "'"
               + NEWLINE, true );
            System.exit( 0 );
        } catch( InvalidKeyException exWrapInvalidKey ) {
            log( "ERROR:  Wrapping key data - "
               + "InvalidKeyException: '"
               + exWrapInvalidKey
               + "'"
               + NEWLINE, true );
            System.exit( 0 );
        } catch( InvalidAlgorithmParameterException exWrapInvalidAlgorithm ) {
            log( "ERROR:  Wrapping key data - "
               + "InvalidAlgorithmParameterException: '"
               + exWrapInvalidAlgorithm
               + "'"
               + NEWLINE, true );
            System.exit( 0 );
        } catch( IllegalStateException exWrapState ) {
            log( "ERROR:  Wrapping key data - "
               + "InvalidStateException: '"
               + exWrapState
               + "'"
               + NEWLINE, true );
            System.exit( 0 );
        } catch( IOException exWrapIO ) {
            log( "ERROR:  Wrapping key data - "
               + "IOException: '"
               + exWrapIO
               + "'"
               + NEWLINE, true );
            System.exit( 0 );
        }

        return rewrappedKeyData;
    }


    /**
     * Helper method used to remove all EOLs ('\n' and '\r')
     * from the passed in string.
     * <P>
     *
     * @param data consisting of an ASCII BASE 64 string containing EOLs
     * @return a string consisting of an ASCII BASE 64 string with no EOLs
     */
    private static String stripEOL( String data ) {
        StringBuffer buffer = new StringBuffer();
        String revised_data = null;

        for( int i = 0; i < data.length(); i++ ) {
            if( ( data.charAt(i) != '\n' ) &&
                ( data.charAt(i) != '\r' ) ) {
                buffer.append( data.charAt( i ) );
            }
        }

        revised_data = buffer.toString();

        return revised_data;
    }


    /**
     * Helper method used to format the unformatted string containing an
     * ASCII BASE 64 string into an ASCII BASE 64 string suitable as an
     * entry for an LDIF file.
     * <P>
     *
     * @param an unformatted string containing an ASCII BASE 64 string
     * @return formatted data consisting of an ASCII BASE 64 string
     * suitable for an LDIF file
     */
    private static String format_ldif_data( String data ) {
        String revised_data = "";

        if( data.length() > 60 ) {
            // process first line
            for( int i = 0; i < 60; i++ ) {
                revised_data += data.charAt( i );
            }

            // terminate first line
            revised_data += '\n';

            // process remaining lines
            int j = 0;
            for( int i = 60; i < data.length(); i++ ) {
                if( j == 0 ) {
                    revised_data += ' ';
                }

                revised_data += data.charAt( i );

                j++;

                if( j == 76 ) {
                    revised_data += '\n';
                    j = 0;
                }
            }
        }

        return revised_data;
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
    private static String BigIntegerToDB( BigInteger i ) {
        int len = i.toString().length();
        String ret = null;

        if( len < 10 ) {
            ret = "0" + Integer.toString( len ) + i.toString();
        } else {
            ret = Integer.toString( len ) + i.toString();
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
    private static BigInteger BigIntegerFromDB( String i ) {
        String s = i.substring( 2 );

        // possibly check length
        return new BigInteger( s );
    }


    /**
     * This method accepts an "attribute", a string representation
     * of numeric data, and a flag indicating whether or not the
     * string representation is "indexed".
     *
     * An "attribute" consists of one of the following values:
     *
     * <PRE>
     *     CN = "cn:";
     *     EXTDATA_KEYRECORD = "extdata-keyrecord:";
     *     EXTDATA_REQUESTID = "extdata-requestid:";
     *     EXTDATA_SERIALNUMBER = "extdata-serialnumber:";
     *     REQUESTID = "requestId:";
     *     SERIALNO = "serialno:";
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
     * @param source_line the string containing the "name" and "value"
     * @param indexed boolean flag indicating if the "value" is "indexed"
     * @return a revised line containing the "name" and "value" with the
     * specified ID offset applied as a "mask" to the "value"
     */
    private static String compose_numeric_line( String attribute,
                                                String source_line,
                                                boolean indexed ) {
        String target_line = null;
        String data = null;
        String revised_data = null;
        BigInteger value = null;

        // Since both "-append_id_offset" and "-remove_id_offset" are OPTIONAL
        // parameters, first check to see if either has been selected
        if( !mAppendIdOffsetFlag &&
            !mRemoveIdOffsetFlag ) {
            return source_line;
        }

        try {
            // extract the data
            data = source_line.substring( attribute.length() + 1 ).trim();

            // skip values which are non-numeric
            if( !data.matches( "[0-9]++" ) ) {
                // set the target_line to the unchanged source_line
                target_line = source_line;

                // log this information
                log( "Skipped changing non-numeric line '"
                   + source_line
                   + "'."
                   + NEWLINE, false );
            } else {
                // if indexed, first strip the index from the data
                if( indexed ) {
                    // NOTE:  Indexed data means that the numeric data
                    //        is stored with a prepended length
                    //        (e. g. - record '73' is stored as '0273').
                    //
                    //        Indexed data is currently limited to '99' digits
                    //        (an index of '00' is invalid).  See
                    //        'com.netscape.cmscore.dbs.BigIntegerMapper.java'
                    //        for details.
                    value = BigIntegerFromDB( data );
                } else {
                    value = new BigInteger( data );
                }

                // compare the specified target ID offset
                // with the actual value of the attribute
                if( mAppendIdOffsetFlag ) {
                    if( mAppendIdOffset.compareTo( value ) == 1 ) {
                        // add the target ID offset to this value
                        if( indexed ) {
                            revised_data = BigIntegerToDB(
                                               value.add( mAppendIdOffset )
                                               ).toString();
                        } else {
                            revised_data = value.add(
                                               mAppendIdOffset ).toString();
                        }
                    } else {
                        log( "ERROR:  attribute='"
                           + attribute
                           + "' is greater than the specified "
                           + "append_id_offset='"
                           + mAppendIdOffset.toString()
                           + "'!"
                           + NEWLINE, true );
                        System.exit( 0 );
                    }
                } else if( mRemoveIdOffsetFlag ) {
                    if( mRemoveIdOffset.compareTo( value ) <= 0 ) {
                        // subtract the target ID offset to this value
                        if( indexed ) {
                            revised_data = BigIntegerToDB(
                                               value.subtract( mRemoveIdOffset )
                                               ).toString();
                        } else {
                            revised_data = value.subtract( mRemoveIdOffset
                                               ).toString();
                        }
                    } else {
                        log( "ERROR:  attribute='"
                           + attribute
                           + "' is less than the specified "
                           + "remove_id_offset='"
                           + mRemoveIdOffset.toString()
                           + "'!"
                           + NEWLINE, true );
                        System.exit( 0 );
                    }
                }

                // set the target_line to the revised data
                target_line = attribute + SPACE + revised_data;

                // log this information
                log( "Changed numeric data '"
                   + data
                   + "' to '"
                   + revised_data
                   + "'."
                   + NEWLINE, false );
            }
        } catch( IndexOutOfBoundsException exBounds ) {
            log( "ERROR:  source_line='"
               + source_line
               + "' IndexOutOfBoundsException: '"
               + exBounds
               + "'"
               + NEWLINE, true );
            System.exit( 0 );
        } catch( PatternSyntaxException exPattern ) {
            log( "ERROR:  data='"
               + data
               + "' PatternSyntaxException: '"
               + exPattern
               + "'"
               + NEWLINE, true );
            System.exit( 0 );
        }

        return target_line;
    }


    /***********************/
    /* LDIF Parser Methods */
    /***********************/

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
        String line = null;
        String previous_line = null;
        String revised_line = null;
        String data = null;
        String revised_data = null;
        String unformatted_data = null;
        String formatted_data = null;
        byte source_wrappedKeyData[] = null;
        byte target_wrappedKeyData[] = null;

        if( mRewrapFlag ) {
            success = obtain_RSA_rewrapping_keys();
            if( !success ) {
                return FAILURE;
            }
        }

        // Process each line in the source LDIF file
        // and store it in the target LDIF file
        try {
            // Open source LDIF file for reading
            reader = new BufferedReader(
                         new FileReader( mSourceLdifFilename ) );

            // Open target LDIF file for writing
            writer = new PrintWriter(
                         new BufferedWriter(
                             new FileWriter( mTargetLdifFilename ) ) );

            System.out.print( "PROCESSING: " );
            while( ( line = reader.readLine() ) != null ) {
                if( line.startsWith( CN ) ) {
                    revised_line = compose_numeric_line( CN,
                                                         line,
                                                         false );
                } else if( line.startsWith( DATE_OF_MODIFY ) ) {
                    // write out a new 'dateOfModify' line
                    revised_line = DATE_OF_MODIFY + SPACE + mDateOfModify;

                    // log this information
                    log( "Changed '"
                       + line
                       + "' to '"
                       + revised_line
                       + "'."
                       + NEWLINE, false );
                } else if( line.startsWith( EXTDATA_KEYRECORD ) ) {
                    revised_line = compose_numeric_line( EXTDATA_KEYRECORD,
                                                         line,
                                                         false );
                } else if( line.startsWith( EXTDATA_REQUESTID ) ) {
                    revised_line = compose_numeric_line( EXTDATA_REQUESTID,
                                                         line,
                                                         false );
                } else if( line.startsWith( EXTDATA_REQUESTNOTES ) ) {
                    // write out a revised 'extdata-requestnotes' line
                    if( mRewrapFlag && mAppendIdOffsetFlag ) {
                        revised_line = line + SPACE
                                     + LEFT_BRACE
                                     + mDateOfModify
                                     + RIGHT_BRACE
                                     + COLON + COLON + SPACE
                                     + REWRAP_MESSAGE
                                     + mPublicKeySize
                                     + RSA_MESSAGE + SPACE
                                     + PLUS + SPACE
                                     + APPENDED_ID_OFFSET_MESSAGE + SPACE
                                     + TIC + mAppendIdOffset.toString() + TIC;
                    } else if( mRewrapFlag && mRemoveIdOffsetFlag ) {
                        revised_line = line + SPACE
                                     + LEFT_BRACE
                                     + mDateOfModify
                                     + RIGHT_BRACE
                                     + COLON + COLON + SPACE
                                     + REWRAP_MESSAGE
                                     + mPublicKeySize
                                     + RSA_MESSAGE + SPACE
                                     + PLUS + SPACE
                                     + REMOVED_ID_OFFSET_MESSAGE + SPACE
                                     + TIC + mRemoveIdOffset.toString() + TIC;
                    } else if( mRewrapFlag ) {
                        revised_line = line + SPACE
                                     + LEFT_BRACE
                                     + mDateOfModify
                                     + RIGHT_BRACE
                                     + COLON + COLON + SPACE
                                     + REWRAP_MESSAGE
                                     + mPublicKeySize
                                     + RSA_MESSAGE;
                    } else if( mAppendIdOffsetFlag ) {
                        revised_line = line + SPACE
                                     + LEFT_BRACE
                                     + mDateOfModify
                                     + RIGHT_BRACE
                                     + COLON + COLON + SPACE
                                     + APPENDED_ID_OFFSET_MESSAGE + SPACE
                                     + TIC + mAppendIdOffset.toString() + TIC;
                    } else if( mRemoveIdOffsetFlag ) {
                        revised_line = line + SPACE
                                     + LEFT_BRACE
                                     + mDateOfModify
                                     + RIGHT_BRACE
                                     + COLON + COLON + SPACE
                                     + REMOVED_ID_OFFSET_MESSAGE + SPACE
                                     + TIC + mRemoveIdOffset.toString() + TIC;
                    }

                    // log this information
                    log( "Changed '"
                       + line
                       + "' to '"
                       + revised_line
                       + "'."
                       + NEWLINE, false );
                } else if( line.startsWith( EXTDATA_REQUEST_TYPE ) ) {
                    if( ( line.contains( NETKEY_KEYGEN ) ||
                          line.contains( RECOVERY ) ) &&
                          !previous_line.startsWith( EXTDATA_REQUESTNOTES ) ) {
                        // write out the missing 'extdata-requestnotes' line
                        if( mRewrapFlag && mAppendIdOffsetFlag ) {
                            revised_line = EXTDATA_REQUESTNOTES + SPACE
                                         + LEFT_BRACE
                                         + mDateOfModify
                                         + RIGHT_BRACE
                                         + COLON + COLON + SPACE
                                         + REWRAP_MESSAGE
                                         + mPublicKeySize
                                         + RSA_MESSAGE + SPACE
                                         + PLUS + SPACE
                                         + APPENDED_ID_OFFSET_MESSAGE + SPACE
                                         + TIC + mAppendIdOffset.toString()
                                         + TIC;
                        } else if( mRewrapFlag && mRemoveIdOffsetFlag ) {
                            revised_line = EXTDATA_REQUESTNOTES + SPACE
                                         + LEFT_BRACE
                                         + mDateOfModify
                                         + RIGHT_BRACE
                                         + COLON + COLON + SPACE
                                         + REWRAP_MESSAGE
                                         + mPublicKeySize
                                         + RSA_MESSAGE + SPACE
                                         + PLUS + SPACE
                                         + REMOVED_ID_OFFSET_MESSAGE + SPACE
                                         + TIC + mRemoveIdOffset.toString()
                                         + TIC;
                        } else if( mRewrapFlag ) {
                            revised_line = EXTDATA_REQUESTNOTES + SPACE
                                         + LEFT_BRACE
                                         + mDateOfModify
                                         + RIGHT_BRACE
                                         + COLON + COLON + SPACE
                                         + REWRAP_MESSAGE
                                         + mPublicKeySize
                                         + RSA_MESSAGE;
                        } else if( mAppendIdOffsetFlag ) {
                            revised_line = EXTDATA_REQUESTNOTES + SPACE
                                         + LEFT_BRACE
                                         + mDateOfModify
                                         + RIGHT_BRACE
                                         + COLON + COLON + SPACE
                                         + APPENDED_ID_OFFSET_MESSAGE + SPACE
                                         + TIC + mAppendIdOffset.toString()
                                         + TIC;
                        } else if( mRemoveIdOffsetFlag ) {
                            revised_line = EXTDATA_REQUESTNOTES + SPACE
                                         + LEFT_BRACE
                                         + mDateOfModify
                                         + RIGHT_BRACE
                                         + COLON + COLON + SPACE
                                         + REMOVED_ID_OFFSET_MESSAGE + SPACE
                                         + TIC + mRemoveIdOffset.toString()
                                         + TIC;
                        }

                        // log this information
                        log( "Created '"
                           + revised_line
                           + "'."
                           + NEWLINE, false );

                        // Write out this revised line and flush the buffer
                        writer.write( revised_line + NEWLINE );
                        writer.flush();
                        System.out.print( "." );
                    }

                    // ALWAYS pass through the original 'extdata-requesttype'
                    // line UNCHANGED so that it is ALWAYS written
                    revised_line = line;
                } else if( line.startsWith( EXTDATA_SERIALNUMBER ) ) {
                    revised_line = compose_numeric_line( EXTDATA_SERIALNUMBER,
                                                         line,
                                                         false );
                } else if( line.startsWith( PRIVATE_KEY_DATA ) ) {
                    // Since "-source_pki_security_database_path",
                    // "-source_storage_token_name",
                    // "-source_storage_certificate_nickname", and
                    // "-target_storage_certificate_file" are OPTIONAL
                    // parameters, ONLY process this field if all of
                    // these options have been selected
                    if( mRewrapFlag ) {
                        // extract the data
                        data = line.substring( PRIVATE_KEY_DATA.length() + 1
                                             ).trim();

                        while( ( line = reader.readLine() ) != null ) {
                            if( line.startsWith( SPACE ) ) {
                                data += line.trim();
                            } else {
                                break;
                            }
                        }

                        // Decode the ASCII BASE 64 certificate enclosed in the
                        // String() object into a BINARY BASE 64 byte[] object
                        source_wrappedKeyData = com.netscape.osutil.OSUtil.AtoB(
                                                    data );

                        // rewrap the source wrapped private key data
                        target_wrappedKeyData = rewrap_wrapped_key_data(
                                                    source_wrappedKeyData );

                        // Encode the BINARY BASE 64 byte[] object
                        // into an ASCII BASE 64 certificate
                        // enclosed in a String() object
                        revised_data = com.netscape.osutil.OSUtil.BtoA(
                                           target_wrappedKeyData );

                        // Unformat the ASCII BASE 64 certificate
                        // for the log file
                        unformatted_data = stripEOL( revised_data );

                        // Format the ASCII BASE 64 certificate
                        // to match the desired LDIF format
                        formatted_data = format_ldif_data( unformatted_data );

                        // construct a revised 'privateKeyData' line
                        revised_line = PRIVATE_KEY_DATA
                                     + SPACE
                                     + formatted_data
                                     + NEWLINE
                                     + line;

                        // log this information
                        log( "Changed 'privateKeyData' from:"
                           + NEWLINE
                           + TIC
                           + data
                           + TIC
                           + NEWLINE
                           + " to:"
                           + NEWLINE
                           + TIC
                           + unformatted_data
                           + TIC
                           + NEWLINE, false );
                    } else {
                        revised_line = line;
                    }
                } else if( line.startsWith( REQUESTID ) ) {
                    revised_line = compose_numeric_line( REQUESTID,
                                                         line,
                                                         true );
                } else if( line.startsWith( SERIALNO ) ) {
                    revised_line = compose_numeric_line( SERIALNO,
                                                         line,
                                                         true );
                } else {
                    // Pass through line unchanged
                    revised_line = line;
                }

                // Always save a copy of this line
                previous_line = revised_line;

                // Always write out the revised line and flush the buffer
                writer.write( revised_line + NEWLINE );
                writer.flush();
                System.out.print( "." );
            }
            System.out.println( " FINISHED." + NEWLINE );
        } catch( IOException exIO ) {
            log( "ERROR:  line='"
               + line
               + "' OR revised_line='"
               + revised_line
               + "' IOException: '"
               + exIO
               + "'"
               + NEWLINE, true );
            return FAILURE;
        } catch( Exception exRewrap ) {
            log( "ERROR:  Unable to rewrap BINARY BASE 64 data. "
               + "Exception: '"
               + exRewrap
               + "'"
               + NEWLINE, true );
            return FAILURE;
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
    public static void main( String[] args ) {
        // Variables
        String append_id_offset = null;
        String remove_id_offset = null;
        File sourceFile = null;
        File sourceDBPath = null;
        File targetStorageCertFile = null;
        File targetFile = null;
        File logFile = null;
        boolean success = false;

        // Get current date and time
        mDateOfModify = now( DATE_OF_MODIFY_PATTERN );

        // Check that the correct number of arguments were
        // submitted to the program
        if( ( args.length != ID_OFFSET_ARGS )  &&
            ( args.length != REWRAP_ARGS )     &&
            ( args.length != REWRAP_AND_ID_OFFSET_ARGS ) ) {
            System.err.println( "ERROR:  Incorrect number of arguments!"
                              + NEWLINE );
            printUsage();
            System.exit( 0 );
        }

        // Process command-line arguments
        for( int i = 0; i < args.length;  i += 2 ) {
            if( args[i].equals( SOURCE_LDIF_FILE ) ) {
                mSourceLdifFilename = args[i + 1];
                mMandatoryNameValuePairs++;
            } else if( args[i].equals( TARGET_LDIF_FILE ) ) {
                mTargetLdifFilename = args[i + 1];
                mMandatoryNameValuePairs++;
            } else if( args[i].equals( LOG_FILE ) ) {
                mLogFilename = args[i + 1];
                mMandatoryNameValuePairs++;
            } else if( args[i].equals( SOURCE_NSS_DB_PATH ) ) {
                mSourcePKISecurityDatabasePath = args[i + 1];
                mRewrapNameValuePairs++;
            } else if( args[i].equals( SOURCE_STORAGE_TOKEN_NAME ) ) {
                mSourceStorageTokenName = args[i + 1];
                mRewrapNameValuePairs++;
            } else if( args[i].equals( SOURCE_STORAGE_CERT_NICKNAME ) ) {
                mSourceStorageCertNickname = args[i + 1];
                mRewrapNameValuePairs++;
            } else if( args[i].equals( TARGET_STORAGE_CERTIFICATE_FILE ) ) {
                mTargetStorageCertificateFilename = args[i + 1];
                mRewrapNameValuePairs++;
            } else if( args[i].equals( APPEND_ID_OFFSET ) ) {
                append_id_offset = args[i + 1];
                mAppendIdOffsetNameValuePairs++;
            } else if( args[i].equals( REMOVE_ID_OFFSET ) ) {
                remove_id_offset = args[i + 1];
                mRemoveIdOffsetNameValuePairs++;
            } else {
                System.err.println( "ERROR:  Unknown argument '"
                                  + args[i]
                                  + "'!"
                                  + NEWLINE );
                printUsage();
                System.exit( 0 );
            }
        }

        // Verify that correct number of valid mandatory
        // arguments were submitted to the program
        if( mMandatoryNameValuePairs != MANDATORY_NAME_VALUE_PAIRS  ||
            mSourceLdifFilename == null                             ||
            mSourceLdifFilename.length() == 0                       ||
            mTargetLdifFilename == null                             ||
            mTargetLdifFilename.length() == 0                       ||
            mLogFilename == null                                    ||
            mLogFilename.length() == 0 ) {
            System.err.println( "ERROR:  Missing mandatory arguments!"
                              + NEWLINE );
            printUsage();
            System.exit( 0 );
        } else {
            // Check for a valid source LDIF file
            sourceFile = new File( mSourceLdifFilename );
            if( !sourceFile.exists() ||
                !sourceFile.isFile() ) {
                System.err.println( "ERROR:  '"
                                  + mSourceLdifFilename
                                  + "' does NOT exist or is NOT a file!"
                                  + NEWLINE );
                printUsage();
                System.exit( 0 );
            }

            // Check that the target LDIF file does NOT exist
            targetFile = new File( mTargetLdifFilename );
            if( targetFile.exists() ) {
                System.err.println( "ERROR:  '"
                                  + mTargetLdifFilename
                                  + "' ALREADY exists!"
                                  + NEWLINE );
                printUsage();
                System.exit( 0 );
            }

            // Check that the log file does NOT exist
            logFile = new File( mLogFilename );
            if( logFile.exists() ) {
                System.err.println( "ERROR:  '"
                                  + mLogFilename
                                  + "' ALREADY exists!"
                                  + NEWLINE );
                printUsage();
                System.exit( 0 );
            }

            // Mark the 'Mandatory' flag true
            mMandatoryFlag = true;
        }

        // Check to see that if the 'Rewrap' command-line options were
        // specified, that they are all present and accounted for
        if( mRewrapNameValuePairs > 0 ) {
            if( mRewrapNameValuePairs != REWRAP_NAME_VALUE_PAIRS  ||
                mSourcePKISecurityDatabasePath == null            ||
                mSourcePKISecurityDatabasePath.length() == 0      ||
                mSourceStorageTokenName == null                   ||
                mSourceStorageTokenName.length() == 0             ||
                mSourceStorageCertNickname == null                ||
                mSourceStorageCertNickname.length() == 0          ||
                mTargetStorageCertificateFilename == null         ||
                mTargetStorageCertificateFilename.length() == 0 ) {
                System.err.println( "ERROR:  Missing 'Rewrap' arguments!"
                                  + NEWLINE );
                printUsage();
                System.exit( 0 );
            } else {
                // Check for a valid path to the PKI security databases
                sourceDBPath = new File( mSourcePKISecurityDatabasePath );
                if( !sourceDBPath.exists() ||
                    !sourceDBPath.isDirectory() ) {
                    System.err.println( "ERROR:  '"
                                      + mSourcePKISecurityDatabasePath
                                      + "' does NOT exist or "
                                      + "'is NOT a directory!"
                                      + NEWLINE );
                    printUsage();
                    System.exit( 0 );
                }

                // Check for a valid target storage certificate file
                targetStorageCertFile = new File(
                                            mTargetStorageCertificateFilename );
                if( !targetStorageCertFile.exists() ||
                    !targetStorageCertFile.isFile() ) {
                    System.err.println( "ERROR:  '"
                                      + mTargetStorageCertificateFilename
                                      + "' does NOT exist or is NOT a file!"
                                      + NEWLINE );
                    printUsage();
                    System.exit( 0 );
                }

                // Mark the 'Rewrap' flag true
                mRewrapFlag = true;
            }
        }

        // Check to see that BOTH append 'ID Offset' command-line options
        // and remove 'ID Offset' command-line options were NOT specified
        // since these two command-line options are mutually exclusive!
        if( ( mAppendIdOffsetNameValuePairs > 0 ) &&
            ( mRemoveIdOffsetNameValuePairs > 0 ) ) {
                System.err.println( "ERROR:  The 'append ID Offset' option "
                                  + "and the 'remove ID Offset' option are "
                                  + "mutually exclusive!"
                                  + NEWLINE );
                printUsage();
                System.exit( 0 );
        }

        // Check to see that if the 'append ID Offset' command-line options
        // were specified, that they are all present and accounted for
        if( mAppendIdOffsetNameValuePairs > 0 ) {
            if( mAppendIdOffsetNameValuePairs == ID_OFFSET_NAME_VALUE_PAIRS &&
                append_id_offset != null                                    &&
                append_id_offset.length() != 0 ) {
                try {
                    if( !append_id_offset.matches( "[0-9]++" ) ) {
                        System.err.println( "ERROR:  '"
                                          + append_id_offset
                                          + "' contains non-numeric "
                                          + "characters!"
                                          + NEWLINE );
                        printUsage();
                        System.exit( 0 );
                    } else {
                        mAppendIdOffset = new BigInteger(
                                              append_id_offset );

                        // Mark the 'append ID Offset' flag true
                        mAppendIdOffsetFlag = true;
                    }
                } catch( PatternSyntaxException exAppendPattern ) {
                    System.err.println( "ERROR:  append_id_offset='"
                                      + append_id_offset
                                      + "' PatternSyntaxException: '"
                                      + exAppendPattern
                                      + "'"
                                      + NEWLINE );
                    System.exit( 0 );
                }
            } else {
                System.err.println( "ERROR:  Missing "
                                  + "'append ID Offset' arguments!"
                                  + NEWLINE );
                printUsage();
                System.exit( 0 );
            }
        }

        // Check to see that if the 'remove ID Offset' command-line options
        // were specified, that they are all present and accounted for
        if( mRemoveIdOffsetNameValuePairs > 0 ) {
            if( mRemoveIdOffsetNameValuePairs == ID_OFFSET_NAME_VALUE_PAIRS &&
                remove_id_offset != null                                    &&
                remove_id_offset.length() != 0 ) {
                try {
                    if( !remove_id_offset.matches( "[0-9]++" ) ) {
                        System.err.println( "ERROR:  '"
                                          + remove_id_offset
                                          + "' contains non-numeric "
                                          + "characters!"
                                          + NEWLINE );
                        printUsage();
                        System.exit( 0 );
                    } else {
                        mRemoveIdOffset = new BigInteger(
                                              remove_id_offset );

                        // Mark the 'remove ID Offset' flag true
                        mRemoveIdOffsetFlag = true;
                    }
                } catch( PatternSyntaxException exRemovePattern ) {
                    System.err.println( "ERROR:  remove_id_offset='"
                                      + remove_id_offset
                                      + "' PatternSyntaxException: '"
                                      + exRemovePattern
                                      + "'"
                                      + NEWLINE );
                    System.exit( 0 );
                }
            } else {
                System.err.println( "ERROR:  Missing "
                                  + "'remove ID Offset' arguments!"
                                  + NEWLINE );
                printUsage();
                System.exit( 0 );
            }
        }

        // Make certain that at least one of the "Rewrap", "Append ID Offset",
        // or "Remove ID Offset" options has been specified
        if( !mRewrapFlag &&
            !mAppendIdOffsetFlag &&
            !mRemoveIdOffsetFlag ) {
            System.err.println( "ERROR:  At least one of the 'rewrap', "
                              + "'append ID Offset', or 'remove ID Offset' "
                              + "options MUST be specified!"
                              + NEWLINE );
            printUsage();
            System.exit( 0 );
        }

        // Enable logging process . . .
        open_log( mLogFilename );

        // Begin logging progress . . .
        if( mRewrapFlag && mAppendIdOffsetFlag ) {
            log( "BEGIN '"
               + DRM_TOOL + SPACE
               + SOURCE_LDIF_FILE + SPACE
               + mSourceLdifFilename + SPACE
               + TARGET_LDIF_FILE + SPACE
               + mTargetLdifFilename + SPACE
               + LOG_FILE + SPACE
               + mLogFilename + SPACE
               + SOURCE_NSS_DB_PATH + SPACE
               + mSourcePKISecurityDatabasePath + SPACE
               + SOURCE_STORAGE_TOKEN_NAME + SPACE
               + mSourceStorageTokenName + SPACE
               + SOURCE_STORAGE_CERT_NICKNAME + SPACE
               + mSourceStorageCertNickname + SPACE
               + TARGET_STORAGE_CERTIFICATE_FILE + SPACE
               + mTargetStorageCertificateFilename + SPACE
               + APPEND_ID_OFFSET + SPACE
               + append_id_offset + "' . . ."
               + NEWLINE, true );
        } else if( mRewrapFlag && mRemoveIdOffsetFlag ) {
            log( "BEGIN '"
               + DRM_TOOL + SPACE
               + SOURCE_LDIF_FILE + SPACE
               + mSourceLdifFilename + SPACE
               + TARGET_LDIF_FILE + SPACE
               + mTargetLdifFilename + SPACE
               + LOG_FILE + SPACE
               + mLogFilename + SPACE
               + SOURCE_NSS_DB_PATH + SPACE
               + mSourcePKISecurityDatabasePath + SPACE
               + SOURCE_STORAGE_TOKEN_NAME + SPACE
               + mSourceStorageTokenName + SPACE
               + SOURCE_STORAGE_CERT_NICKNAME + SPACE
               + mSourceStorageCertNickname + SPACE
               + TARGET_STORAGE_CERTIFICATE_FILE + SPACE
               + mTargetStorageCertificateFilename + SPACE
               + REMOVE_ID_OFFSET + SPACE
               + remove_id_offset + "' . . ."
               + NEWLINE, true );
        } else if( mRewrapFlag ) {
            log( "BEGIN '"
               + DRM_TOOL + SPACE
               + SOURCE_LDIF_FILE + SPACE
               + mSourceLdifFilename + SPACE
               + TARGET_LDIF_FILE + SPACE
               + mTargetLdifFilename + SPACE
               + LOG_FILE + SPACE
               + mLogFilename + SPACE
               + SOURCE_NSS_DB_PATH + SPACE
               + mSourcePKISecurityDatabasePath + SPACE
               + SOURCE_STORAGE_TOKEN_NAME + SPACE
               + mSourceStorageTokenName + SPACE
               + SOURCE_STORAGE_CERT_NICKNAME + SPACE
               + mSourceStorageCertNickname + SPACE
               + TARGET_STORAGE_CERTIFICATE_FILE + SPACE
               + mTargetStorageCertificateFilename + "' . . ."
               + NEWLINE, true );
        } else if( mAppendIdOffsetFlag ) {
            log( "BEGIN '"
               + DRM_TOOL + SPACE
               + SOURCE_LDIF_FILE + SPACE
               + mSourceLdifFilename + SPACE
               + TARGET_LDIF_FILE + SPACE
               + mTargetLdifFilename + SPACE
               + LOG_FILE + SPACE
               + mLogFilename + SPACE
               + APPEND_ID_OFFSET + SPACE
               + append_id_offset + "' . . ."
               + NEWLINE, true );
        } else if( mRemoveIdOffsetFlag ) {
            log( "BEGIN '"
               + DRM_TOOL + SPACE
               + SOURCE_LDIF_FILE + SPACE
               + mSourceLdifFilename + SPACE
               + TARGET_LDIF_FILE + SPACE
               + mTargetLdifFilename + SPACE
               + LOG_FILE + SPACE
               + mLogFilename + SPACE
               + REMOVE_ID_OFFSET + SPACE
               + remove_id_offset + "' . . ."
               + NEWLINE, true );
        }

        // Convert the source LDIF file to a target LDIF file
        success = convert_source_ldif_to_target_ldif();
        if( !success ) {
            log( "FAILED converting source LDIF file --> target LDIF file!"
               + NEWLINE, true );
        } else {
            log( "SUCCESSFULLY converted source LDIF file --> target LDIF file!"
               + NEWLINE, true );
        }

        // Finish logging progress
        if( mRewrapFlag && mAppendIdOffsetFlag ) {
            log( "FINISHED '"
               + DRM_TOOL + SPACE
               + SOURCE_LDIF_FILE + SPACE
               + mSourceLdifFilename + SPACE
               + TARGET_LDIF_FILE + SPACE
               + mTargetLdifFilename + SPACE
               + LOG_FILE + SPACE
               + mLogFilename + SPACE
               + SOURCE_NSS_DB_PATH + SPACE
               + mSourcePKISecurityDatabasePath + SPACE
               + SOURCE_STORAGE_TOKEN_NAME + SPACE
               + mSourceStorageTokenName + SPACE
               + SOURCE_STORAGE_CERT_NICKNAME + SPACE
               + mSourceStorageCertNickname + SPACE
               + TARGET_STORAGE_CERTIFICATE_FILE + SPACE
               + mTargetStorageCertificateFilename + SPACE
               + APPEND_ID_OFFSET + SPACE
               + append_id_offset + "'."
               + NEWLINE, true );
        } else if( mRewrapFlag && mRemoveIdOffsetFlag ) {
            log( "FINISHED '"
               + DRM_TOOL + SPACE
               + SOURCE_LDIF_FILE + SPACE
               + mSourceLdifFilename + SPACE
               + TARGET_LDIF_FILE + SPACE
               + mTargetLdifFilename + SPACE
               + LOG_FILE + SPACE
               + mLogFilename + SPACE
               + SOURCE_NSS_DB_PATH + SPACE
               + mSourcePKISecurityDatabasePath + SPACE
               + SOURCE_STORAGE_TOKEN_NAME + SPACE
               + mSourceStorageTokenName + SPACE
               + SOURCE_STORAGE_CERT_NICKNAME + SPACE
               + mSourceStorageCertNickname + SPACE
               + TARGET_STORAGE_CERTIFICATE_FILE + SPACE
               + mTargetStorageCertificateFilename + SPACE
               + REMOVE_ID_OFFSET + SPACE
               + remove_id_offset + "'."
               + NEWLINE, true );
        } else if( mRewrapFlag ) {
            log( "FINISHED '"
               + DRM_TOOL + SPACE
               + SOURCE_LDIF_FILE + SPACE
               + mSourceLdifFilename + SPACE
               + TARGET_LDIF_FILE + SPACE
               + mTargetLdifFilename + SPACE
               + LOG_FILE + SPACE
               + mLogFilename + SPACE
               + SOURCE_NSS_DB_PATH + SPACE
               + mSourcePKISecurityDatabasePath + SPACE
               + SOURCE_STORAGE_TOKEN_NAME + SPACE
               + mSourceStorageTokenName + SPACE
               + SOURCE_STORAGE_CERT_NICKNAME + SPACE
               + mSourceStorageCertNickname + SPACE
               + TARGET_STORAGE_CERTIFICATE_FILE + SPACE
               + mTargetStorageCertificateFilename + "'."
               + NEWLINE, true );
        } else if( mAppendIdOffsetFlag ) {
            log( "FINISHED '"
               + DRM_TOOL + SPACE
               + SOURCE_LDIF_FILE + SPACE
               + mSourceLdifFilename + SPACE
               + TARGET_LDIF_FILE + SPACE
               + mTargetLdifFilename + SPACE
               + LOG_FILE + SPACE
               + mLogFilename + SPACE
               + APPEND_ID_OFFSET + SPACE
               + append_id_offset + "'."
               + NEWLINE, true );
        } else if( mRemoveIdOffsetFlag ) {
            log( "FINISHED '"
               + DRM_TOOL + SPACE
               + SOURCE_LDIF_FILE + SPACE
               + mSourceLdifFilename + SPACE
               + TARGET_LDIF_FILE + SPACE
               + mTargetLdifFilename + SPACE
               + LOG_FILE + SPACE
               + mLogFilename + SPACE
               + REMOVE_ID_OFFSET + SPACE
               + remove_id_offset + "'."
               + NEWLINE, true );
        }

        // Shutdown logging process
        close_log( mLogFilename );
    }
}

