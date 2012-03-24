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
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.security;


import org.mozilla.jss.crypto.*;
import org.mozilla.jss.*;
import org.mozilla.jss.CryptoManager.*;
import java.io.*;
import java.security.*;
import java.util.*;
import java.security.*;
import java.security.cert.*;
import netscape.security.x509.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.common.*;


/**
 * This interface represents the cryptographics subsystem
 * that provides all the security related functions.
 *
 * @version $Revision$, $Date$
 */
public interface ICryptoSubsystem extends ISubsystem {

    public static final String ID = "jss";

    /**
     * Retrieves a list of nicknames of certificates that are
     * in the installed tokens.
     *
     * @return a list of comma-separated nicknames
     * @exception EBaseException failed to retrieve nicknames
     */
    public String getAllCerts() throws EBaseException;

    /**
     * Retrieves certificate in pretty-print format by the nickname.
     *
     * @param nickname nickname of certificate
     * @param date not after of the returned certificate must be date
     * @param locale user locale
     * @return certificate in pretty-print format
     * @exception EBaseException failed to retrieve certificate
     */
    public String getCertPrettyPrint(String nickname, String date,
        Locale locale) throws EBaseException;
    public String getRootCertTrustBit(String nickname, String serialno,
      String issuerName) throws EBaseException;
    public String getCertPrettyPrint(String nickname, String serialno, 
      String issuername, Locale locale) throws EBaseException;
    public String getCertPrettyPrintAndFingerPrint(String nickname, String serialno, 
      String issuername, Locale locale) throws EBaseException;

    /**
     * Retrieves the certificate in the pretty print format.
     *
     * @param b64E certificate in mime-64 encoded format
     * @param locale end user locale
     * @return certificate in pretty-print format
     * @exception EBaseException failed to retrieve certificate
     */
    public String getCertPrettyPrint(String b64E, Locale locale) 
        throws EBaseException;

    /**
     * Imports certificate into the server.
     *
     * @param b64E certificate in mime-64 encoded format
     * @param nickname nickname for the importing certificate
     * @param certType certificate type
     * @exception EBaseException failed to import certificate
     */
    public void importCert(String b64E, String nickname, String certType)
        throws EBaseException;

    /**
     * Imports certificate into the server.
     *
     * @param signedCert certificate
     * @param nickname nickname for the importing certificate
     * @param certType certificate type
     * @exception EBaseException failed to import certificate
     */
    public void importCert(X509CertImpl signedCert, String nickname,
        String certType) throws EBaseException;

    /**
     * Generates a key pair based on the given parameters.
     *
     * @param properties key parameters
     * @return key pair
     * @exception EBaseException failed to generate key pair
     */
    public KeyPair getKeyPair(KeyCertData properties) throws EBaseException;

    /**
     * Retrieves the key pair based on the given nickname.
     *
     * @param nickname nickname of the public key
     * @exception EBaseException failed to retrieve key pair
     */
    public KeyPair getKeyPair(String nickname) throws EBaseException;

    /**
     * Generates a key pair based on the given parameters.
     *
     * @param tokenName name of token where key is generated
     * @param alg key algorithm
     * @param keySize key size
     * @return key pair
     * @exception EBaseException failed to generate key pair
     */
    public KeyPair getKeyPair(String tokenName, String alg,
        int keySize) throws EBaseException;

    /**
     * Generates a key pair based on the given parameters.
     *
     * @param tokenName name of token where key is generated
     * @param alg key algorithm
     * @param keySize key size
     * @param pqg pqg parameters if DSA key, otherwise null
     * @return key pair
     * @exception EBaseException failed to generate key pair
     */
    public KeyPair getKeyPair(String tokenName, String alg,
        int keySize, PQGParams pqg) throws EBaseException;

    /**
     * Generates an ECC key pair based on the given parameters.
     *
     * @param properties key parameters
     * @return key pair
     * @exception EBaseException failed to generate key pair
     */
    public KeyPair getECCKeyPair(KeyCertData properties) throws EBaseException;

    /**
     * Generates an ECC key pair based on the given parameters.
     *
     * @param token token name
     * @param curveName curve name
     * @param certType type of cert(sslserver etc..)
     * @return key pair
     * @exception EBaseException failed to generate key pair
     */
    public KeyPair getECCKeyPair(String token, String curveName, String certType) throws EBaseException;

    /**
     * Retrieves the signature algorithm of the certificate named
     * by the given nickname.
     *
     * @param nickname nickname of the certificate
     * @return signature algorithm
     * @exception EBaseException failed to retrieve signature 
     */
    public String getSignatureAlgorithm(String nickname) throws EBaseException;

    /**
     * Checks if the given dn is a valid distinguished name.
     *
     * @param dn distinguished name
     * @exception EBaseException failed to check
     */
    public void isX500DN(String dn) throws EBaseException;

    /**
     * Retrieves CA's signing algorithm id. If it is DSA algorithm,
     * algorithm is constructed by reading the parameters
     * ca.dsaP, ca.dsaQ, ca.dsaG.
     *
     * @param algname DSA or RSA
     * @param store configuration store.
     * @return algorithm id
     * @exception EBaseException failed to retrieve algorithm id
     */
    public AlgorithmId getAlgorithmId(String algname, IConfigStore store) throws EBaseException;

    /**
     * Retrieves subject name of the certificate that is identified by
     * the given nickname.
     *
     * @param tokenname name of token where the nickname is valid
     * @param nickname nickname of the certificate
     * @return subject name
     * @exception EBaseException failed to get subject name
     */
    public String getCertSubjectName(String tokenname, String nickname)
        throws EBaseException;

    /**
     * Retrieves extensions of the certificate that is identified by
     * the given nickname.
     *
     * @param tokenname name of token where the nickname is valid
     * @param nickname nickname of the certificate
     * @return certificate extensions
     * @exception EBaseException failed to get extensions
     */
    public CertificateExtensions getExtensions(String tokenname, String nickname
    )
        throws EBaseException;

    /**
     * Deletes certificate of the given nickname.
     *
     * @param nickname nickname of the certificate
     * @param pathname path where a copy of the deleted certificate is stored
     * @exception EBaseException failed to delete certificate
     */
    public void deleteTokenCertificate(String nickname, String pathname) 
        throws EBaseException;

    /**
     * Delete certificate of the given nickname.
     *
     * @param nickname nickname of the certificate
     * @param notAfterTime The notAfter of the certificate. It 
     *        is possible to ge t multiple certificates under 
     *        the same nickname. If one of the certificates match 
     *        the notAfterTime, then the certificate will get 
     *        deleted. The format of the notAfterTime has to be 
     *        in "MMMMM dd, yyyy HH:mm:ss" format.
     * @exception EBaseException failed to delete certificate
     */
    public void deleteCert(String nickname, String notAfterTime) 
        throws EBaseException;

    /**
     * Retrieves the subject DN of the certificate identified by
     * the nickname.
     *
     * @param nickname nickname of the certificate
     * @return subject distinguished name
     * @exception EBaseException failed to retrieve subject DN
     */
    public String getSubjectDN(String nickname) throws EBaseException;

    /**
     * Trusts a certificate for all available purposes.
     *
     * @param nickname nickname of the certificate
     * @param date certificate's not before
     * @param trust "Trust" or other
     * @exception EBaseException failed to trust certificate
     */
    public void trustCert(String nickname, String date, String trust) 
        throws EBaseException;

    /**
     * Checks if the given base-64 encoded string contains an extension
     * or a sequence of extensions.
     *
     * @param ext extension or sequence of extension encoded in base-64
     * @exception EBaseException failed to check encoding
     */
    public void checkCertificateExt(String ext) throws EBaseException;

    /**
     * Gets all certificates on all tokens for Certificate Database Management.
     *
     * @return all certificates
     * @exception EBaseException failed to retrieve certificates
     */
    public NameValuePairs getAllCertsManage() throws EBaseException;
    public NameValuePairs getUserCerts() throws EBaseException;

    /**
     * Gets all CA certificates on all tokens.
     *
     * @return all CA certificates
     * @exception EBaseException failed to retrieve certificates
     */
    public NameValuePairs getCACerts() throws EBaseException;

    public NameValuePairs getRootCerts() throws EBaseException;

    public void setRootCertTrust(String nickname, String serialno,
      String issuername, String trust) throws EBaseException;

    public void deleteRootCert(String nickname, String serialno,
      String issuername) throws EBaseException;

    public void deleteUserCert(String nickname, String serialno,
      String issuername) throws EBaseException;

    /**
     * Retrieves PQG parameters based on key size.
     *
     * @param keysize key size
     * @return pqg parameters
     */
    public PQGParams getPQG(int keysize);

    /**
     * Retrieves PQG parameters based on key size.
     *
     * @param keysize key size
     * @param store configuration store
     * @return pqg parameters
     */
    public PQGParams getCAPQG(int keysize, IConfigStore store)
        throws EBaseException;

    /**
     * Retrieves extensions of the certificate that is identified by
     * the given nickname.
     *
     * @param tokenname token name
     * @param nickname nickname
     * @return certificate extensions
     */
    public CertificateExtensions getCertExtensions(String tokenname, String nickname
    )
        throws NotInitializedException, TokenException, ObjectNotFoundException,

            IOException, CertificateException;

    /**
     * Checks if the given token is logged in.
     *
     * @param name token name
     * @return true if token is logged in
     * @exception EBaseException failed to login 
     */
    public boolean isTokenLoggedIn(String name) throws EBaseException;

    /**
     * Logs into token.
     *
     * @param tokenName name of the token
     * @param pwd token password
     * @exception EBaseException failed to login
     */
    public void loggedInToken(String tokenName, String pwd) 
        throws EBaseException;

    /**
     * Generates certificate request from the given key pair.
     *
     * @param subjectName subject name to use in the request
     * @param kp key pair that contains public key material
     * @return certificate request in base-64 encoded format
     * @exception EBaseException failed to generate request
     */
    public String getCertRequest(String subjectName, KeyPair kp)
        throws EBaseException;

    /**
     * Checks if fortezza is enabled.
     *
     * @return "true" if fortezza is enabled
     */
    public String isCipherFortezza() throws EBaseException;

    /**
     * Retrieves the SSL cipher version.
     *
     * @return cipher version (i.e. "cipherdomestic")
     */
    public String getCipherVersion() throws EBaseException;

    /**
     * Retrieves the cipher preferences.
     *
     * @return cipher preferences (i.e. "rc4export,rc2export,...")
     */
    public String getCipherPreferences() throws EBaseException;

    /**
     * Sets the current SSL cipher preferences.
     *
     * @param cipherPrefs cipher preferences (i.e. "rc4export,rc2export,...")
     * @exception EBaseException failed to set cipher preferences
     */
    public void setCipherPreferences(String cipherPrefs)
        throws EBaseException;

    /**
     * Retrieves a list of currently registered token names.
     *
     * @return list of token names
     * @exception EBaseException failed to retrieve token list
     */
    public String getTokenList() throws EBaseException;

    /**
     * Retrieves all certificates. The result list will not
     * contain the token tag.
     *
     * @param name token name
     * @return list of certificates without token tag
     * @exception EBaseException failed to retrieve
     */
    public String getCertListWithoutTokenName(String name) throws EBaseException;

    /**
     * Retrieves the token name of the internal (software) token.
     *
     * @return the token name
     * @exception EBaseException failed to retrieve token name
     */
    public String getInternalTokenName() throws EBaseException;

    /**
     * Checks to see if the certificate of the given nickname is a
     * CA certificate.
     *
     * @param fullNickname nickname of the certificate to check
     * @return true if it is a CA certificate
     * @exception EBaseException failed to check
     */
    public boolean isCACert(String fullNickname) throws EBaseException;

    /**
     * Adds the specified number of bits of entropy from the system
	 * entropy generator to the RNG of the default PKCS#11 RNG token.
     * The default token is set using the modutil command.
	 * Note that the system entropy generator (usually /dev/random)
	 * will block until sufficient entropy is collected.
     *
     * @param bits number of bits of entropy
     * @exception org.mozilla.jss.util.NotImplementedException If the Crypto device does not support
     *             adding entropy
	 * @exception TokenException If there was some other problem with the Crypto device
	 * @exception IOException If there was a problem reading from the /dev/random
     */

    public void addEntropy(int bits)
    throws org.mozilla.jss.util.NotImplementedException,
            IOException,
            TokenException;

    /**
     * Signs the certificate template into the given data and returns
     * a signed certificate.
     *
     * @param data data that contains certificate template
     * @param certType certificate type
     * @param priKey CA signing key
     * @return certificate
     * @exception EBaseException failed to sign certificate template
     */
    public X509CertImpl getSignedCert(KeyCertData data, String certType, java.security.PrivateKey priKey) throws EBaseException;
}
