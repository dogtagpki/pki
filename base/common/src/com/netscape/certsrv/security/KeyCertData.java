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


import java.util.*;
import java.security.*;
import java.math.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.common.*;
import org.mozilla.jss.crypto.*;
import netscape.security.x509.*;

/**
 * This class represents a container for storaging
 * data in the security package.
 * 
 * @version $Revision$, $Date$
 */
public class KeyCertData extends Properties {

    /**
     * Constructs a key certificate data.
     */
    public KeyCertData() {
        super();
    }

    /**
     * Retrieves the key pair from this container.
     *
     * @return key pair
     */
    public KeyPair getKeyPair() {
        return (KeyPair) get("keypair");
    }

    /**
     * Sets key pair into this container.
     *
     * @param keypair key pair
     */
    public void setKeyPair(KeyPair keypair) {
        put("keypair", keypair);
    }

    /**
     * Retrieves the issuer name from this container.
     *
     * @return issuer name
     */
    public String getIssuerName() {
        return (String) get(Constants.PR_ISSUER_NAME);
    }

    /**
     * Sets the issuer name in this container.
     *
     * @param name issuer name
     */
    public void setIssuerName(String name) {
        put(Constants.PR_ISSUER_NAME, name);
    }

    /**
     * Retrieves certificate server instance name.
     *
     * @return instance name
     */
    public String getCertInstanceName() {
        return (String) get(ConfigConstants.PR_CERT_INSTANCE_NAME);
    }

    /**
     * Sets certificate server instance name.
     *
     * @param name instance name
     */
    public void setCertInstanceName(String name) {
        put(ConfigConstants.PR_CERT_INSTANCE_NAME, name);
    }

    /**
     * Retrieves certificate nickname.
     *
     * @return certificate nickname
     */
    public String getCertNickname() {
        return (String) get(Constants.PR_NICKNAME);
    }
    
    /**
     * Sets certificate nickname.
     *
     * @param nickname certificate nickname
     */
    public void setCertNickname(String nickname) {
        put(Constants.PR_NICKNAME, nickname);
    }

    /**
     * Retrieves key length.
     *
     * @return key length
     */
    public String getKeyLength() {
        return (String) get(Constants.PR_KEY_LENGTH);
    }

    /**
     * Sets key length.
     *
     * @param len key length
     */
    public void setKeyLength(String len) {
        put(Constants.PR_KEY_LENGTH, len);
    }

    /**
     * Retrieves key type.
     *
     * @return key type
     */
    public String getKeyType() {
        return (String) get(Constants.PR_KEY_TYPE);
    }

    /**
     * Sets key type.
     *
     * @param type key type
     */
    public void setKeyType(String type) {
        put(Constants.PR_KEY_TYPE, type);
    }

    /**
     * Retrieves key curve name.
     *
     * @return key curve name
     */
    public String getKeyCurveName() {
        return (String) get(Constants.PR_KEY_CURVENAME);
    }

    /**
     * Sets key curvename.
     *
     * @param len key curvename
     */
    public void setKeyCurveName(String len) {
        put(Constants.PR_KEY_CURVENAME, len);
    }

    /**
     * Retrieves signature algorithm.
     *
     * @return signature algorithm
     */
    public SignatureAlgorithm getSignatureAlgorithm() {
        return (SignatureAlgorithm) get(Constants.PR_SIGNATURE_ALGORITHM);
    }

    /**
     * Sets signature algorithm
     *
     * @param alg signature algorithm
     */
    public void setSignatureAlgorithm(SignatureAlgorithm alg) {
        put(Constants.PR_SIGNATURE_ALGORITHM, alg);
    }

    /**
     * Retrieves algorithm used to sign the root CA Cert.
     *
     * @return signature algorithm
     */
    public String getSignedBy() {
        return (String) get(Constants.PR_SIGNEDBY_TYPE);
    }

    /**
     * Sets signature algorithm used to sign root CA cert
     *
     * @param alg signature algorithm
     */
    public void setSignedBy(String alg) {
        put(Constants.PR_SIGNEDBY_TYPE, alg);
    }

    /**
     * Retrieves signature algorithm.
     *
     * @return signature algorithm
     */
    public AlgorithmId getAlgorithmId() {
        return (AlgorithmId) get(Constants.PR_ALGORITHM_ID);
    }

    /**
     * Sets algorithm identifier
     *
     * @param id signature algorithm
     */
    public void setAlgorithmId(AlgorithmId id) {
        put(Constants.PR_ALGORITHM_ID, id);
    }

    /**
     * Retrieves serial number.
     *
     * @return serial number
     */
    public BigInteger getSerialNumber() {
        return (BigInteger) get("serialno");
    }

    /**
     * Sets serial number.
     *
     * @param num serial number
     */
    public void setSerialNumber(BigInteger num) {
        put("serialno", num);
    }

    /**
     * Retrieves configuration file.
     *
     * @return configuration file
     */
    public IConfigStore getConfigFile() {
        return (IConfigStore)(get("cmsFile"));
    }

    /**
     * Sets configuration file.
     *
     * @param file configuration file
     */
    public void setConfigFile(IConfigStore file) {
        put("cmsFile", file);
    }

    /**
     * Retrieves begining year of validity.
     *
     * @return begining year
     */
    public String getBeginYear() {
        return (String) get(Constants.PR_BEGIN_YEAR);
    }

    /**
     * Sets begining year of validity.
     *
     * @param year begining year
     */
    public void setBeginYear(String year) {
        put(Constants.PR_BEGIN_YEAR, year);
    }

    /**
     * Retrieves ending year of validity.
     *
     * @return ending year
     */
    public String getAfterYear() {
        return (String) get(Constants.PR_AFTER_YEAR);
    }

    /**
     * Sets ending year of validity.
     *
     * @param year ending year
     */
    public void setAfterYear(String year) {
        put(Constants.PR_AFTER_YEAR, year);
    }

    /**
     * Retrieves begining month of validity.
     *
     * @return begining month
     */
    public String getBeginMonth() {
        return (String) get(Constants.PR_BEGIN_MONTH);
    }

    /**
     * Sets begining month of validity.
     *
     * @param month begining month
     */
    public void setBeginMonth(String month) {
        put(Constants.PR_BEGIN_MONTH, month);
    }

    /**
     * Retrieves ending month of validity.
     *
     * @return ending month
     */
    public String getAfterMonth() {
        return (String) get(Constants.PR_AFTER_MONTH);
    }

    /**
     * Sets ending month of validity.
     *
     * @param month ending month
     */
    public void setAfterMonth(String month) {
        put(Constants.PR_AFTER_MONTH, month);
    }

    /**
     * Retrieves begining date of validity.
     *
     * @return begining date
     */
    public String getBeginDate() {
        return (String) get(Constants.PR_BEGIN_DATE);
    }

    /**
     * Sets begining date of validity.
     *
     * @param date begining date
     */
    public void setBeginDate(String date) {
        put(Constants.PR_BEGIN_DATE, date);
    }

    /**
     * Retrieves ending date of validity.
     *
     * @return ending date
     */
    public String getAfterDate() {
        return (String) get(Constants.PR_AFTER_DATE);
    }

    /**
     * Sets ending date of validity.
     *
     * @param date ending date
     */
    public void setAfterDate(String date) {
        put(Constants.PR_AFTER_DATE, date);
    }

    /**
     * Retrieves starting hour of validity.
     *
     * @return starting hour
     */
    public String getBeginHour() {
        return (String) get(Constants.PR_BEGIN_HOUR);
    }

    /**
     * Sets starting hour of validity.
     *
     * @param hour starting hour
     */
    public void setBeginHour(String hour) {
        put(Constants.PR_BEGIN_HOUR, hour);
    }

    /**
     * Retrieves ending hour of validity.
     *
     * @return ending hour
     */
    public String getAfterHour() {
        return (String) get(Constants.PR_AFTER_HOUR);
    }

    /**
     * Sets ending hour of validity.
     *
     * @param hour ending hour
     */
    public void setAfterHour(String hour) {
        put(Constants.PR_AFTER_HOUR, hour);
    }

    /**
     * Retrieves starting minute of validity.
     *
     * @return starting minute
     */
    public String getBeginMin() {
        return (String) get(Constants.PR_BEGIN_MIN);
    }
  
    /**
     * Sets starting minute of validity.
     *
     * @param min starting minute
     */
    public void setBeginMin(String min) {
        put(Constants.PR_BEGIN_MIN, min);
    }

    /**
     * Retrieves ending minute of validity.
     *
     * @return ending minute
     */
    public String getAfterMin() {
        return (String) get(Constants.PR_AFTER_MIN);
    }

    /**
     * Sets ending minute of validity.
     *
     * @param min ending minute
     */
    public void setAfterMin(String min) {
        put(Constants.PR_AFTER_MIN, min);
    }

    /**
     * Retrieves starting second of validity.
     *
     * @return starting second
     */
    public String getBeginSec() {
        return (String) get(Constants.PR_BEGIN_SEC);
    }

    /**
     * Sets starting second of validity.
     *
     * @param sec starting second
     */
    public void setBeginSec(String sec) {
        put(Constants.PR_BEGIN_SEC, sec);
    }

    /**
     * Retrieves ending second of validity.
     *
     * @return ending second
     */
    public String getAfterSec() {
        return (String) get(Constants.PR_AFTER_SEC);
    }

    /**
     * Sets ending second of validity.
     *
     * @param sec ending second
     */
    public void setAfterSec(String sec) {
        put(Constants.PR_AFTER_SEC, sec);
    }

    /**
     * Retrieves CA key pair
     *
     * @return CA key pair
     */
    public KeyPair getCAKeyPair() {
        return (KeyPair) get(Constants.PR_CA_KEYPAIR);
    }

    /**
     * Sets CA key pair
     *
     * @param keypair key pair
     */
    public void setCAKeyPair(KeyPair keypair) {
        put(Constants.PR_CA_KEYPAIR, keypair);
    }

    /**
     * Retrieves extensions
     *
     * @return extensions
     */
    public String getDerExtension() {
        return (String) get(Constants.PR_DER_EXTENSION);
    }

    /**
     * Sets extensions
     *
     * @param ext extensions
     */
    public void setDerExtension(String ext) {
        put(Constants.PR_DER_EXTENSION, ext);
    }

    /**
     * Retrieves isCA
     *
     * @return "true" if it is CA
     */
    public String isCA() {
        return (String) get(Constants.PR_IS_CA);
    }

    /**
     * Sets isCA
     *
     * @param ext "true" if it is CA
     */
    public void setCA(String ext) {
        put(Constants.PR_IS_CA, ext);
    }

    /**
     * Retrieves key length
     *
     * @return certificate's key length
     */
    public String getCertLen() {
        return (String) get(Constants.PR_CERT_LEN);
    }

    /**
     * Sets key length
     *
     * @param len certificate's key length
     */
    public void setCertLen(String len) {
        put(Constants.PR_CERT_LEN, len);
    }

    /**
     * Retrieves SSL Client bit
     *
     * @return SSL Client bit
     */
    public String getSSLClientBit() {
        return (String) get(Constants.PR_SSL_CLIENT_BIT);
    }

    /**
     * Sets SSL Client bit
     *
     * @param sslClientBit SSL Client bit
     */
    public void setSSLClientBit(String sslClientBit) {
        put(Constants.PR_SSL_CLIENT_BIT, sslClientBit);
    }

    /**
     * Retrieves SSL Server bit
     *
     * @return SSL Server bit
     */
    public String getSSLServerBit() {
        return (String) get(Constants.PR_SSL_SERVER_BIT);
    }

    /**
     * Sets SSL Server bit
     *
     * @param sslServerBit SSL Server bit
     */
    public void setSSLServerBit(String sslServerBit) {
        put(Constants.PR_SSL_SERVER_BIT, sslServerBit);
    }

    /**
     * Retrieves SSL Mail bit
     *
     * @return SSL Mail bit
     */
    public String getSSLMailBit() {
        return (String) get(Constants.PR_SSL_MAIL_BIT);
    }

    /**
     * Sets SSL Mail bit
     *
     * @param sslMailBit SSL Mail bit
     */
    public void setSSLMailBit(String sslMailBit) {
        put(Constants.PR_SSL_MAIL_BIT, sslMailBit);
    }

    /**
     * Retrieves SSL CA bit
     *
     * @return SSL CA bit
     */
    public String getSSLCABit() {
        return (String) get(Constants.PR_SSL_CA_BIT);
    }

    /**
     * Sets SSL CA bit
     *
     * @param cabit SSL CA bit
     */
    public void setSSLCABit(String cabit) {
        put(Constants.PR_SSL_CA_BIT, cabit);
    }

    /**
     * Retrieves SSL Signing bit
     *
     * @return SSL Signing bit
     */
    public String getObjectSigningBit() {
        return (String) get(Constants.PR_OBJECT_SIGNING_BIT);
    }

    /** 
     * Retrieves Time Stamping bit
     *
     * @return Time Stamping bit
     */
    public String getTimeStampingBit() {
        return (String) get(Constants.PR_TIMESTAMPING_BIT);
    }

    /**
     * Sets SSL Signing bit
     *
     * @param objectSigningBit SSL Signing bit
     */
    public void setObjectSigningBit(String objectSigningBit) {
        put(Constants.PR_OBJECT_SIGNING_BIT, objectSigningBit);
    }

    /**
     * Retrieves SSL Mail CA bit
     *
     * @return SSL Mail CA bit
     */
    public String getMailCABit() {
        return (String) get(Constants.PR_MAIL_CA_BIT);
    }

    /**
     * Sets SSL Mail CA bit
     *
     * @param mailCABit SSL Mail CA bit
     */
    public void setMailCABit(String mailCABit) {
        put(Constants.PR_MAIL_CA_BIT, mailCABit);
    }

    /**
     * Retrieves SSL Object Signing bit
     *
     * @return SSL Object Signing bit
     */
    public String getObjectSigningCABit() {
        return (String) get(Constants.PR_OBJECT_SIGNING_CA_BIT);
    }

    /**
     * Sets SSL Object Signing bit
     *
     * @param bit SSL Object Signing bit
     */
    public void setObjectSigningCABit(String bit) {
        put(Constants.PR_OBJECT_SIGNING_CA_BIT, bit);
    }

    /**
     * Retrieves OCSP Signing flag
     *
     * @return OCSP Signing flag
     */
    public String getOCSPSigning() {
        return (String) get(Constants.PR_OCSP_SIGNING);
    }

    /**
     * Sets OCSP Signing flag
     *
     * @param aki OCSP Signing flag
     */
    public void setOCSPSigning(String aki) {
        put(Constants.PR_OCSP_SIGNING, aki);
    }

    /**
     * Retrieves OCSP No Check flag
     *
     * @return OCSP No Check flag
     */
    public String getOCSPNoCheck() {
        return (String) get(Constants.PR_OCSP_NOCHECK);
    }

    /**
     * Sets OCSP No Check flag
     *
     * @param noCheck OCSP No Check flag
     */
    public void setOCSPNoCheck(String noCheck) {
        put(Constants.PR_OCSP_NOCHECK, noCheck);
    }

    /**
     * Retrieves Authority Information Access flag
     *
     * @return Authority Information Access flag
     */
    public String getAIA() {
        return (String) get(Constants.PR_AIA);
    }

    /**
     * Sets Authority Information Access flag
     *
     * @param aia Authority Information Access flag
     */
    public void setAIA(String aia) {
        put(Constants.PR_AIA, aia);
    }

    /**
     * Retrieves Authority Key Identifier flag
     *
     * @return Authority Key Identifier flag
     */
    public String getAKI() {
        return (String) get(Constants.PR_AKI);
    }

    /**
     * Sets Authority Key Identifier flag
     *
     * @param aki Authority Key Identifier flag
     */
    public void setAKI(String aki) {
        put(Constants.PR_AKI, aki);
    }

    /**
     * Retrieves Subject Key Identifier flag
     *
     * @return Subject Key Identifier flag
     */
    public String getSKI() {
        return (String) get(Constants.PR_SKI);
    }

    /**
     * Sets Subject Key Identifier flag
     *
     * @param ski Subject Key Identifier flag
     */
    public void setSKI(String ski) {
        put(Constants.PR_SKI, ski);
    }

    /**
     * Retrieves key usage extension
     *
     * @return true if key usage extension set
     */
    public boolean getKeyUsageExtension() {
        String str = (String) get(Constants.PR_KEY_USAGE);

        if (str == null || str.equals(ConfigConstants.FALSE))
            return false;
        return true;
    }

    /**
     * Sets CA extensions
     *
     * @param ext CA extensions
     */
    public void setCAExtensions(CertificateExtensions ext) {
        put("CAEXTENSIONS", ext);
    }

    /**
     * Retrieves CA extensions
     *
     * @return CA extensions
     */
    public CertificateExtensions getCAExtensions() {
        return (CertificateExtensions) get("CAEXTENSIONS");
    }

    /**
     * Retrieves hash type
     *
     * @return hash type
     */
    public String getHashType() {
        return (String) get(ConfigConstants.PR_HASH_TYPE);
    }
}

