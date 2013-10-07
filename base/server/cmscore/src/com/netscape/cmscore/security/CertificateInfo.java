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
package com.netscape.cmscore.security;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.util.Calendar;
import java.util.Date;

import netscape.security.util.DerInputStream;
import netscape.security.util.ObjectIdentifier;
import netscape.security.x509.AlgorithmId;
import netscape.security.x509.AuthorityKeyIdentifierExtension;
import netscape.security.x509.CertificateAlgorithmId;
import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.CertificateIssuerName;
import netscape.security.x509.CertificateSerialNumber;
import netscape.security.x509.CertificateSubjectName;
import netscape.security.x509.CertificateValidity;
import netscape.security.x509.CertificateVersion;
import netscape.security.x509.CertificateX509Key;
import netscape.security.x509.KeyIdentifier;
import netscape.security.x509.KeyUsageExtension;
import netscape.security.x509.SubjectKeyIdentifierExtension;
import netscape.security.x509.X500Name;
import netscape.security.x509.X509CertInfo;
import netscape.security.x509.X509Key;

import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.crypto.PQGParamGenException;
import org.mozilla.jss.crypto.SignatureAlgorithm;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.common.ConfigConstants;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.security.KeyCertData;

/**
 * This base class provides methods to import CA signing cert or get certificate
 * request.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 */
public abstract class CertificateInfo {

    protected KeyCertData mProperties;
    protected KeyPair mKeyPair;
    protected IConfigStore mConfig;

    public CertificateInfo(KeyCertData properties) {
        this(properties, null);
    }

    public CertificateInfo(KeyCertData properties, KeyPair pair) {
        mProperties = properties;
        if (pair == null) {
            mKeyPair = (KeyPair) properties.get("keypair");
        } else {
            mKeyPair = pair;
        }
        mConfig = (IConfigStore) (mProperties.get("cmsFile"));
    }

    protected abstract KeyUsageExtension getKeyUsageExtension() throws IOException;

    public abstract String getSubjectName();

    //public abstract SignatureAlgorithm getSigningAlgorithm();
    public abstract String getKeyAlgorithm();

    public abstract String getNickname();

    public abstract void updateConfig(IConfigStore store) throws EBaseException;

    public CertificateValidity getCertificateValidity() throws EBaseException {

        /*
         String period = (String)mProperties.get(Constants.PR_VALIDITY_PERIOD);
         Date notBeforeDate = CMS.getCurrentDate();
         Date notAfterDate = new Date(notBeforeDate.getYear(),
         notBeforeDate.getMonth(),
         notBeforeDate.getDate()+Integer.parseInt(period));
         return new CertificateValidity(notBeforeDate, notAfterDate);
         */
        Date notBeforeDate = null;
        Date notAfterDate = null;
        String notBeforeStr = (String) mProperties.get("notBeforeStr");
        String notAfterStr = (String) mProperties.get("notAfterStr");

        if (notBeforeStr != null && notAfterStr != null) {
            notBeforeDate = new Date(Long.parseLong(notBeforeStr));
            notAfterDate = new Date(Long.parseLong(notAfterStr));
        } else {
            int beginYear =
                    Integer.parseInt(mProperties.getBeginYear()) - 1900;
            int afterYear =
                    Integer.parseInt(mProperties.getAfterYear()) - 1900;
            int beginMonth =
                    Integer.parseInt(mProperties.getBeginMonth());
            int afterMonth =
                    Integer.parseInt(mProperties.getAfterMonth());
            int beginDate =
                    Integer.parseInt(mProperties.getBeginDate());
            int afterDate =
                    Integer.parseInt(mProperties.getAfterDate());
            int beginHour =
                    Integer.parseInt(mProperties.getBeginHour());
            int afterHour =
                    Integer.parseInt(mProperties.getAfterHour());
            int beginMin =
                    Integer.parseInt(mProperties.getBeginMin());
            int afterMin =
                    Integer.parseInt(mProperties.getAfterMin());
            int beginSec =
                    Integer.parseInt(mProperties.getBeginSec());
            int afterSec =
                    Integer.parseInt(mProperties.getAfterSec());

            Calendar calendar = Calendar.getInstance();
            calendar.set(beginYear, beginMonth, beginDate,
                        beginHour, beginMin, beginSec);
            notBeforeDate = calendar.getTime();
            calendar.set(afterYear, afterMonth, afterDate,
                    afterHour, afterMin, afterSec);
            notAfterDate = calendar.getTime();
        }
        return new CertificateValidity(notBeforeDate, notAfterDate);
    }

    public X509CertInfo getCertInfo() throws EBaseException, PQGParamGenException {
        X509CertInfo certInfo = new X509CertInfo();

        try {
            certInfo.set(X509CertInfo.VERSION,
                    new CertificateVersion(CertificateVersion.V3));
            BigInteger serialNumber = mProperties.getSerialNumber();

            certInfo.set(X509CertInfo.SERIAL_NUMBER,
                    new CertificateSerialNumber(serialNumber));
            certInfo.set(X509CertInfo.EXTENSIONS, getExtensions());
            certInfo.set(X509CertInfo.VALIDITY, getCertificateValidity());
            String issuerName = mProperties.getIssuerName();

            if (issuerName == null) {
                issuerName = getSubjectName();
            }

            certInfo.set(X509CertInfo.ISSUER,
                    new CertificateIssuerName(new X500Name(issuerName)));
            certInfo.set(X509CertInfo.SUBJECT,
                    new CertificateSubjectName(new X500Name(getSubjectName())));
            certInfo.set(X509CertInfo.VERSION,
                    new CertificateVersion(CertificateVersion.V3));

            PublicKey pubk = mKeyPair.getPublic();
            X509Key xKey = KeyCertUtil.convertPublicKeyToX509Key(pubk);

            certInfo.set(X509CertInfo.KEY, new CertificateX509Key(xKey));
            //SignatureAlgorithm algm = getSigningAlgorithm();
            SignatureAlgorithm algm =
                    (SignatureAlgorithm) mProperties.get(Constants.PR_SIGNATURE_ALGORITHM);

            if (algm == null) {
                String hashtype = (String) mProperties.get(ConfigConstants.PR_HASH_TYPE);
                String key = getKeyAlgorithm();
                algm = KeyCertUtil.getSigningAlgorithm(key, hashtype);
                if (algm == null) {
                    throw new NoSuchAlgorithmException("Key : " + key + "/ Hashtype : " + hashtype);
                }
                mProperties.put(Constants.PR_SIGNATURE_ALGORITHM, algm);
            }

            AlgorithmId sigAlgId = getAlgorithmId();

            if (sigAlgId == null) {
                byte[] encodedOID = ASN1Util.encode(algm.toOID());

                sigAlgId = new AlgorithmId(new ObjectIdentifier(
                                new DerInputStream(encodedOID)));
            }
            certInfo.set(X509CertInfo.ALGORITHM_ID,
                    new CertificateAlgorithmId(sigAlgId));
        } catch (InvalidKeyException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_KEY"));
        } catch (CertificateException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_CERT", e.toString()));
        } catch (IOException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_CERT", e.toString()));
        } catch (NoSuchAlgorithmException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_ALG_NOT_SUPPORTED", e.getMessage()));
        }

        return certInfo;
    }

    public CertificateExtensions getExtensions() throws IOException,
            CertificateException, InvalidKeyException, NoSuchAlgorithmException {
        CertificateExtensions exts = new CertificateExtensions();

        KeyCertUtil.setExtendedKeyUsageExtension(exts, mProperties);
        KeyCertUtil.setDERExtension(exts, mProperties);
        KeyCertUtil.setBasicConstraintsExtension(exts, mProperties);
        KeyCertUtil.setSubjectKeyIdentifier(mKeyPair, exts, mProperties);
        //KeyCertUtil.setOCSPSigning(mKeyPair, exts, mProperties);
        KeyCertUtil.setAuthInfoAccess(mKeyPair, exts, mProperties);
        KeyCertUtil.setOCSPNoCheck(mKeyPair, exts, mProperties);
        String aki = mProperties.getAKI();

        if ((aki != null) && (aki.equals(Constants.TRUE))) {
            CertificateExtensions caexts = null;

            // if (this instanceof CASigningCert) {
            if (this.getClass().getName().indexOf("CASigningCert") != -1) {
                caexts = exts;
            } else {
                caexts = mProperties.getCAExtensions();
            }
            setAuthorityKeyIdExt(caexts, exts);
        }
        boolean isKeyUsageEnabled = mProperties.getKeyUsageExtension();

        if (isKeyUsageEnabled) {
            KeyCertUtil.setKeyUsageExtension(
                    exts, getKeyUsageExtension());
        }
        return exts;
    }

    public AlgorithmId getAlgorithmId() {
        return (AlgorithmId) (mProperties.get(Constants.PR_ALGORITHM_ID));
    }

    public void setAuthorityKeyIdExt(CertificateExtensions caexts, CertificateExtensions ext)
            throws IOException, CertificateException, CertificateEncodingException,
            CertificateParsingException {
        SubjectKeyIdentifierExtension subjKeyExt = null;

        try {
            subjKeyExt =
                    (SubjectKeyIdentifierExtension) caexts.get(SubjectKeyIdentifierExtension.NAME);
        } catch (IOException e) {
        }

        if (subjKeyExt == null)
            return;
        else {
            KeyIdentifier keyId = (KeyIdentifier) subjKeyExt.get(
                    SubjectKeyIdentifierExtension.KEY_ID);
            AuthorityKeyIdentifierExtension authExt =
                    new AuthorityKeyIdentifierExtension(false, keyId, null, null);

            ext.set(AuthorityKeyIdentifierExtension.NAME, authExt);
        }
    }
}
