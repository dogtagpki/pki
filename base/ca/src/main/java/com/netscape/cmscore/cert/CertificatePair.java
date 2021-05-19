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
package com.netscape.cmscore.cert;

import java.io.IOException;
import java.io.OutputStream;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.asn1.ANY;
import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.Tag;

import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.cert.ICrossCertPairSubsystem;

/**
 * This class implements CertificatePair used for Cross Certification
 *
 * @author cfu
 * @version $Revision$, $Date$
 */
public class CertificatePair implements ASN1Value {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CertificatePair.class);

    private byte[] mForward; // cert cross-siged by another CA
    private byte[] mReverse; // subordinate cert signed by this CA
    private static final Tag TAG = SEQUENCE.TAG;

    /**
     * construct a CertificatePair. It doesn't matter which is
     * forward and which is reverse in the parameters. It will figure
     * it out
     *
     * @param cert1 one X509Certificate
     * @param cert2 one X509Certificate
     */
    public CertificatePair(X509Certificate cert1, X509Certificate cert2)
            throws EBaseException {
        if ((cert1 == null) || (cert2 == null))
            throw new EBaseException("CertificatePair: both certs can not be null");
        logger.debug("CertifiatePair: in CertificatePair()");
        boolean rightOrder = certOrders(cert1, cert2);

        try {
            if (rightOrder == false) {
                mForward = cert2.getEncoded();
                mReverse = cert1.getEncoded();
            } else {
                mForward = cert1.getEncoded();
                mReverse = cert2.getEncoded();
            }
        } catch (CertificateException e) {
            throw new EBaseException("CertificatePair: constructor failed:" + e.toString());
        }
    }

    /**
     * construct a CertificatePair. It doesn't matter which is
     * forward and which is reverse in the parameters. It will figure
     * it out
     *
     * @param cert1 one certificate byte array
     * @param cert2 one certificate byte array
     */
    public CertificatePair(byte[] cert1, byte[] cert2)
            throws EBaseException {
        if ((cert1 == null) || (cert2 == null))
            throw new EBaseException("CertificatePair: both certs can not be null");
        boolean rightOrder = certOrders(cert1, cert2);

        if (rightOrder == false) {
            mForward = cert2;
            mReverse = cert1;
        } else {
            mForward = cert1;
            mReverse = cert2;
        }
    }

    /*
     * returns true if c1 is forward and cert2 is reverse
     * returns false if c2 is forward and cert1 is reverse
     */
    private boolean certOrders(X509Certificate c1, X509Certificate c2)
            throws EBaseException {

        logger.debug("CertifiatePair: in certOrders() with X509Cert");

        CAEngine engine = CAEngine.getInstance();
        CertificateAuthority ca = engine.getCA();
        X509Certificate caCert = ca.getCACert();

        logger.debug("CertifiatePair: got this caCert");
        // reverse cert is the one signed by this ca
        // more check really should be done here regarding the
        // validity of the two certs...later

        /* It looks the DN's returned are not normalized and fail
         * comparison

         if ((c1.getIssuerDN().equals((Object) caCert.getSubjectDN())))
         logger.debug("CertifiatePair: myCA signed c1");
         else {
         logger.debug("CertifiatePair: c1 issuerDN="+c1.getIssuerDN().toString());
         logger.debug("CertifiatePair: myCA subjectDN="+caCert.getSubjectDN().toString());
         }

         if(caCert.getSubjectDN().equals((Object) c2.getSubjectDN()))
         logger.debug("CertifiatePair: myCA subject == c2 subject");
         else {
         logger.debug("CertifiatePair: caCert subjectDN="+caCert.getSubjectDN().toString());
         logger.debug("CertifiatePair: c2 subjectDN="+c2.getSubjectDN().toString());
         }

         if ((c2.getIssuerDN().equals((Object) caCert.getSubjectDN())))
         logger.debug("CertifiatePair: myCA signed c2");
         else {
         logger.debug("CertifiatePair: c2 issuerDN="+c1.getIssuerDN().toString());
         logger.debug("CertifiatePair: myCA subjectDN="+caCert.getSubjectDN().toString());
         }

         if(caCert.getSubjectDN().equals((Object) c1.getSubjectDN()))
         logger.debug("CertifiatePair: myCA subject == c1 subject");
         else {
         logger.debug("CertifiatePair: caCert subjectDN="+caCert.getSubjectDN().toString());
         logger.debug("CertifiatePair: c1 subjectDN="+c1.getSubjectDN().toString());
         }

         if ((c1.getIssuerDN().equals((Object) caCert.getSubjectDN()))
         && (caCert.getSubjectDN().equals((Object) c2.getSubjectDN())))

         {
         return false;
         } else if ((c2.getIssuerDN().equals((Object) caCert.getSubjectDN()))
         && (caCert.getSubjectDN().equals((Object) c1.getSubjectDN())))
         {
         return true;
         } else {
         throw new EBaseException("CertificatePair: need correct forward and reverse relationship to construct CertificatePair");
         }
         */

        /*
         * my other attempt:
         * one of the certs has to share the same public key as this
         * CA, and that will be the "forward" cert; the other one is
         * assumed to be the "reverse" cert
         */
        byte[] caCertBytes = caCert.getPublicKey().getEncoded();

        if (caCertBytes != null)
            logger.debug("CertifiatePair: got cacert public key bytes length=" + caCertBytes.length);
        else {
            logger.error("CertifiatePair: cacert public key bytes null");
            throw new EBaseException(
                    "CertificatePair: certOrders() fails to get this CA's signing certificate public key encoded");
        }

        byte[] c1Bytes = c1.getPublicKey().getEncoded();

        if (c1Bytes != null)
            logger.debug("CertifiatePair: got c1 public key bytes length=" + c1Bytes.length);
        else {
            logger.error("CertifiatePair: c1 cert public key bytes length null");
            throw new EBaseException("CertificatePair::certOrders() public key bytes are of length null");
        }

        byte[] c2Bytes = c2.getPublicKey().getEncoded();

        if (c2Bytes != null)
            logger.debug("CertifiatePair: got c2 public key bytes length=" + c2Bytes.length);
        else
            logger.debug("CertifiatePair: c2 cert public key bytes length null");

        if (byteArraysAreEqual(c1Bytes, caCertBytes)) {
            logger.debug("CertifiatePair: c1 has same public key as this ca");
            return true;
        } else if (byteArraysAreEqual(c2Bytes, caCertBytes)) {
            logger.debug("CertifiatePair: c2 has same public key as this ca");

            return false;
        } else {
            logger.error("CertifiatePair: neither c1 nor c2 public key matches with this ca");
            throw new EBaseException(
                    "CertificatePair: need correct forward and reverse relationship to construct CertificatePair");
        }
    }

    /**
     * compares contents two byte arrays returning true if exactly same.
     */
    public boolean byteArraysAreEqual(byte[] a, byte[] b) {
        logger.debug("CertifiatePair: in byteArraysAreEqual()");

        if (a == null && b == null) {
            return true;
        }
        if (a == null || b == null) {
            return false;
        }
        if (a.length != b.length) {
            logger.debug("CertifiatePair: exiting byteArraysAreEqual(): false");
            return false;
        }
        for (int i = 0; i < a.length; i++) {
            if (a[i] != b[i]) {
                logger.debug("CertifiatePair: exiting byteArraysAreEqual(): false");
                return false;
            }
        }
        logger.debug("CertifiatePair: exiting byteArraysAreEqual(): true");
        return true;
    }

    /*
     * returns true if cert1 is forward and cert2 is reverse
     * returns false if cert2 is forward and cert1 is reverse
     */
    private boolean certOrders(byte[] cert1, byte[] cert2)
            throws EBaseException {

        logger.debug("CertifiatePair: in certOrders() with byte[]");

        CAEngine engine = CAEngine.getInstance();
        ICrossCertPairSubsystem ccps = (ICrossCertPairSubsystem) engine.getSubsystem(ICrossCertPairSubsystem.ID);
        X509Certificate c1 = null;
        X509Certificate c2 = null;

        try {
            c1 = ccps.byteArray2X509Cert(cert1);
            c2 = ccps.byteArray2X509Cert(cert2);
        } catch (CertificateException e) {
            throw new EBaseException("CertificatePair: certOrders() failed:" + e.toString());
        }
        return certOrders(c1, c2);
    }

    @Override
    public void encode(OutputStream os) throws IOException {
        encode(TAG, os);
    }

    @Override
    public void encode(Tag implicitTag, OutputStream os) throws IOException {
        SEQUENCE seq = new SEQUENCE();

        if (mForward != null) {
            try {
                ANY any = new ANY(mForward);

                seq.addElement(any);
            } catch (InvalidBERException e) {
                logger.warn("CertifiatePair: encode error:" + e.toString());
            }
        }
        if (mReverse != null) {
            try {
                ANY any = new ANY(mReverse);

                seq.addElement(any);
            } catch (InvalidBERException e) {
                logger.warn("CertifiatePair: encode error:" + e.toString());
            }
        }

        seq.encode(implicitTag, os);
    }

    @Override
    public Tag getTag() {
        return TAG;
    }
}
