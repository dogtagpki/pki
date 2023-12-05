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
package com.netscape.cms.profile.def;

import java.io.IOException;
import java.security.cert.CertificateException;

import org.mozilla.jss.netscape.security.x509.CertificateX509Key;
import org.mozilla.jss.netscape.security.x509.KeyIdentifier;
import org.mozilla.jss.netscape.security.x509.PKIXExtensions;
import org.mozilla.jss.netscape.security.x509.SubjectKeyIdentifierExtension;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.mozilla.jss.netscape.security.x509.X509Key;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * This class implements an abstract CA specific
 * Enrollment default. This policy can only be
 * used with CA subsystem.
 *
 * @version $Revision$, $Date$
 */
public abstract class CAEnrollDefault extends EnrollDefault {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CAEnrollDefault.class);

    public CAEnrollDefault() {
    }

    public KeyIdentifier getKeyIdentifier(X509CertInfo info) {
        return getKeyIdentifier(info, "SHA-1");
    }
    public KeyIdentifier getKeyIdentifier(X509CertInfo info, String messageDigest) {
        String method = "CAEnrollDefault: getKeyIdentifier: ";
        try {
            /*
             * The SKI must be placed before the AKI in the enrollment profile
             * for this to work properly
             */
            SubjectKeyIdentifierExtension ext = (SubjectKeyIdentifierExtension) getExtension(PKIXExtensions.SubjectKey_Id.toString(), info);
            if (ext != null) {
                logger.debug(method + "found SubjectKey_Id extension");
                KeyIdentifier kid = (KeyIdentifier) ext.get(SubjectKeyIdentifierExtension.KEY_ID);
                return kid;
            }
            // ski not found, calculate the ski
            CertificateX509Key ckey = (CertificateX509Key)
                    info.get(X509CertInfo.KEY);
            X509Key key = (X509Key) ckey.get(CertificateX509Key.KEY);
            byte[] hash = CryptoUtil.generateKeyIdentifier(key.getKey(), messageDigest);
            if (hash == null) {
                logger.warn(method + "CryptoUtil.generateKeyIdentifier returns null");
                return null;
            }

            return new KeyIdentifier(hash);
        } catch (IOException e) {
            logger.warn(method + e.getMessage(), e);
        } catch (CertificateException e) {
            logger.warn(method + e.getMessage(), e);
        }
        return null;
    }

    public KeyIdentifier getCAKeyIdentifier(X509CertImpl caCert) throws EBaseException {
        String method = "CAEnrollDefault: getCAKeyIdentifier: ";
        if (caCert == null) {
            // during configuration, we dont have the CA certificate
            return null;
        }
        X509Key key = (X509Key) caCert.getPublicKey();

        SubjectKeyIdentifierExtension subjKeyIdExt =
                (SubjectKeyIdentifierExtension)
                caCert.getExtension(PKIXExtensions.SubjectKey_Id.toString());
        if (subjKeyIdExt != null) {
            try {
                KeyIdentifier keyId = (KeyIdentifier) subjKeyIdExt.get(
                        SubjectKeyIdentifierExtension.KEY_ID);
                return keyId;
            } catch (IOException e) {
                logger.warn(method + e.toString());
                return null;
            }
        }
        logger.warn(method + "SubjectKeyIdentifierExtension not found in CA signing cert. Returning null");
            return null;

        /* SubjectKeyIdentifierExtension has to exist in a CA signing cert
        byte[] hash = CryptoUtil.generateKeyIdentifier(key.getKey());
        if (hash == null) {
            logger.warn(method + "CryptoUtil.generateKeyIdentifier returns null");
            return null;
        }
        return new KeyIdentifier(hash);
        */
    }
}
