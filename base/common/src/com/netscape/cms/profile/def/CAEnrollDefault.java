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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import netscape.security.x509.CertificateX509Key;
import netscape.security.x509.KeyIdentifier;
import netscape.security.x509.PKIXExtensions;
import netscape.security.x509.SubjectKeyIdentifierExtension;
import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509CertInfo;
import netscape.security.x509.X509Key;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.ca.ICertificateAuthority;

/**
 * This class implements an abstract CA specific
 * Enrollment default. This policy can only be
 * used with CA subsystem.
 *
 * @version $Revision$, $Date$
 */
public abstract class CAEnrollDefault extends EnrollDefault {
    public CAEnrollDefault() {
    }

    public KeyIdentifier getKeyIdentifier(X509CertInfo info) {
        try {
            CertificateX509Key ckey = (CertificateX509Key)
                    info.get(X509CertInfo.KEY);
            X509Key key = (X509Key) ckey.get(CertificateX509Key.KEY);
            MessageDigest md = MessageDigest.getInstance("SHA-1");

            md.update(key.getKey());
            byte[] hash = md.digest();

            return new KeyIdentifier(hash);
        } catch (IOException e) {
            CMS.debug("AuthorityKeyIdentifierExtDefault: getKeyId " +
                    e.toString());
        } catch (CertificateException e) {
            CMS.debug("AuthorityKeyIdentifierExtDefault: getKeyId " +
                    e.toString());
        } catch (NoSuchAlgorithmException e) {
            CMS.debug("AuthorityKeyIdentifierExtDefault: getKeyId " +
                    e.toString());
        }
        return null;
    }

    public KeyIdentifier getCAKeyIdentifier() {
        ICertificateAuthority ca = (ICertificateAuthority)
                CMS.getSubsystem(CMS.SUBSYSTEM_CA);
        X509CertImpl caCert = ca.getCACert();
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
            }
        }

        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");

            md.update(key.getKey());
            byte[] hash = md.digest();

            return new KeyIdentifier(hash);
        } catch (NoSuchAlgorithmException e) {
            CMS.debug("AuthorityKeyIdentifierExtDefault: getKeyId " +
                    e.toString());
        }
        return null;
    }
}
