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
package com.netscape.cmscore.util;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;

import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.BMPString;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.SET;
import org.mozilla.jss.crypto.PBEAlgorithm;
import org.mozilla.jss.pkcs12.AuthenticatedSafes;
import org.mozilla.jss.pkcs12.CertBag;
import org.mozilla.jss.pkcs12.PFX;
import org.mozilla.jss.pkcs12.PasswordConverter;
import org.mozilla.jss.pkcs12.SafeBag;
import org.mozilla.jss.pkix.primitive.EncryptedPrivateKeyInfo;
import org.mozilla.jss.pkix.primitive.PrivateKeyInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;

public class PFXUtils {

    /**
     * Creates a PKCS12 package.
     */
    public static byte[] createPFX(String pwd, X509Certificate x509cert,
            byte privateKeyInfo[]) throws EBaseException {
        try {
            // add certificate
            SEQUENCE encSafeContents = new SEQUENCE();
            ASN1Value cert = new OCTET_STRING(
                    x509cert.getEncoded());
            byte localKeyId[] = createLocalKeyId(x509cert);
            SET certAttrs = createBagAttrs(
                    x509cert.getSubjectDN().toString(), localKeyId);
            // attributes: user friendly name, Local Key ID
            SafeBag certBag = new SafeBag(SafeBag.CERT_BAG,
                    new CertBag(CertBag.X509_CERT_TYPE, cert),
                    certAttrs);

            encSafeContents.addElement(certBag);

            // add key
            org.mozilla.jss.util.Password pass = new
                    org.mozilla.jss.util.Password(
                            pwd.toCharArray());

            SEQUENCE safeContents = new SEQUENCE();
            PasswordConverter passConverter = new
                    PasswordConverter();

            // XXX - should generate salt
            byte salt[] = { 0x01, 0x01, 0x01, 0x01 };
            PrivateKeyInfo pki = (PrivateKeyInfo)
                    ASN1Util.decode(PrivateKeyInfo.getTemplate(),
                            privateKeyInfo);
            ASN1Value key = EncryptedPrivateKeyInfo.createPBE(
                    PBEAlgorithm.PBE_SHA1_DES3_CBC,
                    pass, salt, 1, passConverter, pki);
            SET keyAttrs = createBagAttrs(
                    x509cert.getSubjectDN().toString(),
                    localKeyId);
            SafeBag keyBag = new SafeBag(
                    SafeBag.PKCS8_SHROUDED_KEY_BAG, key,
                    keyAttrs); // ??

            safeContents.addElement(keyBag);

            // build contents
            AuthenticatedSafes authSafes = new
                    AuthenticatedSafes();

            authSafes.addSafeContents(safeContents);
            authSafes.addSafeContents(encSafeContents);

            //                      authSafes.addEncryptedSafeContents(
            //                              authSafes.DEFAULT_KEY_GEN_ALG,
            //                              pass, null, 1,
            //                              encSafeContents);
            PFX pfx = new PFX(authSafes);

            pfx.computeMacData(pass, null, 5); // ??
            ByteArrayOutputStream fos = new
                    ByteArrayOutputStream();

            pfx.encode(fos);
            pass.clear();

            // put final PKCS12 into volatile request
            return fos.toByteArray();
        } catch (Exception e) {
            throw new EBaseException(
                    CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR",
                            "Failed to create PKCS12 - " + e.toString()));
        }
    }

    /**
     * Creates local key identifier.
     */
    public static byte[] createLocalKeyId(X509Certificate cert)
            throws EBaseException {
        try {
            byte certDer[] = cert.getEncoded();
            MessageDigest md = MessageDigest.getInstance("SHA");

            md.update(certDer);
            return md.digest();
        } catch (Exception e) {
            throw new EBaseException(
                    CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR",
                            "Failed to create Key ID - " + e.toString()));
        }
    }

    /**
     * Creates bag attributes.
     */
    public static SET createBagAttrs(String nickName, byte localKeyId[])
            throws EBaseException {
        try {
            SET attrs = new SET();
            SEQUENCE nickNameAttr = new SEQUENCE();

            nickNameAttr.addElement(SafeBag.FRIENDLY_NAME);
            SET nickNameSet = new SET();

            nickNameSet.addElement(new BMPString(nickName));
            nickNameAttr.addElement(nickNameSet);
            attrs.addElement(nickNameAttr);
            SEQUENCE localKeyAttr = new SEQUENCE();

            localKeyAttr.addElement(SafeBag.LOCAL_KEY_ID);
            SET localKeySet = new SET();

            localKeySet.addElement(new OCTET_STRING(localKeyId));
            localKeyAttr.addElement(localKeySet);
            attrs.addElement(localKeyAttr);
            return attrs;
        } catch (Exception e) {
            throw new EBaseException(
                    CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR",
                            "Failed to create Key Bag - " + e.toString()));
        }
    }
}
