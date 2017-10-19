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
import java.util.Locale;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cmsutil.crypto.CryptoUtil;

import netscape.security.x509.CertificateX509Key;
import netscape.security.x509.KeyIdentifier;
import netscape.security.x509.PKIXExtensions;
import netscape.security.x509.SubjectKeyIdentifierExtension;
import netscape.security.x509.X509CertInfo;
import netscape.security.x509.X509Key;

/**
 * This class implements an enrollment default policy
 * that populates a subject key identifier extension
 * into the certificate template.
 *
 * @version $Revision$, $Date$
 */
public class SubjectKeyIdentifierExtDefault extends EnrollExtDefault {

    public static final String CONFIG_CRITICAL = "critical";

    public static final String VAL_CRITICAL = "critical";
    public static final String VAL_KEY_ID = "keyid";
    public static final String CONFIG_MD = "messageDigest";
    public static final String VAL_MD = "messageDigest";
    public static final String DEF_CONFIG_MDS = "SHA-1,SHA-256,SHA-384,SHA-512";
    public static final String MD_LABEL="Message digest";

    public SubjectKeyIdentifierExtDefault() {
        super();

        CMS.debug("SubjectKeyIdentifierExtDefault: adding config name. " + CONFIG_MD);
        addConfigName(CONFIG_MD);
        CMS.debug("SubjectKeyIdentifierExtDefault: done adding config name. " + CONFIG_MD);
        addValueName(VAL_CRITICAL);
        addValueName(VAL_KEY_ID);

        addValueName(VAL_MD);
    }

    public void init(IProfile profile, IConfigStore config)
            throws EProfileException {
        super.init(profile, config);
    }

    public IDescriptor getConfigDescriptor(Locale locale, String name) { /* testms */
        if (name.equals(CONFIG_MD)) {
            return new Descriptor(IDescriptor.CHOICE, DEF_CONFIG_MDS,
                    "SHA-1",
                    MD_LABEL);
        } else {
            return null;
        }
    }


    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(VAL_CRITICAL)) {
            return new Descriptor(IDescriptor.STRING,
                    IDescriptor.READONLY,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_CRITICAL"));
        } else if (name.equals(VAL_KEY_ID)) {
            return new Descriptor(IDescriptor.STRING,
                    IDescriptor.READONLY,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_KEY_ID"));
        } else if (name.equals(VAL_MD)) {
           return new Descriptor(IDescriptor.STRING,
                   IDescriptor.READONLY,
                   null,
                   MD_LABEL);
        } else {
            return null;
        }
    }

    public void setValue(String name, Locale locale,
            X509CertInfo info, String value)
            throws EPropertyException {
        if (name == null) {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
        if (name.equals(VAL_CRITICAL)) {
            // read-only; do nothing
        } else if (name.equals(VAL_KEY_ID)) {
            // read-only; do nothing
        } else if (name.equals(VAL_MD)) {
            // read-only; do nothing
            CMS.debug("value: " + value );
        } else {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
    }

    public String getValue(String name, Locale locale,
            X509CertInfo info)
            throws EPropertyException {
        if (name == null) {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }

        SubjectKeyIdentifierExtension ext =
                (SubjectKeyIdentifierExtension) getExtension(
                        PKIXExtensions.SubjectKey_Id.toString(), info);

        if (ext == null) {
            try {
                populate(null, info);

            } catch (EProfileException e) {
                throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
            }

        }

        if (name.equals(VAL_CRITICAL)) {
            ext =
                    (SubjectKeyIdentifierExtension) getExtension(
                            PKIXExtensions.SubjectKey_Id.toString(), info);

            if (ext == null) {
                return null;
            }
            if (ext.isCritical()) {
                return "true";
            } else {
                return "false";
            }
        } else if (name.equals(VAL_KEY_ID)) {
            ext =
                    (SubjectKeyIdentifierExtension) getExtension(
                            PKIXExtensions.SubjectKey_Id.toString(), info);

            if (ext == null) {
                return null;
            }
            KeyIdentifier kid = null;

            try {
                kid = (KeyIdentifier)
                        ext.get(SubjectKeyIdentifierExtension.KEY_ID);
            } catch (IOException e) {
                CMS.debug("SubjectKeyIdentifierExtDefault::getValue() - " +
                           "kid is null!");
                throw new EPropertyException(CMS.getUserMessage(locale,
                                                                  "CMS_INVALID_PROPERTY",
                                                                  name));
            }
            return toHexString(kid.getIdentifier());
        } else if (name.equals(VAL_MD)) {
            String alg = getConfig(CONFIG_MD);

            if(alg == null || alg.length() == 0) {
                alg = "SHA-1";
            }
            return alg;
        } else {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
    }

    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_DEF_SUBJECT_KEY_ID_EXT");
    }

    /**
     * Populates the request with this policy default.
     */
    public void populate(IRequest request, X509CertInfo info)
            throws EProfileException {
        SubjectKeyIdentifierExtension ext = createExtension(info);

        addExtension(PKIXExtensions.SubjectKey_Id.toString(), ext, info);
    }

    public SubjectKeyIdentifierExtension createExtension(X509CertInfo info) {
        KeyIdentifier kid = getKeyIdentifier(info);

        if (kid == null) {
            CMS.debug("SubjectKeyIdentifierExtDefault: KeyIdentifier not found");
            return null;
        }
        SubjectKeyIdentifierExtension ext = null;

        boolean critical = Boolean.valueOf(getConfig(CONFIG_CRITICAL)).booleanValue();

        try {
            ext = new SubjectKeyIdentifierExtension(critical, kid.getIdentifier());
        } catch (IOException e) {
            CMS.debug("SubjectKeyIdentifierExtDefault: createExtension " +
                    e.toString());
            //
        }
        return ext;
    }

    public KeyIdentifier getKeyIdentifier(X509CertInfo info) {
        String method = "SubjectKeyIdentifierExtDefault: getKeyIdentifier: ";
        try {

            String configHashAlg = getConfig(CONFIG_MD);

            CMS.debug(method + " configured hash alg: " + configHashAlg);
            CertificateX509Key infokey = (CertificateX509Key)
                    info.get(X509CertInfo.KEY);
            X509Key key = (X509Key) infokey.get(CertificateX509Key.KEY);

            // "SHA-1" is default for CryptoUtil.generateKeyIdentifier.
            // you could specify different algorithm with the alg parameter
            // like this:
            //byte[] hash = CryptoUtil.generateKeyIdentifier(key.getKey(), "SHA-256");

            byte[] hash = null;

            if (configHashAlg != null && configHashAlg.length() != 0) {
                CMS.debug(method + " generating hash with alg: " + configHashAlg);
                hash = CryptoUtil.generateKeyIdentifier(key.getKey(), configHashAlg);
            } else {
                CMS.debug(method + " generating hash with default alg: SHA-1");
                hash = CryptoUtil.generateKeyIdentifier(key.getKey());
            }

            if (hash == null) {
                CMS.debug(method +
                    "CryptoUtil.generateKeyIdentifier returns null");
                return null;
            }
            return new KeyIdentifier(hash);
        } catch (Exception e) {
            CMS.debug(method + e.toString());
        }
        return null;
    }
}
