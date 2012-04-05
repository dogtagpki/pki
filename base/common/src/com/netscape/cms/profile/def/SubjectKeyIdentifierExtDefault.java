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
import java.util.Locale;

import netscape.security.x509.CertificateX509Key;
import netscape.security.x509.KeyIdentifier;
import netscape.security.x509.PKIXExtensions;
import netscape.security.x509.SubjectKeyIdentifierExtension;
import netscape.security.x509.X509CertInfo;
import netscape.security.x509.X509Key;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;

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

    public SubjectKeyIdentifierExtDefault() {
        super();
        addValueName(VAL_CRITICAL);
        addValueName(VAL_KEY_ID);
    }

    public void init(IProfile profile, IConfigStore config)
            throws EProfileException {
        super.init(profile, config);
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
        try {
            CertificateX509Key infokey = (CertificateX509Key)
                    info.get(X509CertInfo.KEY);
            X509Key key = (X509Key) infokey.get(CertificateX509Key.KEY);
            MessageDigest md = MessageDigest.getInstance("SHA-1");

            md.update(key.getKey());
            byte[] hash = md.digest();

            return new KeyIdentifier(hash);
        } catch (NoSuchAlgorithmException e) {
            CMS.debug("SubjectKeyIdentifierExtDefault: getKeyIdentifier " +
                    e.toString());
        } catch (Exception e) {
            CMS.debug("SubjectKeyIdentifierExtDefault: getKeyIdentifier " +
                    e.toString());
        }
        return null;
    }
}
