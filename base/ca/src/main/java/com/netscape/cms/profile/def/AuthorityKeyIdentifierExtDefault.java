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

import org.mozilla.jss.netscape.security.x509.AuthorityKeyIdentifierExtension;
import org.mozilla.jss.netscape.security.x509.KeyIdentifier;
import org.mozilla.jss.netscape.security.x509.PKIXExtensions;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.request.Request;

/**
 * This class implements an enrollment default policy
 * that populates Authority Key Identifier extension
 * into the certificate template.
 *
 * @version $Revision$, $Date$
 */
public class AuthorityKeyIdentifierExtDefault extends CAEnrollDefault {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(AuthorityKeyIdentifierExtDefault.class);

    public static final String VAL_CRITICAL = "critical";
    public static final String VAL_KEY_ID = "keyid";

    public AuthorityKeyIdentifierExtDefault() {
        super();

        addValueName(VAL_CRITICAL);
        addValueName(VAL_KEY_ID);
    }

    @Override
    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(VAL_CRITICAL)) {
            return new Descriptor(IDescriptor.STRING,
                    IDescriptor.READONLY, null, CMS.getUserMessage(locale,
                            "CMS_PROFILE_CRITICAL"));
        } else if (name.equals(VAL_KEY_ID)) {
            return new Descriptor(IDescriptor.STRING,
                    IDescriptor.READONLY, null, CMS.getUserMessage(locale,
                            "CMS_PROFILE_KEY_ID"));
        } else {
            return null;
        }
    }

    @Override
    public void setValue(String name, Locale locale,
            X509CertInfo info, String value)
            throws EPropertyException {
        if (name == null) {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
        if (name.equals(VAL_CRITICAL)) {
            // do nothing for read only value
        } else if (name.equals(VAL_KEY_ID)) {
            // do nothing for read only value
        } else {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
    }

    @Override
    public String getValue(String name, Locale locale,
            X509CertInfo info)
            throws EPropertyException {
        if (name == null) {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
        if (info == null) {
            // info is null; possibly strippedldapRecords enabled
            return null;
        }

        AuthorityKeyIdentifierExtension ext =
                (AuthorityKeyIdentifierExtension) getExtension(
                        PKIXExtensions.AuthorityKey_Id.toString(), info);

        if (ext == null) {
            try {
                populate(null, info);

            } catch (EProfileException e) {
                logger.error("AuthorityKeyIdentifierExtDefault: getValue " + e.getMessage(), e);
                throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
            }

        }
        if (name.equals(VAL_CRITICAL)) {
            ext =
                    (AuthorityKeyIdentifierExtension) getExtension(
                            PKIXExtensions.AuthorityKey_Id.toString(), info);

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
                    (AuthorityKeyIdentifierExtension) getExtension(
                            PKIXExtensions.AuthorityKey_Id.toString(), info);

            if (ext == null) {
                // do something here
                return "";
            }
            KeyIdentifier kid = null;

            try {
                kid = (KeyIdentifier)
                        ext.get(AuthorityKeyIdentifierExtension.KEY_ID);
            } catch (IOException e) {
                logger.warn("AuthorityKeyIdentifierExtDefault: " + e.getMessage(), e);
            }
            if (kid == null)
                return "";
            return toHexString(kid.getIdentifier());
        } else {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
    }

    @Override
    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_DEF_AKI_EXT");
    }

    /**
     * Populates the request with this policy default.
     */
    @Override
    public void populate(Request request, X509CertInfo info)
            throws EProfileException {

        AuthorityKeyIdentifierExtension ext;
        try {
            String localKey = getConfig("localKey");
            KeyIdentifier kid = null;

            if (localKey != null && localKey.equals("true")) {
                kid = getKeyIdentifier(info);

            } else {
                String authorityID = request.getExtDataInString(Request.AUTHORITY_ID);
                X509CertImpl signingCert = getSigningCert(authorityID);
                kid = getCAKeyIdentifier(signingCert);
            }

            ext = createExtension(kid);

        } catch (Exception e) {
            throw new EProfileException(e);
        }

        if (ext == null) {
            throw new EProfileException(
                "Could not instantiate AuthorityKeyIdentifier extension.");
        }

        addExtension(PKIXExtensions.AuthorityKey_Id.toString(), ext, info);
    }

    public AuthorityKeyIdentifierExtension createExtension(KeyIdentifier kid) throws EBaseException {

        if (kid == null)
            return null;

        AuthorityKeyIdentifierExtension ext = null;
        try {
            ext = new AuthorityKeyIdentifierExtension(false, kid, null, null);
        } catch (IOException e) {
            logger.warn("AuthorityKeyIdentifierExtDefault: createExtension " + e.getMessage(), e);
        }

        return ext;
    }
}
