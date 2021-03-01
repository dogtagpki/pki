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
// (C) 2016 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.profile.def;

import java.io.IOException;
import java.util.Locale;

import org.mozilla.jss.netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cmscore.apps.CMS;

public class AuthzRealmDefault extends EnrollDefault {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(AuthzRealmDefault.class);

    public static final String CONFIG_REALM = "realm";
    public static final String VAL_REALM = "realm";

    public AuthzRealmDefault() {
        super();
        addConfigName(CONFIG_REALM);
        addValueName(VAL_REALM);
    }

    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        if (name.equals(CONFIG_REALM)) {
            return new Descriptor(IDescriptor.STRING, null, null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_AUTHZ_REALM"));
        }
        return null;
    }

    @Override
    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(VAL_REALM)) {
            return new Descriptor(IDescriptor.STRING, null, null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_AUTHZ_REALM"));
        }
        return null;
    }

    @Override
    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_DEF_AUTHZ_REALM",
                getConfig(CONFIG_REALM));
    }

    @Override
    public void populate(IRequest request, X509CertInfo info) throws EProfileException {
        try {
            request.setRealm(mapPattern(request, getConfig(CONFIG_REALM)));
        } catch (IOException e) {
            logger.error("authzRealmDefault: failed to populate request" + e.getMessage(), e);
            throw new EProfileException(e);
        }
    }

    @Override
    public void setValue(String name, Locale locale, X509CertInfo info, String value)
            throws EPropertyException {
    }

    @Override
    public String getValue(String name, Locale locale, X509CertInfo info)
            throws EPropertyException {
        return null;
    }

}
