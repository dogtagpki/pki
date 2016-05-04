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
package com.netscape.cms.profile.constraint;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.ERejectException;
import com.netscape.certsrv.profile.IPolicyDefault;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.profile.def.AuthzRealmDefault;
import com.netscape.cms.profile.def.NoDefault;

import netscape.security.x509.X509CertInfo;

/**
 * This class implements the authz realm constraint.
 * It checks if the authz realm in the certificate
 * template satisfies the criteria.
 *
 * @version $Revision$, $Date$
 */
public class AuthzRealmConstraint extends EnrollConstraint {

    public static final String CONFIG_REALMS_ALLOWED = "realmsAllowed";

    public AuthzRealmConstraint() {
        super();
        addConfigName(CONFIG_REALMS_ALLOWED);
    }

    public void init(IProfile profile, IConfigStore config)
            throws EProfileException {
        super.init(profile, config);
    }

    public void setConfig(String name, String value)
            throws EPropertyException {

        if (mConfig.getSubStore("params") == null) {
            CMS.debug("AuthzRealmConstraint: mConfig.getSubStore is null");
            return;
        }

        CMS.debug("AuthzRealmConstraint: setConfig name=" + name +
                " value=" + value);

        mConfig.getSubStore("params").putString(name, value);
    }

    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        if (name.equals(CONFIG_REALMS_ALLOWED)) {
            return new Descriptor(IDescriptor.STRING, null, null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_AUTHZ_REALMS_ALLOWED"));
        }
        return null;
    }

    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_CONSTRAINT_REALM_TEXT",
                getConfig(CONFIG_REALMS_ALLOWED));
    }

    public boolean isApplicable(IPolicyDefault def) {
        if (def instanceof NoDefault)
            return true;
        if (def instanceof AuthzRealmDefault)
            return true;
        return false;
    }

    @Override
    public void validate(IRequest request, X509CertInfo info) throws ERejectException {
        String realm = request.getRealm();
        List<String> allowedRealms = Arrays.asList(getConfig(CONFIG_REALMS_ALLOWED).split("\\s*,\\s*"));
        if (! allowedRealms.contains(realm)) {
            throw new ERejectException(CMS.getUserMessage(
                    getLocale(request),
                    "CMS_PROFILE_AUTHZ_REALM_NOT_MATCHED", realm));
        }

        // TODO: code here to check authz based on identity

    }

}
