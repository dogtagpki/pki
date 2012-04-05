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
package com.netscape.cms.profile.constraint;

import java.io.IOException;
import java.util.Date;
import java.util.Locale;

import netscape.security.x509.CertificateValidity;
import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.ERejectException;
import com.netscape.certsrv.profile.IPolicyDefault;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.profile.def.CAValidityDefault;
import com.netscape.cms.profile.def.NoDefault;
import com.netscape.cms.profile.def.UserValidityDefault;
import com.netscape.cms.profile.def.ValidityDefault;

/**
 * This class implements the validity constraint.
 * It checks if the validity in the certificate
 * template is within the CA's validity.
 *
 * @version $Revision$, $Date$
 */
public class CAValidityConstraint extends CAEnrollConstraint {

    private Date mDefNotBefore = null;
    private Date mDefNotAfter = null;

    public CAValidityConstraint() {
        super();
    }

    public void init(IProfile profile, IConfigStore config)
            throws EProfileException {
        super.init(profile, config);
        X509CertImpl caCert = getCACert();

        mDefNotBefore = caCert.getNotBefore();
        mDefNotAfter = caCert.getNotAfter();
    }

    /**
     * Validates the request. The request is not modified
     * during the validation.
     */
    public void validate(IRequest request, X509CertInfo info)
            throws ERejectException {
        CMS.debug("CAValidityConstraint: validate start");
        CertificateValidity v = null;

        try {
            v = (CertificateValidity) info.get(X509CertInfo.VALIDITY);
        } catch (Exception e) {
            throw new ERejectException(CMS.getUserMessage(
                        getLocale(request), "CMS_PROFILE_VALIDITY_NOT_FOUND"));
        }
        Date notBefore = null;

        try {
            notBefore = (Date) v.get(CertificateValidity.NOT_BEFORE);
        } catch (IOException e) {
            CMS.debug("CAValidity: not before " + e.toString());
            throw new ERejectException(CMS.getUserMessage(
                        getLocale(request), "CMS_PROFILE_INVALID_NOT_BEFORE"));
        }
        Date notAfter = null;

        try {
            notAfter = (Date) v.get(CertificateValidity.NOT_AFTER);
        } catch (IOException e) {
            CMS.debug("CAValidity: not after " + e.toString());
            throw new ERejectException(CMS.getUserMessage(
                        getLocale(request), "CMS_PROFILE_INVALID_NOT_AFTER"));
        }

        if (mDefNotBefore != null) {
            CMS.debug("ValidtyConstraint: notBefore=" + notBefore +
                    " defNotBefore=" + mDefNotBefore);
            if (notBefore.before(mDefNotBefore)) {
                throw new ERejectException(CMS.getUserMessage(
                            getLocale(request), "CMS_PROFILE_INVALID_NOT_BEFORE"));
            }
        }
        CMS.debug("ValidtyConstraint: notAfter=" + notAfter +
                " defNotAfter=" + mDefNotAfter);
        if (notAfter.after(mDefNotAfter)) {
            throw new ERejectException(CMS.getUserMessage(
                        getLocale(request), "CMS_PROFILE_INVALID_NOT_AFTER"));
        }

        CMS.debug("CAValidtyConstraint: validate end");
    }

    public String getText(Locale locale) {
        String params[] = {
                mDefNotBefore.toString(),
                mDefNotAfter.toString()
            };

        return CMS.getUserMessage(locale,
                "CMS_PROFILE_CONSTRAINT_CA_VALIDITY_CONSTRAINT_TEXT",
                params);
    }

    public boolean isApplicable(IPolicyDefault def) {
        if (def instanceof NoDefault)
            return true;
        if (def instanceof UserValidityDefault)
            return true;
        if (def instanceof ValidityDefault)
            return true;
        if (def instanceof CAValidityDefault)
            return true;
        return false;
    }
}
