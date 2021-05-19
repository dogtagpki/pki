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

import org.mozilla.jss.netscape.security.x509.CertificateValidity;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.ERejectException;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.profile.def.CAValidityDefault;
import com.netscape.cms.profile.def.PolicyDefault;
import com.netscape.cms.profile.def.NoDefault;
import com.netscape.cms.profile.def.UserValidityDefault;
import com.netscape.cms.profile.def.ValidityDefault;
import com.netscape.cmscore.apps.CMS;

/**
 * This class implements the validity constraint.
 * It checks if the validity in the certificate
 * template is within the CA's validity.
 *
 * @version $Revision$, $Date$
 */
public class CAValidityConstraint extends CAEnrollConstraint {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CAValidityConstraint.class);

    private Date mDefNotBefore = null;
    private Date mDefNotAfter = null;

    public CAValidityConstraint() {
        super();
    }

    @Override
    public void init(IConfigStore config) throws EProfileException {
        super.init(config);
        X509CertImpl caCert;
        try {
            caCert = getCACert();
        } catch (EBaseException e) {
            throw new EProfileException(e);
        }

        mDefNotBefore = caCert.getNotBefore();
        mDefNotAfter = caCert.getNotAfter();
    }

    /**
     * Validates the request. The request is not modified
     * during the validation.
     */
    @Override
    public void validate(IRequest request, X509CertInfo info)
            throws ERejectException {
        String method = "CAValidityConstraint: validate: ";
        logger.debug(method + "validate start");
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
            logger.error(method + "not before " + e.getMessage(), e);
            throw new ERejectException(CMS.getUserMessage(
                        getLocale(request), "CMS_PROFILE_INVALID_NOT_BEFORE"));
        }
        Date notAfter = null;

        try {
            notAfter = (Date) v.get(CertificateValidity.NOT_AFTER);
        } catch (IOException e) {
            logger.error(method + "not after " + e.getMessage(), e);
            throw new ERejectException(CMS.getUserMessage(
                        getLocale(request), "CMS_PROFILE_INVALID_NOT_AFTER"));
        }

        if (mDefNotBefore != null) {
            logger.debug(method + "notBefore=" + notBefore +
                    " defNotBefore=" + mDefNotBefore);
            if (notBefore.before(mDefNotBefore)) {
                throw new ERejectException(CMS.getUserMessage(
                            getLocale(request), "CMS_PROFILE_INVALID_NOT_BEFORE"));
            }
        }
        logger.debug(method + "notAfter=" + notAfter +
                " defNotAfter=" + mDefNotAfter);
        if (notAfter.after(mDefNotAfter)) {
            throw new ERejectException(CMS.getUserMessage(
                        getLocale(request), "CMS_PROFILE_INVALID_NOT_AFTER"));
        }

        if (notAfter.getTime() < notBefore.getTime()) {
            logger.error(method + "notAfter (" + notAfter + ") < notBefore (" + notBefore + ")");
            throw new ERejectException(CMS.getUserMessage(getLocale(request),
                        "CMS_PROFILE_NOT_AFTER_BEFORE_NOT_BEFORE"));
        }

        logger.debug(method + "validate end");
    }

    @Override
    public String getText(Locale locale) {
        String params[] = {
                mDefNotBefore.toString(),
                mDefNotAfter.toString()
            };

        return CMS.getUserMessage(locale,
                "CMS_PROFILE_CONSTRAINT_CA_VALIDITY_CONSTRAINT_TEXT",
                params);
    }

    @Override
    public boolean isApplicable(PolicyDefault def) {
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
