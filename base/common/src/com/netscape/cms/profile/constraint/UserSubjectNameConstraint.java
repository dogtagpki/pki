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


import java.util.*;
import java.io.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.profile.*;
import com.netscape.certsrv.request.*;
import com.netscape.certsrv.property.*;
import com.netscape.certsrv.apps.*;
import com.netscape.cms.profile.common.*;
import com.netscape.cms.profile.def.*;

import netscape.security.x509.*;

/**
 * This class implements the user subject name constraint.
 * It copies user encoded subject name into the certificate template.
 *
 * @version $Revision$, $Date$
 */
public class UserSubjectNameConstraint extends EnrollConstraint {

    public UserSubjectNameConstraint() {
    }

    public void init(IProfile profile, IConfigStore config)
        throws EProfileException {
        super.init(profile, config);
    }

    public IDescriptor getConfigDescriptor(Locale locale, String name) { 
        return null;
    }

    public String getDefaultConfig(String name) {
        return null;
    }

    /**
     * Validates the request. The request is not modified
     * during the validation. User encoded subject name
     * is copied into the certificate template.
     */
    public void validate(IRequest request, X509CertInfo info)
            throws ERejectException {
        CMS.debug("UserSubjectNameConstraint: validate start");
        CertificateSubjectName requestSN = null;

        try {
            requestSN = request.getExtDataInCertSubjectName(
                                IEnrollProfile.REQUEST_SUBJECT_NAME);
            info.set(X509CertInfo.SUBJECT, requestSN);
            CMS.debug("UserSubjectNameConstraint: validate user subject ="+
                      requestSN.toString());
        } catch (Exception e) {
            throw new ERejectException(
                    CMS.getUserMessage(getLocale(request),
                        "CMS_PROFILE_SUBJECT_NAME_NOT_FOUND"));
        }
    }

    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, 
                "CMS_PROFILE_CONSTRAINT_USER_SUBJECT_NAME_TEXT");
    }

    public boolean isApplicable(IPolicyDefault def) {
        if (def instanceof UserSubjectNameDefault)
            return true;
        return false;
    }
}
