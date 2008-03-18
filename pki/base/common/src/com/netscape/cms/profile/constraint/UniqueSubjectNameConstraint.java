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
import com.netscape.certsrv.ca.*;
import com.netscape.certsrv.authority.*;
import com.netscape.certsrv.dbs.certdb.*;
import com.netscape.cms.profile.common.*;
import com.netscape.cms.profile.def.*;
import netscape.security.x509.*;

/**
 * This class implements the unique subject name constraint.
 * It checks if the subject name in the certificate is
 * unique in the internal database, ie, no two certificates
 * have the same subject name.
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public class UniqueSubjectNameConstraint extends EnrollConstraint {

    public UniqueSubjectNameConstraint() {
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
     * during the validation.
     */
    public void validate(IRequest request, X509CertInfo info)
        throws ERejectException {
        CMS.debug("UniqueSubjectNameConstraint: validate start");
        CertificateSubjectName sn = null;
        IAuthority authority = (IAuthority)CMS.getSubsystem("ca");
        
        ICertificateRepository certdb = null;
        if (authority != null && authority instanceof ICertificateAuthority) {
            ICertificateAuthority ca = (ICertificateAuthority)authority;
            certdb = ca.getCertificateRepository();
        }
            
        try {
            sn = (CertificateSubjectName) info.get(X509CertInfo.SUBJECT);
        } catch (Exception e) {
            throw new ERejectException(
                    CMS.getUserMessage(getLocale(request), 
                        "CMS_PROFILE_SUBJECT_NAME_NOT_FOUND"));
        }

        String certsubjectname = null;
        if (sn == null)
            throw new ERejectException(
                    CMS.getUserMessage(getLocale(request), 
                        "CMS_PROFILE_SUBJECT_NAME_NOT_FOUND"));
        else {
            certsubjectname = sn.toString();
            String filter = "x509Cert.subject=" + certsubjectname;
            Enumeration sameSubjRecords = null;
            try {
                sameSubjRecords = certdb.findCertRecords(filter);
            } catch (EBaseException e) {
                CMS.debug("UniqueSubjectNameConstraint exception: "+e.toString());
            }
            if (sameSubjRecords != null && sameSubjRecords.hasMoreElements()) {
                throw new ERejectException(
                  CMS.getUserMessage(getLocale(request),
                  "CMS_PROFILE_SUBJECT_NAME_NOT_UNIQUE",
                  certsubjectname));
            }
        }
    }

    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, 
                "CMS_PROFILE_CONSTRAINT_UNIQUE_SUBJECT_NAME_TEXT");
    }

    public boolean isApplicable(IPolicyDefault def) {
        if (def instanceof NoDefault)
            return true;
        if (def instanceof SubjectNameDefault)
            return true;
        if (def instanceof UserSubjectNameDefault)
            return true;
        return false;
    }
}
