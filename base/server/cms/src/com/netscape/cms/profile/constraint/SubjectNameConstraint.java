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
import java.util.Locale;

import netscape.security.x509.CertificateSubjectName;
import netscape.security.x509.X500Name;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.ERejectException;
import com.netscape.certsrv.profile.IPolicyDefault;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.profile.def.NoDefault;
import com.netscape.cms.profile.def.SubjectNameDefault;
import com.netscape.cms.profile.def.UserSubjectNameDefault;

/**
 * This class implements the subject name constraint.
 * It checks if the subject name in the certificate
 * template satisfies the criteria.
 *
 * @version $Revision$, $Date$
 */
public class SubjectNameConstraint extends EnrollConstraint {

    public static final String CONFIG_PATTERN = "pattern";


    private static final int COMMON_NAME_MAX = 64;
    private static final int LOCALITY_NAME_MAX = 128;
    private static final int STATE_NAME_MAX = 128;
    private static final int ORG_NAME_MAX = 64;
    private static final int ORG_UNIT_NAME_MAX = 64;
    private static final int EMAIL_NAME_MAX = 255;
    private static final int COUNTRY_NAME_MAX = 3;
    private static final int UID_NAME_MAX = 64;

    public SubjectNameConstraint() {
        // configuration names
        addConfigName(CONFIG_PATTERN);
    }

    public void init(IProfile profile, IConfigStore config)
            throws EProfileException {
        super.init(profile, config);
    }

    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        if (name.equals(CONFIG_PATTERN)) {
            return new Descriptor(IDescriptor.STRING,
                    null, null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_SUBJECT_NAME_PATTERN"));
        } else {
            return null;
        }
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
        CMS.debug("SubjectNameConstraint: validate start");
        CertificateSubjectName sn = null;

        try {
            sn = (CertificateSubjectName) info.get(X509CertInfo.SUBJECT);
            CMS.debug("SubjectNameConstraint: validate cert subject =" +
                         sn.toString());
        } catch (Exception e) {
            throw new ERejectException(
                    CMS.getUserMessage(getLocale(request),
                            "CMS_PROFILE_SUBJECT_NAME_NOT_FOUND"));
        }
        X500Name sn500 = null;

        try {
            sn500 = (X500Name) sn.get(CertificateSubjectName.DN_NAME);
        } catch (IOException e) {
            throw new ERejectException(
                    CMS.getUserMessage(getLocale(request),
                            "CMS_PROFILE_SUBJECT_NAME_NOT_FOUND"));
        }
        if (sn500 == null) {
            CMS.debug("SubjectNameConstraint: validate() - sn500 is null");
            throw new ERejectException(
                    CMS.getUserMessage(getLocale(request),
                            "CMS_PROFILE_SUBJECT_NAME_NOT_FOUND"));
        } else {
            CMS.debug("SubjectNameConstraint: validate() - sn500 " +
                    CertificateSubjectName.DN_NAME + " = " +
                    sn500.toString());
        }
        if (!sn500.toString().matches(getConfig(CONFIG_PATTERN))) {
            CMS.debug("SubjectNameConstraint: validate() - sn500 not matching pattern " + getConfig(CONFIG_PATTERN));
            throw new ERejectException(
                    CMS.getUserMessage(getLocale(request),
                            "CMS_PROFILE_SUBJECT_NAME_NOT_MATCHED",
                            sn500.toString()));
        }

        String incorrectFields = " [ Invalid fields: ";
        String country = null;
        boolean fieldError = false;

        String commonName = null;
        try {
            commonName = sn500.getCommonName();
        } catch (Exception e) {
        }
        if ( commonName != null && commonName.length() > COMMON_NAME_MAX ) {
            fieldError = true;
            incorrectFields += " Common Name "; 

        }

        try { 
             country =  sn500.getCountry();
        } catch (Exception e) {
        }

        if ( country != null && country.length() > COUNTRY_NAME_MAX ) {
            fieldError = true;
            incorrectFields += " , Country ";
        }

        String ou = null ;
        try {
            ou = sn500.getOrganizationalUnit();
        } catch (Exception e) {
        }

        if ( ou != null && ou.length() > ORG_UNIT_NAME_MAX) {
            fieldError = true;
            incorrectFields += " , Org Unit ";
        }

        String o = null; 
        try {
            o = sn500.getOrganization();
        } catch (Exception e) {
        }

        if ( o != null && o.length() > ORG_NAME_MAX) {
            fieldError = true;
            incorrectFields += " , Org ";
        }

        String locality = null;
        try {
            locality =  sn500.getLocality();
        } catch (Exception e) {
        }

        if ( locality != null && locality.length() > LOCALITY_NAME_MAX ) {
            fieldError = true;
            incorrectFields += " , Locality ";
        }

        String state =  null; 
        try {
            state = sn500.getState();
        } catch (Exception e) {
        }

        if ( state != null && state.length() > STATE_NAME_MAX ) {
            fieldError = true;
            incorrectFields += " , State "; 
        }

        String email =  null; 
        try {
            email = sn500.getEmail();
        } catch (Exception e) {
        }

        if ( email != null && email.length() > EMAIL_NAME_MAX ) {
            fieldError = true;
            incorrectFields += " , Email ";
        }

        String UID =  null;
        try {
            UID = sn500.getUserID();
        } catch (Exception e) {
        }
        
        if ( UID != null && UID.length() > UID_NAME_MAX) {
             fieldError = true;
             incorrectFields += " , UID";
        }   

        if ( fieldError == true ) {
            throw new ERejectException(
                    CMS.getUserMessage(getLocale(request),
                        "CMS_PROFILE_INVALID_SUBJECT_NAME",sn500.toString() + incorrectFields + " ] "));

        }
    }

    public String getText(Locale locale) {
        return CMS.getUserMessage(locale,
                "CMS_PROFILE_CONSTRAINT_SUBJECT_NAME_TEXT",
                getConfig(CONFIG_PATTERN));
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
