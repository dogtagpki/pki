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
package com.netscape.cms.profile.input;

import java.util.Enumeration;
import java.util.Locale;
import java.util.Vector;

import netscape.security.x509.CertificateSubjectName;
import netscape.security.x509.X500Name;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.profile.IProfileContext;
import com.netscape.certsrv.profile.IProfileInput;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.profile.common.EnrollProfile;

/**
 * This plugin accepts subject DN from end user.
 */
public class SubjectDNInput extends EnrollInput implements IProfileInput {

    public static final String VAL_SUBJECT = "subject";

    public SubjectDNInput() {
    }

    /**
     * Initializes this default policy.
     */
    public void init(IProfile profile, IConfigStore config)
            throws EProfileException {
        super.init(profile, config);
    }

    /**
     * Retrieves the localizable name of this policy.
     */
    public String getName(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_INPUT_SUBJECT_NAME_NAME");
    }

    /**
     * Retrieves the localizable description of this policy.
     */
    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_INPUT_SUBJECT_NAME_TEXT");
    }

    public String getConfig(String name) {
        String config = super.getConfig(name);
        if (config == null || config.equals(""))
            return "true";
        return config;
    }

    /**
     * Returns selected value names based on the configuration.
     */
    public Enumeration<String> getValueNames() {
        Vector<String> v = new Vector<String>();
        v.addElement(VAL_SUBJECT);
        return v.elements();
    }

    /**
     * Populates the request with this policy default.
     */
    public void populate(IProfileContext ctx, IRequest request)
            throws EProfileException {
        X509CertInfo info =
                request.getExtDataInCertInfo(EnrollProfile.REQUEST_CERTINFO);
        String subjectName = "";

        subjectName = ctx.get(VAL_SUBJECT);
        if (subjectName.equals("")) {
            throw new EProfileException(
                    CMS.getUserMessage(getLocale(request),
                            "CMS_PROFILE_SUBJECT_NAME_NOT_FOUND"));
        }
        X500Name name = null;

        try {
            name = new X500Name(subjectName);
        } catch (Exception e) {
            throw new EProfileException(
                    CMS.getUserMessage(getLocale(request),
                            "CMS_PROFILE_INVALID_SUBJECT_NAME", subjectName));
        }
        parseSubjectName(name, info, request);
        request.setExtData(EnrollProfile.REQUEST_CERTINFO, info);
    }

    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        return null;
    }

    /**
     * Retrieves the descriptor of the given value
     * parameter by name.
     */
    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(VAL_SUBJECT)) {
            return new Descriptor(IDescriptor.STRING, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_SUBJECT_NAME"));
        }
        return null;
    }

    protected void parseSubjectName(X500Name subj, X509CertInfo info, IRequest req)
            throws EProfileException {
        try {
            req.setExtData(EnrollProfile.REQUEST_SUBJECT_NAME,
                    new CertificateSubjectName(subj));
        } catch (Exception e) {
            CMS.debug("SubjectNameInput: parseSubject Name " +
                    e.toString());
        }
    }
}
