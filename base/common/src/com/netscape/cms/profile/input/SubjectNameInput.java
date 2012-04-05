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
 * This class implements the subject name input
 * that populates text fields to the enrollment
 * page so that distinguished name parameters
 * can be collected from the user.
 * <p>
 * The collected parameters could be used for fomulating the subject name in the certificate.
 * <p>
 *
 * @version $Revision$, $Date$
 */
public class SubjectNameInput extends EnrollInput implements IProfileInput {

    public static final String CONFIG_UID = "sn_uid";
    public static final String CONFIG_EMAIL = "sn_e";
    public static final String CONFIG_CN = "sn_cn";
    public static final String CONFIG_OU3 = "sn_ou3";
    public static final String CONFIG_OU2 = "sn_ou2";
    public static final String CONFIG_OU1 = "sn_ou1";
    public static final String CONFIG_OU = "sn_ou";
    public static final String CONFIG_O = "sn_o";
    public static final String CONFIG_C = "sn_c";

    public static final String VAL_UID = "sn_uid";
    public static final String VAL_EMAIL = "sn_e";
    public static final String VAL_CN = "sn_cn";
    public static final String VAL_OU3 = "sn_ou3";
    public static final String VAL_OU2 = "sn_ou2";
    public static final String VAL_OU1 = "sn_ou1";
    public static final String VAL_OU = "sn_ou";
    public static final String VAL_O = "sn_o";
    public static final String VAL_C = "sn_c";

    public SubjectNameInput() {
        addConfigName(CONFIG_UID);
        addConfigName(CONFIG_EMAIL);
        addConfigName(CONFIG_CN);
        addConfigName(CONFIG_OU3);
        addConfigName(CONFIG_OU2);
        addConfigName(CONFIG_OU1);
        addConfigName(CONFIG_OU);
        addConfigName(CONFIG_O);
        addConfigName(CONFIG_C);
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
        String c_uid = getConfig(CONFIG_UID);
        if (c_uid == null || c_uid.equals("")) {
            v.addElement(VAL_UID); // default case
        } else {
            if (c_uid.equals("true")) {
                v.addElement(VAL_UID);
            }
        }
        String c_email = getConfig(CONFIG_EMAIL);
        if (c_email == null || c_email.equals("")) {
            v.addElement(VAL_EMAIL);
        } else {
            if (c_email.equals("true")) {
                v.addElement(VAL_EMAIL);
            }
        }
        String c_cn = getConfig(CONFIG_CN);
        if (c_cn == null || c_cn.equals("")) {
            v.addElement(VAL_CN);
        } else {
            if (c_cn.equals("true")) {
                v.addElement(VAL_CN);
            }
        }
        String c_ou3 = getConfig(CONFIG_OU3);
        if (c_ou3 == null || c_ou3.equals("")) {
            v.addElement(VAL_OU3);
        } else {
            if (c_ou3.equals("true")) {
                v.addElement(VAL_OU3);
            }
        }
        String c_ou2 = getConfig(CONFIG_OU2);
        if (c_ou2 == null || c_ou2.equals("")) {
            v.addElement(VAL_OU2);
        } else {
            if (c_ou2.equals("true")) {
                v.addElement(VAL_OU2);
            }
        }
        String c_ou1 = getConfig(CONFIG_OU1);
        if (c_ou1 == null || c_ou1.equals("")) {
            v.addElement(VAL_OU1);
        } else {
            if (c_ou1.equals("true")) {
                v.addElement(VAL_OU1);
            }
        }
        String c_ou = getConfig(CONFIG_OU);
        if (c_ou == null || c_ou.equals("")) {
            v.addElement(VAL_OU);
        } else {
            if (c_ou.equals("true")) {
                v.addElement(VAL_OU);
            }
        }
        String c_o = getConfig(CONFIG_O);
        if (c_o == null || c_o.equals("")) {
            v.addElement(VAL_O);
        } else {
            if (c_o.equals("true")) {
                v.addElement(VAL_O);
            }
        }
        String c_c = getConfig(CONFIG_C);
        if (c_c == null || c_c.equals("")) {
            v.addElement(VAL_C);
        } else {
            if (c_c.equals("true")) {
                v.addElement(VAL_C);
            }
        }
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

        String uid = ctx.get(VAL_UID);

        if (uid != null && !uid.equals("")) {
            subjectName += "UID=" + uid;
        }
        String email = ctx.get(VAL_EMAIL);

        if (email != null && !email.equals("")) {
            if (!subjectName.equals("")) {
                subjectName += ",";
            }
            subjectName += "E=" + email;
        }
        String cn = ctx.get(VAL_CN);

        if (cn != null && !cn.equals("")) {
            if (!subjectName.equals("")) {
                subjectName += ",";
            }
            subjectName += "CN=" + cn;
        }
        String ou3 = ctx.get(VAL_OU3);
        if (ou3 != null && !ou3.equals("")) {
            if (!subjectName.equals("")) {
                subjectName += ",";
            }
            subjectName += "OU=" + ou3;
        }
        String ou2 = ctx.get(VAL_OU2);
        if (ou2 != null && !ou2.equals("")) {
            if (!subjectName.equals("")) {
                subjectName += ",";
            }
            subjectName += "OU=" + ou2;
        }
        String ou1 = ctx.get(VAL_OU1);
        if (ou1 != null && !ou1.equals("")) {
            if (!subjectName.equals("")) {
                subjectName += ",";
            }
            subjectName += "OU=" + ou1;
        }
        String ou = ctx.get(VAL_OU);
        if (ou != null && !ou.equals("")) {
            if (!subjectName.equals("")) {
                subjectName += ",";
            }
            subjectName += "OU=" + ou;
        }
        String o = ctx.get(VAL_O);

        if (o != null && !o.equals("")) {
            if (!subjectName.equals("")) {
                subjectName += ",";
            }
            subjectName += "O=" + o;
        }
        String c = ctx.get(VAL_C);

        if (c != null && !c.equals("")) {
            if (!subjectName.equals("")) {
                subjectName += ",";
            }
            subjectName += "C=" + c;
        }
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
        if (name.equals(CONFIG_UID)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "true",
                    CMS.getUserMessage(locale, "CMS_PROFILE_SN_UID"));
        } else if (name.equals(CONFIG_EMAIL)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "true",
                    CMS.getUserMessage(locale, "CMS_PROFILE_SN_UID"));
        } else if (name.equals(CONFIG_CN)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "true",
                    CMS.getUserMessage(locale, "CMS_PROFILE_SN_CN"));
        } else if (name.equals(CONFIG_OU3)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "true",
                    CMS.getUserMessage(locale, "CMS_PROFILE_SN_OU"));
        } else if (name.equals(CONFIG_OU2)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "true",
                    CMS.getUserMessage(locale, "CMS_PROFILE_SN_OU"));
        } else if (name.equals(CONFIG_OU1)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "true",
                    CMS.getUserMessage(locale, "CMS_PROFILE_SN_OU"));
        } else if (name.equals(CONFIG_OU)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "true",
                    CMS.getUserMessage(locale, "CMS_PROFILE_SN_OU"));
        } else if (name.equals(CONFIG_O)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "true",
                    CMS.getUserMessage(locale, "CMS_PROFILE_SN_O"));
        } else if (name.equals(CONFIG_C)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "true",
                    CMS.getUserMessage(locale, "CMS_PROFILE_SN_C"));
        } else {
            return null;
        }
    }

    /**
     * Retrieves the descriptor of the given value
     * parameter by name.
     */
    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(VAL_UID)) {
            return new Descriptor(IDescriptor.STRING, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_SN_UID"));
        } else if (name.equals(VAL_EMAIL)) {
            return new Descriptor(IDescriptor.STRING, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_SN_EMAIL"));
        } else if (name.equals(VAL_CN)) {
            return new Descriptor(IDescriptor.STRING, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_SN_CN"));
        } else if (name.equals(VAL_OU3)) {
            return new Descriptor(IDescriptor.STRING, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_SN_OU") + " 3");
        } else if (name.equals(VAL_OU2)) {
            return new Descriptor(IDescriptor.STRING, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_SN_OU") + " 2");
        } else if (name.equals(VAL_OU1)) {
            return new Descriptor(IDescriptor.STRING, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_SN_OU") + " 1");
        } else if (name.equals(VAL_OU)) {
            return new Descriptor(IDescriptor.STRING, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_SN_OU"));
        } else if (name.equals(VAL_O)) {
            return new Descriptor(IDescriptor.STRING, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_SN_O"));
        } else if (name.equals(VAL_C)) {
            return new Descriptor(IDescriptor.STRING, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_SN_C"));
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
