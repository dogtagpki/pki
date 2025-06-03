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

import org.mozilla.jss.netscape.security.x509.CertificateSubjectName;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.request.Request;

/**
 * This class implements an enrollment default policy
 * that populates a user-supplied subject name
 * into the certificate template.
 *
 * @version $Revision$, $Date$
 */
public class UserSubjectNameDefault extends EnrollDefault {

    public static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(UserSubjectNameDefault.class);

    private static final String CMS_INVALID_PROPERTY = "CMS_INVALID_PROPERTY";
    public static final String VAL_NAME = "name";
    public static final String CONFIG_USE_SYS_ENCODING = "useSysEncoding";

    public UserSubjectNameDefault() {
        super();
        addConfigName(CONFIG_USE_SYS_ENCODING);
        addValueName(VAL_NAME);
    }

    @Override
    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        if (name.equals(CONFIG_USE_SYS_ENCODING)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_CONFIG_USE_SYS_ENCODING"));
        }
        return null;
    }

    @Override
    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(VAL_NAME)) {
            return new Descriptor(IDescriptor.STRING, null, null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_SUBJECT_NAME"));
        }
        return null;
    }

    private X500Name getX500Name(X509CertInfo info, String value) {
            String method = "UserSubjectNameDefault: getX500Name: ";
            X500Name x500name = null;
            /*
             * useSysEencoding default is false
             * To change that, add the following in the affected profile:
             * policyset.<policy set>.<#>.default.params.useSysEncoding=true
             */
            boolean useSysEncoding = getConfigBoolean(CONFIG_USE_SYS_ENCODING);
            logger.debug("{} use system encoding: {}", method, useSysEncoding);

            try {
                if (value != null)
                    x500name = new X500Name(value);

                // oldName is what comes with the CSR
                CertificateSubjectName oldName = info.getSubjectObj();

                if (oldName == null) {
                    logger.debug("{} subjectDN does not exist in CSR.", method);
                } else {
                    logger.debug("{} subjectDN exists in CSR: {}", method, oldName);
                }

                if (!useSysEncoding && oldName != null) {
                    /* If the canonical string representations of
                     * existing Subject DN and new DN are equal,
                     * keep the old name so that the attribute
                     * encodings are preserved. */
                    X500Name oldX500name = oldName.getX500Name();
                    if (x500name == null) {
                        logger.debug("{} new Subject DN is null; retaining current value: {}",
                                method, oldX500name);
                        x500name = oldX500name;
                    } else if (x500name.toString().equals(oldX500name.toString())) {
                        logger.debug("{} new Subject DN has same string representation as current value;"
                                + " retaining current value: {}", method, oldX500name);
                        x500name = oldX500name;
                    } else {
                        logger.debug("{} replacing current value `{}` with new value `{}`",
                                method, oldX500name, x500name);
                    }
                }
            } catch (IOException e) {
                logger.warn(method + e.getMessage(), e);
                // failed to build x500 name
            }

            logger.debug("{} subject: {}", method, x500name);

            return x500name;
    }

    @Override
    public void setValue(String name, Locale locale,
            X509CertInfo info, String value)
            throws EPropertyException {
        String method = "UserSubjectNameDefault: setValue: ";
        if (name == null) {
            logger.error("{} name = null", method);
            throw new EPropertyException(CMS.getUserMessage(
                        locale, CMS_INVALID_PROPERTY, name));
        }
        logger.debug("{} name = {}", method, name);
        logger.debug("{} value = {}", method, value);

        if (name.equals(VAL_NAME)) {
            X500Name x500name = getX500Name(info, value);
            logger.debug("{} setting name={}", method, x500name);
            try {
                info.set(X509CertInfo.SUBJECT,
                        new CertificateSubjectName(x500name));
            } catch (Exception e) {
                // failed to insert subject name
                logger.error(method + e.getMessage(), e);
                throw new EPropertyException(CMS.getUserMessage(
                            locale, CMS_INVALID_PROPERTY, name));
            }
        } else {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, CMS_INVALID_PROPERTY, name));
        }
    }

    @Override
    public String getValue(String name, Locale locale,
            X509CertInfo info)
            throws EPropertyException {
        if (name == null) {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, CMS_INVALID_PROPERTY, name));
        }
        if (name.equals(VAL_NAME)) {
            CertificateSubjectName sn = null;

            try {
                sn = (CertificateSubjectName)
                        info.get(X509CertInfo.SUBJECT);
                return sn.toString();
            } catch (Exception e) {
                // nothing
            }
            throw new EPropertyException(CMS.getUserMessage(
                        locale, CMS_INVALID_PROPERTY, name));
        }
        throw new EPropertyException(CMS.getUserMessage(
                    locale, CMS_INVALID_PROPERTY, name));
    }

    @Override
    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_DEF_USER_SUBJECT_NAME");
    }

    /**
     * Populates the request with this policy default.
     */
    @Override
    public void populate(Request request, X509CertInfo info)
            throws EProfileException {

        // authenticate the subject name and populate it
        // to the certinfo
        CertificateSubjectName reqSbj = request.getExtDataInCertSubjectName(
                    Request.REQUEST_SUBJECT_NAME);
        logger.info("UserSubjectNameDefault: - subject: {}", reqSbj);

        if (reqSbj == null) {
            // failed to retrieve subject name
            logger.error("UserSubjectNameDefault: populate req_sbj is null");
            throw new EProfileException(CMS.getUserMessage(getLocale(request),
                        "CMS_PROFILE_SUBJECT_NAME_NOT_FOUND"));
        }

        try {
            info.set(X509CertInfo.SUBJECT, reqSbj);

            // see if the encoding needs changing
            X500Name x500name = getX500Name(info, reqSbj.toString());
            if (x500name != null) {
                info.set(X509CertInfo.SUBJECT,
                        new CertificateSubjectName(x500name));
            }
        } catch (Exception e) {
            // failed to insert subject name
            throw new EProfileException(e.toString());
        }
    }
}
