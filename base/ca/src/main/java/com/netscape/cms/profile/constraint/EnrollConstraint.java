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

import java.util.Enumeration;
import java.util.Locale;

import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.x509.CertificateExtensions;
import org.mozilla.jss.netscape.security.x509.Extension;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.profile.ERejectException;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.usrgrp.Certificates;
import com.netscape.certsrv.usrgrp.EUsrGrpException;
import com.netscape.cms.profile.common.EnrollProfile;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.usrgrp.ExactMatchCertUserLocator;
import com.netscape.cmscore.usrgrp.UGSubsystem;
import com.netscape.cmscore.usrgrp.User;

import netscape.ldap.LDAPException;

/**
 * This class implements the generic enrollment constraint.
 *
 * @version $Revision$, $Date$
 */
public abstract class EnrollConstraint extends PolicyConstraint {

    public static final String CONFIG_PARAMS = "params";

    public EnrollConstraint() {
    }

    public IDescriptor getValueDescriptor(Locale locale, String name) {
        return null;
    }

    public Locale getLocale(Request request) {
        Locale locale = null;
        String language = request.getExtDataInString(
                EnrollProfile.REQUEST_LOCALE);
        if (language != null) {
            locale = new Locale(language);
        }
        return locale;
    }

    @Override
    public void setConfig(String name, String value)
            throws EPropertyException {
        if (mConfig.getSubStore(CONFIG_PARAMS) == null) {
            //
        } else {
            mConfig.getSubStore(CONFIG_PARAMS).putString(name, value);
        }
    }

    @Override
    public String getConfig(String name) {
        return getConfig(name, "");
    }

    /**
     * Get constraint parameter in profile configuration.
     *
     * @param name parameter name
     * @param defval default value if parameter does not exist
     * @return parameter value if exists, defval if does not exist, or null if error occured
     */
    public String getConfig(String name, String defval) {

        if (mConfig == null) {
            logger.warn("Missing profile constraint configuration");
            return null;
        }

        ConfigStore params = mConfig.getSubStore(CONFIG_PARAMS, ConfigStore.class);
        if (params == null) {
            logger.warn("Error: Missing constraint parameters");
            return null;
        }

        try {
            return params.getString(name, defval);
        } catch (EBaseException e) {
            logger.warn("Unable to get profile constraint " + name + " parameter: " + e.getMessage(), e);
            return null;
        }
    }

    /**
     * Validates the request. The request is not modified
     * during the validation.
     *
     * @param request enrollment request
     * @param info certificate template
     * @exception ERejectException request is rejected due
     *                to violation of constraint
     */
    public abstract void validate(Request request, X509CertInfo info)
            throws ERejectException;

    /**
     * Validates the request. The request is not modified
     * during the validation.
     *
     * The current implementation of this method calls
     * into the subclass's validate(request, info)
     * method for validation checking.
     *
     * @param request request
     * @exception ERejectException request is rejected due
     *                to violation of constraint
     */
    @Override
    public void validate(Request request)
            throws ERejectException {
        String name = getClass().getName();

        name = name.substring(name.lastIndexOf('.') + 1);
        logger.debug(name + ": validate start");
        X509CertInfo info =
                request.getExtDataInCertInfo(Request.REQUEST_CERTINFO);

        validate(request, info);

        request.setExtData(Request.REQUEST_CERTINFO, info);
        logger.debug(name + ": validate end");
    }

    @Override
    public String getText(Locale locale) {
        return "Enroll Constraint";
    }

    protected Extension getExtension(String name, X509CertInfo info) {
        CertificateExtensions exts = null;

        try {
            exts = (CertificateExtensions)
                    info.get(X509CertInfo.EXTENSIONS);
        } catch (Exception e) {
            logger.warn("EnrollConstraint: getExtension " + e.getMessage(), e);
        }
        if (exts == null)
            return null;
        Enumeration<Extension> e = exts.getAttributes();

        while (e.hasMoreElements()) {
            Extension ext = e.nextElement();

            if (ext.getExtensionId().toString().equals(name)) {
                return ext;
            }
        }
        return null;
    }

    protected boolean isOptional(String value) {
        return value.equals("") || value.equals("-");
    }

    protected boolean getBoolean(String value) {
        return Boolean.valueOf(value).booleanValue();
    }

    protected int getInt(String value) {
        return Integer.valueOf(value).intValue();
    }

    protected boolean getConfigBoolean(String value) {
        return getBoolean(getConfig(value));
    }

    protected int getConfigInt(String value) {
        return getInt(getConfig(value));
    }

    /**
     * Check if a certificate belongs to a Certificate Manager Agent.
     * This is used by RA-related constraints to determine authorization level.
     *
     * @param cert The certificate to check
     * @return true if the certificate owner is a member of "Certificate Manager Agents" group
     */
    protected boolean isAgentCert(X509CertImpl cert) {
        ExactMatchCertUserLocator mcu = new ExactMatchCertUserLocator();
        CAEngine engine = CAEngine.getInstance();
        mcu.setCMSEngine(engine);
        X509CertImpl[] certList = new X509CertImpl[1];
        certList[0] = cert;
        Certificates ci = new Certificates(certList);
        User user;
        try {
            user = mcu.locateUser(ci);
        } catch (EUsrGrpException | LDAPException e) {
            logger.debug("EnrollConstraint: isAgentCert - could not locate user", e);
            return false;
        }
        UGSubsystem uggroup = engine.getUGSubsystem();
        if (uggroup.isMemberOf(user, "Certificate Manager Agents")) {
            logger.debug("EnrollConstraint: User {} is a Certificate Manager Agent", user.getUserID());
            return true;
        }
        return false;
    }
}
