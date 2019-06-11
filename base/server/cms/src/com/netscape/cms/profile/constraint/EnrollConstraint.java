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
import java.util.Vector;

import org.mozilla.jss.netscape.security.x509.CertificateExtensions;
import org.mozilla.jss.netscape.security.x509.Extension;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.ERejectException;
import com.netscape.certsrv.profile.IPolicyConstraint;
import com.netscape.certsrv.profile.IPolicyDefault;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.profile.common.EnrollProfile;

/**
 * This class implements the generic enrollment constraint.
 *
 * @version $Revision$, $Date$
 */
public abstract class EnrollConstraint implements IPolicyConstraint {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(EnrollConstraint.class);

    public static final String CONFIG_NAME = "name";
    public static final String CONFIG_PARAMS = "params";

    protected IConfigStore mConfig = null;
    protected Vector<String> mConfigNames = new Vector<String>();

    public EnrollConstraint() {
    }

    public Enumeration<String> getConfigNames() {
        return mConfigNames.elements();
    }

    public void addConfigName(String name) {
        mConfigNames.addElement(name);
    }

    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        return null;
    }

    public IDescriptor getValueDescriptor(Locale locale, String name) {
        return null;
    }

    public Locale getLocale(IRequest request) {
        Locale locale = null;
        String language = request.getExtDataInString(
                EnrollProfile.REQUEST_LOCALE);
        if (language != null) {
            locale = new Locale(language);
        }
        return locale;
    }

    public void setConfig(String name, String value)
            throws EPropertyException {
        if (mConfig.getSubStore(CONFIG_PARAMS) == null) {
            //
        } else {
            mConfig.getSubStore(CONFIG_PARAMS).putString(name, value);
        }
    }

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
            logger.warn("Error: Missing profile configuration");
            return null;
        }

        IConfigStore params = mConfig.getSubStore(CONFIG_PARAMS);
        if (params == null) {
            logger.warn("Error: Missing constraint parameters");
            return null;
        }

        try {
            return params.getString(name, defval);

        } catch (EBaseException e) {
            logger.warn("EnrollConstraint: " + e.getMessage(), e);
            return null;
        }
    }

    public void init(IProfile profile, IConfigStore config)
            throws EProfileException {
        mConfig = config;
    }

    public IConfigStore getConfigStore() {
        return mConfig;
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
    public abstract void validate(IRequest request, X509CertInfo info)
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
    public void validate(IRequest request)
            throws ERejectException {
        String name = getClass().getName();

        name = name.substring(name.lastIndexOf('.') + 1);
        logger.debug(name + ": validate start");
        X509CertInfo info =
                request.getExtDataInCertInfo(EnrollProfile.REQUEST_CERTINFO);

        validate(request, info);

        request.setExtData(EnrollProfile.REQUEST_CERTINFO, info);
        logger.debug(name + ": validate end");
    }

    public String getText(Locale locale) {
        return "Enroll Constraint";
    }

    public String getName(Locale locale) {
        try {
            return mConfig.getString(CONFIG_NAME);
        } catch (EBaseException e) {
            return null;
        }
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
        if (value.equals("") || value.equals("-"))
            return true;
        else
            return false;
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

    public boolean isApplicable(IPolicyDefault def) {
        return true;
    }
}
