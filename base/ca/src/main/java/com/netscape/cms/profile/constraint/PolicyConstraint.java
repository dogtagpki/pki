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

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.ERejectException;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IConfigTemplate;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.cms.profile.def.PolicyDefault;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.request.Request;

/**
 * This represents a constraint policy. A constraint policy
 * validates if the given request conforms to the set
 * rules.
 */
public abstract class PolicyConstraint implements IConfigTemplate {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PolicyConstraint.class);

    public static final String CONFIG_NAME = "name";

    protected ConfigStore mConfig;
    protected Vector<String> mConfigNames = new Vector<>();

    /**
     * Initializes this constraint policy.
     *
     * @param config configuration store for this constraint
     * @exception EProfileException failed to initialize
     */
    public void init(ConfigStore config) throws EProfileException {
        mConfig = config;
    }

    /**
     * Returns the corresponding configuration store
     * of this constraint policy.
     *
     * @return config store of this constraint
     */
    public ConfigStore getConfigStore() {
        return mConfig;
    }

    @Override
    public Enumeration<String> getConfigNames() {
        return mConfigNames.elements();
    }

    public void addConfigName(String name) {
        mConfigNames.addElement(name);
    }

    @Override
    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        return null;
    }

    @Override
    public String getConfig(String name) {
        return null;
    }

    @Override
    public void setConfig(String name, String value)
            throws EPropertyException {
    }

    public String getDefaultConfig(String name) {
        return null;
    }

    /**
     * Validates the request. The request is not modified
     * during the validation.
     *
     * @param request request to be validated
     * @exception ERejectException reject the given request
     */
    public void validate(Request request) throws ERejectException {
    }

    /**
     * Returns localized description of this constraint.
     *
     * @param locale locale of the end-user
     * @return localized description of this constraint
     */
    public String getText(Locale locale) {
        return null;
    }

    /**
     * Returns localized name of this constraint.
     *
     * @param locale locale of the end-user
     * @return localized name of this constraint
     */
    public String getName(Locale locale) {
        try {
            return mConfig.getString(CONFIG_NAME);
        } catch (EBaseException e) {
            return null;
        }
    }

    /**
     * Checks if this constraint is applicable to the
     * given default policy.
     *
     * @param def default policy to be checked
     * @return true if this constraint can be applied to
     *         the given default policy
     */
    public boolean isApplicable(PolicyDefault def) {
        return true;
    }
}
