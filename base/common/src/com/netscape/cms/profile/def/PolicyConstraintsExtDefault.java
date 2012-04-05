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

import netscape.security.x509.PKIXExtensions;
import netscape.security.x509.PolicyConstraintsExtension;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;

/**
 * This class implements an enrollment default policy
 * that populates a policy constraints extension
 * into the certificate template.
 *
 * @version $Revision$, $Date$
 */
public class PolicyConstraintsExtDefault extends EnrollExtDefault {

    public static final String CONFIG_CRITICAL = "policyConstraintsCritical";
    public static final String CONFIG_REQ_EXPLICIT_POLICY = "policyConstraintsReqExplicitPolicy";
    public static final String CONFIG_INHIBIT_POLICY_MAPPING = "policyConstraintsInhibitPolicyMapping";

    public static final String VAL_CRITICAL = "policyConstraintsCritical";
    public static final String VAL_REQ_EXPLICIT_POLICY = "policyConstraintsReqExplicitPolicy";
    public static final String VAL_INHIBIT_POLICY_MAPPING = "policyConstraintsInhibitPolicyMapping";

    public PolicyConstraintsExtDefault() {
        super();
        addValueName(VAL_CRITICAL);
        addValueName(VAL_REQ_EXPLICIT_POLICY);
        addValueName(VAL_INHIBIT_POLICY_MAPPING);

        addConfigName(CONFIG_CRITICAL);
        addConfigName(CONFIG_REQ_EXPLICIT_POLICY);
        addConfigName(CONFIG_INHIBIT_POLICY_MAPPING);
    }

    public void init(IProfile profile, IConfigStore config)
            throws EProfileException {
        super.init(profile, config);
    }

    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        if (name.equals(CONFIG_CRITICAL)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_CRITICAL"));
        } else if (name.equals(CONFIG_REQ_EXPLICIT_POLICY)) {
            return new Descriptor(IDescriptor.INTEGER, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_REQUIRED_EXPLICIT_POLICY"));
        } else if (name.equals(CONFIG_INHIBIT_POLICY_MAPPING)) {
            return new Descriptor(IDescriptor.INTEGER, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_INHIBIT_POLICY_MAPPING"));
        }
        return null;
    }

    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(VAL_CRITICAL)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_CRITICAL"));
        } else if (name.equals(VAL_REQ_EXPLICIT_POLICY)) {
            return new Descriptor(IDescriptor.INTEGER, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_REQUIRED_EXPLICIT_POLICY"));
        } else if (name.equals(VAL_INHIBIT_POLICY_MAPPING)) {
            return new Descriptor(IDescriptor.INTEGER, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_INHIBIT_POLICY_MAPPING"));
        }
        return null;
    }

    public void setValue(String name, Locale locale,
            X509CertInfo info, String value)
            throws EPropertyException {
        try {
            PolicyConstraintsExtension ext = null;

            if (name == null) {
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
            }

            ext = (PolicyConstraintsExtension)
                        getExtension(PKIXExtensions.PolicyConstraints_Id.toString(),
                                info);

            if (ext == null) {
                populate(null, info);
            }

            if (name.equals(VAL_CRITICAL)) {
                ext = (PolicyConstraintsExtension)
                        getExtension(PKIXExtensions.PolicyConstraints_Id.toString(),
                                info);
                boolean val = Boolean.valueOf(value).booleanValue();

                if (ext == null) {
                    return;
                }
                ext.setCritical(val);
            } else if (name.equals(VAL_REQ_EXPLICIT_POLICY)) {
                ext = (PolicyConstraintsExtension)
                        getExtension(PKIXExtensions.PolicyConstraints_Id.toString(),
                                info);

                if (ext == null) {
                    return;
                }
                Integer num = new Integer(value);

                ext.set(PolicyConstraintsExtension.REQUIRE, num);
            } else if (name.equals(VAL_INHIBIT_POLICY_MAPPING)) {
                ext = (PolicyConstraintsExtension)
                        getExtension(PKIXExtensions.PolicyConstraints_Id.toString(),
                                info);

                if (ext == null) {
                    return;
                }
                Integer num = new Integer(value);

                ext.set(PolicyConstraintsExtension.INHIBIT, num);
            } else {
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
            }

            replaceExtension(PKIXExtensions.PolicyConstraints_Id.toString(),
                    ext, info);
        } catch (EProfileException e) {
            CMS.debug("PolicyConstraintsExtDefault: setValue " + e.toString());
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        } catch (IOException e) {
            CMS.debug("PolicyConstraintsExtDefault: setValue " + e.toString());
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
    }

    public String getValue(String name, Locale locale,
            X509CertInfo info)
            throws EPropertyException {
        PolicyConstraintsExtension ext = null;

        if (name == null) {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }

        ext = (PolicyConstraintsExtension)
                    getExtension(PKIXExtensions.PolicyConstraints_Id.toString(),
                            info);
        if (ext == null) {

            try {
                populate(null, info);

            } catch (EProfileException e) {
                throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
            }

        }

        if (name.equals(VAL_CRITICAL)) {
            ext = (PolicyConstraintsExtension)
                    getExtension(PKIXExtensions.PolicyConstraints_Id.toString(),
                            info);

            if (ext == null) {
                return null;
            }
            if (ext.isCritical()) {
                return "true";
            } else {
                return "false";
            }
        } else if (name.equals(VAL_REQ_EXPLICIT_POLICY)) {
            ext = (PolicyConstraintsExtension)
                    getExtension(PKIXExtensions.PolicyConstraints_Id.toString(),
                            info);

            if (ext == null)
                return "";

            int num = ext.getRequireExplicitMapping();

            return "" + num;
        } else if (name.equals(VAL_INHIBIT_POLICY_MAPPING)) {
            ext = (PolicyConstraintsExtension)
                    getExtension(PKIXExtensions.PolicyConstraints_Id.toString(),
                            info);

            if (ext == null)
                return "";

            int num = ext.getInhibitPolicyMapping();

            return "" + num;
        } else {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
    }

    public String getText(Locale locale) {
        String params[] = {
                getConfig(CONFIG_CRITICAL),
                getConfig(CONFIG_REQ_EXPLICIT_POLICY),
                getConfig(CONFIG_INHIBIT_POLICY_MAPPING)
            };

        return CMS.getUserMessage(locale, "CMS_PROFILE_DEF_POLICY_CONSTRAINTS_EXT", params);
    }

    /**
     * Populates the request with this policy default.
     */
    public void populate(IRequest request, X509CertInfo info)
            throws EProfileException {
        PolicyConstraintsExtension ext = createExtension();

        if (ext == null)
            return;
        addExtension(PKIXExtensions.PolicyConstraints_Id.toString(),
                ext, info);
    }

    public PolicyConstraintsExtension createExtension() {
        PolicyConstraintsExtension ext = null;

        try {
            boolean critical = getConfigBoolean(CONFIG_CRITICAL);

            int reqNum = -1;
            int inhibitNum = -1;
            String req = getConfig(CONFIG_REQ_EXPLICIT_POLICY);

            if (req != null && req.length() > 0) {
                reqNum = Integer.parseInt(req);
            }
            String inhibit = getConfig(CONFIG_INHIBIT_POLICY_MAPPING);

            if (inhibit != null && inhibit.length() > 0) {
                inhibitNum = Integer.parseInt(inhibit);
            }
            ext = new PolicyConstraintsExtension(critical, reqNum, inhibitNum);
        } catch (Exception e) {
            CMS.debug("PolicyConstraintsExtDefault: createExtension " +
                    e.toString());
        }

        return ext;
    }
}
