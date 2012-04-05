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
import java.util.Enumeration;
import java.util.Locale;
import java.util.Vector;

import netscape.security.util.ObjectIdentifier;
import netscape.security.x509.CertificatePolicyId;
import netscape.security.x509.CertificatePolicyMap;
import netscape.security.x509.PKIXExtensions;
import netscape.security.x509.PolicyMappingsExtension;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;

/**
 * This class implements an enrollment default policy
 * that populates a policy mappings extension
 * into the certificate template.
 *
 * @version $Revision$, $Date$
 */
public class PolicyMappingsExtDefault extends EnrollExtDefault {

    public static final String CONFIG_CRITICAL = "policyMappingsCritical";
    public static final String CONFIG_NUM_POLICY_MAPPINGS = "policyMappingsNum";
    public static final String CONFIG_ISSUER_DOMAIN_POLICY = "policyMappingsIssuerDomainPolicy_";
    public static final String CONFIG_SUBJECT_DOMAIN_POLICY = "policyMappingsSubjectDomainPolicy_";
    public static final String CONFIG_ENABLE = "policyMappingsEnable_";

    public static final String VAL_CRITICAL = "policyMappingsCritical";
    public static final String VAL_DOMAINS = "policyMappingsDomains";

    private static final String ISSUER_POLICY_ID = "Issuer Policy Id";
    private static final String SUBJECT_POLICY_ID = "Subject Policy Id";
    private static final String POLICY_ID_ENABLE = "Enable";

    private static final int DEF_NUM_MAPPINGS = 1;
    private static final int MAX_NUM_MAPPINGS = 100;

    public PolicyMappingsExtDefault() {
        super();
    }

    protected int getNumMappings() {
        int num = DEF_NUM_MAPPINGS;
        String numMappings = getConfig(CONFIG_NUM_POLICY_MAPPINGS);

        if (numMappings != null) {
            try {
                num = Integer.parseInt(numMappings);
            } catch (NumberFormatException e) {
                // ignore
            }
        }
        return num;
    }

    public void init(IProfile profile, IConfigStore config)
            throws EProfileException {
        super.init(profile, config);
        refreshConfigAndValueNames();
    }

    public void setConfig(String name, String value)
            throws EPropertyException {
        int num = 0;
        if (name.equals(CONFIG_NUM_POLICY_MAPPINGS)) {
            try {
                num = Integer.parseInt(value);

                if (num >= MAX_NUM_MAPPINGS || num < 0) {
                    throw new EPropertyException(CMS.getUserMessage(
                            "CMS_INVALID_PROPERTY", CONFIG_NUM_POLICY_MAPPINGS));
                }

            } catch (Exception e) {
                throw new EPropertyException(CMS.getUserMessage(
                            "CMS_INVALID_PROPERTY", CONFIG_NUM_POLICY_MAPPINGS));
            }
        }
        super.setConfig(name, value);
    }

    public Enumeration<String> getConfigNames() {
        refreshConfigAndValueNames();
        return super.getConfigNames();
    }

    protected void refreshConfigAndValueNames() {
        super.refreshConfigAndValueNames();

        addValueName(VAL_CRITICAL);
        addValueName(VAL_DOMAINS);

        addConfigName(CONFIG_CRITICAL);
        int num = getNumMappings();

        addConfigName(CONFIG_NUM_POLICY_MAPPINGS);
        for (int i = 0; i < num; i++) {
            addConfigName(CONFIG_ISSUER_DOMAIN_POLICY + i);
            addConfigName(CONFIG_SUBJECT_DOMAIN_POLICY + i);
            addConfigName(CONFIG_ENABLE + i);
        }
    }

    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        if (name.equals(CONFIG_CRITICAL)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_CRITICAL"));
        } else if (name.startsWith(CONFIG_ISSUER_DOMAIN_POLICY)) {
            return new Descriptor(IDescriptor.STRING, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_ISSUER_DOMAIN_POLICY"));
        } else if (name.startsWith(CONFIG_SUBJECT_DOMAIN_POLICY)) {
            return new Descriptor(IDescriptor.STRING, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_SUBJECT_DOMAIN_POLICY"));
        } else if (name.startsWith(CONFIG_ENABLE)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_ENABLE"));
        } else if (name.startsWith(CONFIG_NUM_POLICY_MAPPINGS)) {
            return new Descriptor(IDescriptor.INTEGER, null,
                    "1",
                    CMS.getUserMessage(locale, "CMS_PROFILE_NUM_POLICY_MAPPINGS"));
        }

        return null;
    }

    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(VAL_CRITICAL)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_CRITICAL"));
        } else if (name.equals(VAL_DOMAINS)) {
            return new Descriptor(IDescriptor.STRING_LIST, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_DOMAINS"));
        }
        return null;
    }

    public void setValue(String name, Locale locale,
            X509CertInfo info, String value)
            throws EPropertyException {
        try {
            PolicyMappingsExtension ext = null;

            if (name == null) {
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
            }

            ext = (PolicyMappingsExtension)
                        getExtension(PKIXExtensions.PolicyMappings_Id.toString(),
                                info);

            if (ext == null) {
                populate(null, info);

            }

            if (name.equals(VAL_CRITICAL)) {
                ext = (PolicyMappingsExtension)
                        getExtension(PKIXExtensions.PolicyMappings_Id.toString(),
                                info);
                boolean val = Boolean.valueOf(value).booleanValue();

                if (ext == null) {
                    return;
                }
                ext.setCritical(val);
            } else if (name.equals(VAL_DOMAINS)) {
                ext = (PolicyMappingsExtension)
                        getExtension(PKIXExtensions.PolicyMappings_Id.toString(),
                                info);

                if (ext == null) {
                    return;
                }
                Vector<NameValuePairs> v = parseRecords(value);
                int size = v.size();

                String issuerPolicyId = null;
                String subjectPolicyId = null;
                String enable = null;
                Vector<CertificatePolicyMap> policyMaps = new Vector<CertificatePolicyMap>();

                for (int i = 0; i < size; i++) {
                    NameValuePairs nvps = v.elementAt(i);

                    for (String name1 : nvps.keySet()) {

                        if (name1.equals(ISSUER_POLICY_ID)) {
                            issuerPolicyId = nvps.get(name1);
                        } else if (name1.equals(SUBJECT_POLICY_ID)) {
                            subjectPolicyId = nvps.get(name1);
                        } else if (name1.equals(POLICY_ID_ENABLE)) {
                            enable = nvps.get(name1);
                        }
                    }

                    if (enable != null && enable.equals("true")) {
                        if (issuerPolicyId == null ||
                                issuerPolicyId.length() == 0 || subjectPolicyId == null ||
                                subjectPolicyId.length() == 0)
                            throw new EPropertyException(CMS.getUserMessage(
                                        locale, "CMS_PROFILE_POLICY_ID_NOT_FOUND"));
                        CertificatePolicyMap map = new CertificatePolicyMap(
                                new CertificatePolicyId(new ObjectIdentifier(issuerPolicyId)),
                                new CertificatePolicyId(new ObjectIdentifier(subjectPolicyId)));

                        policyMaps.addElement(map);
                    }
                }
                ext.set(PolicyMappingsExtension.MAP, policyMaps);
            } else {
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
            }

            replaceExtension(PKIXExtensions.PolicyMappings_Id.toString(),
                    ext, info);
        } catch (EProfileException e) {
            CMS.debug("PolicyMappingsExtDefault: setValue " + e.toString());
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        } catch (IOException e) {
            CMS.debug("PolicyMappingsExtDefault: setValue " + e.toString());
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
    }

    public String getValue(String name, Locale locale,
            X509CertInfo info)
            throws EPropertyException {
        PolicyMappingsExtension ext = null;

        if (name == null) {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }

        ext = (PolicyMappingsExtension)
                    getExtension(PKIXExtensions.PolicyMappings_Id.toString(),
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
            ext = (PolicyMappingsExtension)
                    getExtension(PKIXExtensions.PolicyMappings_Id.toString(),
                            info);

            if (ext == null) {
                return null;
            }
            if (ext.isCritical()) {
                return "true";
            } else {
                return "false";
            }
        } else if (name.equals(VAL_DOMAINS)) {
            ext = (PolicyMappingsExtension)
                    getExtension(PKIXExtensions.PolicyMappings_Id.toString(),
                            info);

            if (ext == null)
                return "";

            int num_mappings = getNumMappings();

            Enumeration<CertificatePolicyMap> maps = ext.getMappings();

            Vector<NameValuePairs> recs = new Vector<NameValuePairs>();

            for (int i = 0; i < num_mappings; i++) {
                NameValuePairs pairs = new NameValuePairs();

                if (maps.hasMoreElements()) {
                    CertificatePolicyMap map = maps.nextElement();

                    CertificatePolicyId i1 = map.getIssuerIdentifier();
                    CertificatePolicyId s1 = map.getSubjectIdentifier();

                    pairs.put(ISSUER_POLICY_ID, i1.getIdentifier().toString());
                    pairs.put(SUBJECT_POLICY_ID, s1.getIdentifier().toString());
                    pairs.put(POLICY_ID_ENABLE, "true");
                } else {
                    pairs.put(ISSUER_POLICY_ID, "");
                    pairs.put(SUBJECT_POLICY_ID, "");
                    pairs.put(POLICY_ID_ENABLE, "false");

                }
                recs.addElement(pairs);
            }

            return buildRecords(recs);
        } else {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
    }

    public String getText(Locale locale) {
        StringBuffer sb = new StringBuffer();
        int num = getNumMappings();

        for (int i = 0; i < num; i++) {
            sb.append("Record #");
            sb.append(i);
            sb.append("{");
            sb.append(ISSUER_POLICY_ID + ":");
            sb.append(getConfig(CONFIG_ISSUER_DOMAIN_POLICY + i));
            sb.append(",");
            sb.append(SUBJECT_POLICY_ID + ":");
            sb.append(getConfig(CONFIG_SUBJECT_DOMAIN_POLICY + i));
            sb.append(",");
            sb.append(POLICY_ID_ENABLE + ":");
            sb.append(getConfig(CONFIG_ENABLE + i));
            sb.append("}");
        }
        return CMS.getUserMessage(locale,
                "CMS_PROFILE_DEF_POLICY_MAPPINGS_EXT",
                getConfig(CONFIG_CRITICAL), sb.toString());
    }

    /**
     * Populates the request with this policy default.
     */
    public void populate(IRequest request, X509CertInfo info)
            throws EProfileException {
        PolicyMappingsExtension ext = createExtension();

        if (ext == null)
            return;
        addExtension(PKIXExtensions.PolicyMappings_Id.toString(),
                ext, info);
    }

    public PolicyMappingsExtension createExtension() {
        PolicyMappingsExtension ext = null;

        try {
            boolean critical = getConfigBoolean(CONFIG_CRITICAL);
            Vector<CertificatePolicyMap> policyMaps = new Vector<CertificatePolicyMap>();
            int num = getNumMappings();

            for (int i = 0; i < num; i++) {
                String enable = getConfig(CONFIG_ENABLE + i);

                if (enable != null && enable.equals("true")) {
                    String issuerID = getConfig(CONFIG_ISSUER_DOMAIN_POLICY + i);

                    if (issuerID == null || issuerID.length() == 0) {
                        return null;
                    }

                    String subjectID = getConfig(CONFIG_SUBJECT_DOMAIN_POLICY + i);

                    if (subjectID == null || subjectID.length() == 0) {
                        return null;
                    }

                    CertificatePolicyMap map = new CertificatePolicyMap(
                            new CertificatePolicyId(new ObjectIdentifier(issuerID)),
                            new CertificatePolicyId(new ObjectIdentifier(subjectID)));

                    policyMaps.addElement(map);
                }
            }

            ext = new PolicyMappingsExtension(critical, policyMaps);
        } catch (Exception e) {
            CMS.debug("PolicyMappingsExtDefault: createExtension " +
                    e.toString());
        }

        return ext;
    }
}
