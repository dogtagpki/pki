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
import java.util.Hashtable;
import java.util.Locale;
import java.util.StringTokenizer;
import java.util.Vector;

import netscape.security.util.ObjectIdentifier;
import netscape.security.x509.CPSuri;
import netscape.security.x509.CertificatePoliciesExtension;
import netscape.security.x509.CertificatePolicyId;
import netscape.security.x509.CertificatePolicyInfo;
import netscape.security.x509.DisplayText;
import netscape.security.x509.NoticeReference;
import netscape.security.x509.PKIXExtensions;
import netscape.security.x509.PolicyQualifiers;
import netscape.security.x509.Qualifier;
import netscape.security.x509.UserNotice;
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
 * that populates a policy mappings extension
 * into the certificate template.
 *
 * @version $Revision$, $Date$
 */
public class CertificatePoliciesExtDefault extends EnrollExtDefault {

    public static final String CONFIG_CRITICAL = "Critical";
    public static final String CONFIG_PREFIX = "PoliciesExt.certPolicy";
    public static final String CONFIG_PREFIX1 = "PolicyQualifiers";
    public static final String CONFIG_POLICY_ENABLE = "enable";
    public static final String CONFIG_POLICY_NUM = "PoliciesExt.num";
    public static final String CONFIG_POLICY_ID = "policyId";
    public static final String CONFIG_POLICY_QUALIFIERS_NUM = "PolicyQualifiers.num";
    public static final String CONFIG_CPSURI_ENABLE = "CPSURI.enable";
    public static final String CONFIG_USERNOTICE_ENABLE = "usernotice.enable";
    public static final String CONFIG_CPSURI_VALUE = "CPSURI.value";
    public static final String CONFIG_USERNOTICE_ORG = "usernotice.noticeReference.organization";
    public static final String CONFIG_USERNOTICE_NUMBERS = "usernotice.noticeReference.noticeNumbers";
    public static final String CONFIG_USERNOTICE_TEXT = "usernotice.explicitText.value";

    public static final String VAL_CRITICAL = "Critical";
    public static final String VAL_POLICY_QUALIFIERS = "policyQualifiers";

    private static final String SEPARATOR = ".";
    private static final int DEF_NUM_POLICIES = 5;
    private static final int DEF_NUM_QUALIFIERS = 1;
    private static final int MAX_NUM_POLICIES = 20;
    private static final String POLICY_ID_ENABLE = "Enable";
    private static final String POLICY_ID = "Policy Id";
    private static final String POLICY_QUALIFIER_CPSURI_ENABLE = "CPSuri Enable";
    private static final String POLICY_QUALIFIER_USERNOTICE_ENABLE = "UserNotice Enable";
    private static final String USERNOTICE_REF_ORG = "UserNoticeReference Organization";
    private static final String USERNOTICE_REF_NUMBERS = "UserNoticeReference Numbers";
    private static final String USERNOTICE_EXPLICIT_TEXT = "UserNoticeReference Explicit Text";
    private static final String CPSURI = "CPS uri";

    public CertificatePoliciesExtDefault() {
        super();
    }

    protected int getNumPolicies() {
        int num = DEF_NUM_POLICIES;
        String numPolicies = getConfig(CONFIG_POLICY_NUM);

        if (numPolicies != null) {
            try {
                num = Integer.parseInt(numPolicies);
            } catch (NumberFormatException e) {
                // ignore
            }
        }

        if (num >= MAX_NUM_POLICIES)
            num = DEF_NUM_POLICIES;
        return num;
    }

    protected int getNumQualifiers() {
        int num = DEF_NUM_QUALIFIERS;
        String numQualifiers = getConfig(CONFIG_POLICY_QUALIFIERS_NUM);
        if (numQualifiers != null) {
            try {
                num = Integer.parseInt(numQualifiers);
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
        if (name.equals(CONFIG_POLICY_NUM)) {
            try {
                num = Integer.parseInt(value);

                if (num >= MAX_NUM_POLICIES || num < 0) {
                    throw new EPropertyException(CMS.getUserMessage(
                            "CMS_INVALID_PROPERTY", CONFIG_POLICY_NUM));
                }

            } catch (Exception e) {
                throw new EPropertyException(CMS.getUserMessage(
                            "CMS_INVALID_PROPERTY", CONFIG_POLICY_NUM));
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
        addValueName(VAL_POLICY_QUALIFIERS);

        addConfigName(CONFIG_CRITICAL);
        int num = getNumPolicies();
        int numQualifiers = getNumQualifiers();

        addConfigName(CONFIG_POLICY_NUM);

        for (int i = 0; i < num; i++) {
            addConfigName(CONFIG_PREFIX + i + SEPARATOR + CONFIG_POLICY_ID);
            addConfigName(CONFIG_PREFIX + i + SEPARATOR + CONFIG_POLICY_ENABLE);
            for (int j = 0; j < numQualifiers; j++) {
                addConfigName(CONFIG_PREFIX + i + SEPARATOR + CONFIG_PREFIX1 + j + SEPARATOR + CONFIG_CPSURI_ENABLE);
                addConfigName(CONFIG_PREFIX + i + SEPARATOR + CONFIG_PREFIX1 + j + SEPARATOR + CONFIG_USERNOTICE_ENABLE);
                addConfigName(CONFIG_PREFIX + i + SEPARATOR + CONFIG_PREFIX1 + j + SEPARATOR + CONFIG_CPSURI_VALUE);
                addConfigName(CONFIG_PREFIX + i + SEPARATOR + CONFIG_PREFIX1 + j + SEPARATOR + CONFIG_USERNOTICE_ORG);
                addConfigName(CONFIG_PREFIX
                        + i + SEPARATOR + CONFIG_PREFIX1 + j + SEPARATOR + CONFIG_USERNOTICE_NUMBERS);
                addConfigName(CONFIG_PREFIX + i + SEPARATOR + CONFIG_PREFIX1 + j + SEPARATOR + CONFIG_USERNOTICE_TEXT);
            }
        }
    }

    public IDescriptor getConfigDescriptor(Locale locale, String name) {

        if (name.equals(CONFIG_CRITICAL)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_CRITICAL"));
        } else if (name.indexOf(CONFIG_POLICY_ID) >= 0) {
            return new Descriptor(IDescriptor.STRING, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_POLICY_ID"));
        } else if (name.indexOf(CONFIG_CPSURI_ENABLE) >= 0) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_POLICY_QUALIFIER_CPSURI_ENABLE"));
        } else if (name.indexOf(CONFIG_USERNOTICE_ENABLE) >= 0) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_POLICY_QUALIFIER_USERNOTICE_ENABLE"));
        } else if (name.indexOf(CONFIG_POLICY_ENABLE) >= 0) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_CERTIFICATE_POLICY_ENABLE"));
        } else if (name.indexOf(CONFIG_POLICY_QUALIFIERS_NUM) >= 0) {
            return new Descriptor(IDescriptor.INTEGER, null,
                    "1",
                    CMS.getUserMessage(locale, "CMS_PROFILE_POLICY_QUALIFIER_NUM"));
        } else if (name.indexOf(CONFIG_USERNOTICE_ORG) >= 0) {
            return new Descriptor(IDescriptor.STRING, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_POLICY_USERNOTICE_REF_ORG"));
        } else if (name.indexOf(CONFIG_USERNOTICE_NUMBERS) >= 0) {
            return new Descriptor(IDescriptor.STRING, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_POLICY_USERNOTICE_REF_NUMBERS"));
        } else if (name.indexOf(CONFIG_USERNOTICE_TEXT) >= 0) {
            return new Descriptor(IDescriptor.STRING, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_POLICY_USERNOTICE_EXPLICIT_TEXT"));
        } else if (name.indexOf(CONFIG_CPSURI_VALUE) >= 0) {
            return new Descriptor(IDescriptor.STRING, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_POLICY_CPSURI"));
        } else if (name.indexOf(CONFIG_POLICY_NUM) >= 0) {
            return new Descriptor(IDescriptor.INTEGER, null,
                    "5",
                    CMS.getUserMessage(locale, "CMS_PROFILE_NUM_POLICIES"));
        }
        return null;
    }

    public IDescriptor getValueDescriptor(Locale locale, String name) {

        if (name.equals(VAL_CRITICAL)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_CRITICAL"));
        } else if (name.equals(VAL_POLICY_QUALIFIERS)) {
            return new Descriptor(IDescriptor.STRING_LIST, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_POLICY_QUALIFIERS"));
        }
        return null;
    }

    private Hashtable<String, String> buildRecords(String value) throws EPropertyException {
        StringTokenizer st = new StringTokenizer(value, "\r\n");
        Hashtable<String, String> table = new Hashtable<String, String>();
        while (st.hasMoreTokens()) {
            String token = st.nextToken();
            int index = token.indexOf(":");
            if (index <= 0)
                throw new EPropertyException(CMS.getUserMessage(
                        "CMS_INVALID_PROPERTY", token));
            String name = token.substring(0, index);
            String val = "";
            if ((token.length() - 1) > index) {
                val = token.substring(index + 1);
            }
            table.put(name, val);
        }

        return table;
    }

    public void setValue(String name, Locale locale,
            X509CertInfo info, String value)
            throws EPropertyException {
        try {
            CertificatePoliciesExtension ext = null;

            if (name == null) {
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
            }
            if (name.equals(VAL_CRITICAL)) {
                ext = (CertificatePoliciesExtension)
                        getExtension(PKIXExtensions.CertificatePolicies_Id.toString(),
                                info);
                boolean val = Boolean.valueOf(value).booleanValue();

                ext.setCritical(val);
            } else if (name.equals(VAL_POLICY_QUALIFIERS)) {
                ext = (CertificatePoliciesExtension)
                        getExtension(PKIXExtensions.CertificatePolicies_Id.toString(),
                                info);

                Hashtable<String, String> h = buildRecords(value);

                String numStr = h.get(CONFIG_POLICY_NUM);
                int size = Integer.parseInt(numStr);

                Vector<CertificatePolicyInfo> certificatePolicies = new Vector<CertificatePolicyInfo>();
                for (int i = 0; i < size; i++) {
                    String enable = h.get(CONFIG_PREFIX + i + SEPARATOR + CONFIG_POLICY_ENABLE);
                    CertificatePolicyInfo cinfo = null;
                    if (enable != null && enable.equals("true")) {
                        String policyId = h.get(CONFIG_PREFIX + i + SEPARATOR + CONFIG_POLICY_ID);

                        if (policyId == null || policyId.length() == 0)
                            throw new EPropertyException(CMS.getUserMessage(
                                        locale, "CMS_PROFILE_CERTIFICATE_POLICIES_EMPTY_POLICYID"));
                        CertificatePolicyId cpolicyId = getPolicyId(policyId);

                        String qualifersNum =
                                h.get(CONFIG_PREFIX + i + SEPARATOR + CONFIG_POLICY_QUALIFIERS_NUM);
                        PolicyQualifiers policyQualifiers = new PolicyQualifiers();
                        int num = 0;
                        if (qualifersNum != null && qualifersNum.length() > 0)
                            num = Integer.parseInt(qualifersNum);
                        for (int j = 0; j < num; j++) {
                            String cpsuriEnable =
                                    h.get(CONFIG_PREFIX
                                    + i + SEPARATOR + CONFIG_PREFIX1 + j + SEPARATOR + CONFIG_CPSURI_ENABLE);
                            String usernoticeEnable =
                                    h.get(CONFIG_PREFIX
                                            + i + SEPARATOR + CONFIG_PREFIX1 + j + SEPARATOR
                                            + CONFIG_USERNOTICE_ENABLE);
                            if (cpsuriEnable != null && cpsuriEnable.equals("true")) {
                                String cpsuri =
                                        h.get(CONFIG_PREFIX
                                        + i + SEPARATOR + CONFIG_PREFIX1 + j + SEPARATOR + CONFIG_CPSURI_VALUE);
                                netscape.security.x509.PolicyQualifierInfo qualifierInfo = createCPSuri(cpsuri);
                                if (qualifierInfo != null)
                                    policyQualifiers.add(qualifierInfo);
                            } else if (usernoticeEnable != null && enable.equals("true")) {
                                String org =
                                        h.get(CONFIG_PREFIX
                                        + i + SEPARATOR + CONFIG_PREFIX1 + j + SEPARATOR
                                        + CONFIG_USERNOTICE_ORG);
                                String noticenumbers =
                                        h.get(CONFIG_PREFIX
                                        + i + SEPARATOR + CONFIG_PREFIX1 + j + SEPARATOR
                                        + CONFIG_USERNOTICE_NUMBERS);
                                String explicitText =
                                        h.get(CONFIG_PREFIX
                                        + i + SEPARATOR + CONFIG_PREFIX1 + j + SEPARATOR
                                        + CONFIG_USERNOTICE_TEXT);
                                netscape.security.x509.PolicyQualifierInfo qualifierInfo = createUserNotice(org,
                                        noticenumbers, explicitText);
                                if (qualifierInfo != null)
                                    policyQualifiers.add(qualifierInfo);
                            }
                        }

                        if (policyQualifiers.size() <= 0) {
                            cinfo = new CertificatePolicyInfo(cpolicyId);
                        } else {
                            cinfo = new CertificatePolicyInfo(cpolicyId, policyQualifiers);
                        }
                        if (cinfo != null)
                            certificatePolicies.addElement(cinfo);
                    }
                }

                ext.set(CertificatePoliciesExtension.INFOS, certificatePolicies);
            } else {
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
            }

            replaceExtension(PKIXExtensions.CertificatePolicies_Id.toString(),
                    ext, info);
        } catch (EProfileException e) {
            CMS.debug("CertificatePoliciesExtDefault: setValue " + e.toString());
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        } catch (IOException e) {
            CMS.debug("CertificatePoliciesExtDefault: setValue " + e.toString());
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
    }

    @SuppressWarnings("unchecked")
    public String getValue(String name, Locale locale,
            X509CertInfo info)
            throws EPropertyException {
        CertificatePoliciesExtension ext = null;

        if (name == null) {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }

        if (name.equals(VAL_CRITICAL)) {
            ext = (CertificatePoliciesExtension)
                    getExtension(PKIXExtensions.CertificatePolicies_Id.toString(),
                            info);

            if (ext == null) {
                return null;
            }
            if (ext.isCritical()) {
                return "true";
            } else {
                return "false";
            }
        } else if (name.equals(VAL_POLICY_QUALIFIERS)) {
            ext = (CertificatePoliciesExtension)
                    getExtension(PKIXExtensions.CertificatePolicies_Id.toString(),
                            info);

            if (ext == null)
                return "";

            StringBuffer sb = new StringBuffer();
            int num_policies = getNumPolicies();
            sb.append(CONFIG_POLICY_NUM);
            sb.append(":");
            sb.append(num_policies);
            sb.append("\n");
            Vector<CertificatePolicyInfo> infos;

            try {
                infos = (Vector<CertificatePolicyInfo>) ext.get(CertificatePoliciesExtension.INFOS);
            } catch (IOException ee) {
                infos = null;
            }

            for (int i = 0; i < num_policies; i++) {
                int qSize = 0;
                String policyId = "";
                String policyEnable = "false";
                PolicyQualifiers qualifiers = null;
                if (infos.size() > 0) {
                    CertificatePolicyInfo cinfo =
                            infos.elementAt(0);

                    CertificatePolicyId id1 = cinfo.getPolicyIdentifier();
                    policyId = id1.getIdentifier().toString();
                    policyEnable = "true";
                    qualifiers = cinfo.getPolicyQualifiers();
                    if (qualifiers != null)
                        qSize = qualifiers.size();
                    infos.removeElementAt(0);
                }
                sb.append(CONFIG_PREFIX + i + SEPARATOR + CONFIG_POLICY_ENABLE);
                sb.append(":");
                sb.append(policyEnable);
                sb.append("\n");
                sb.append(CONFIG_PREFIX + i + SEPARATOR + CONFIG_POLICY_ID);
                sb.append(":");
                sb.append(policyId);
                sb.append("\n");

                if (qSize == 0) {
                    sb.append(CONFIG_PREFIX + i + SEPARATOR + CONFIG_POLICY_QUALIFIERS_NUM);
                    sb.append(":");
                    sb.append(DEF_NUM_QUALIFIERS);
                    sb.append("\n");
                } else {
                    sb.append(CONFIG_PREFIX + i + SEPARATOR + CONFIG_POLICY_QUALIFIERS_NUM);
                    sb.append(":");
                    sb.append(qSize);
                    sb.append("\n");
                }
                if (qSize == 0) {
                    sb.append(CONFIG_PREFIX + i + SEPARATOR + CONFIG_PREFIX1 + "0" + SEPARATOR + CONFIG_CPSURI_ENABLE);
                    sb.append(":");
                    sb.append("false");
                    sb.append("\n");
                    sb.append(CONFIG_PREFIX + i + SEPARATOR + CONFIG_PREFIX1 + "0" + SEPARATOR + CONFIG_CPSURI_VALUE);
                    sb.append(":");
                    sb.append("");
                    sb.append("\n");
                    sb.append(CONFIG_PREFIX
                            + i + SEPARATOR + CONFIG_PREFIX1 + "0" + SEPARATOR + CONFIG_USERNOTICE_ENABLE);
                    sb.append(":");
                    sb.append("false");
                    sb.append("\n");
                    sb.append(CONFIG_PREFIX + i + SEPARATOR + CONFIG_PREFIX1 + "0" + SEPARATOR + CONFIG_USERNOTICE_ORG);
                    sb.append(":");
                    sb.append("");
                    sb.append("\n");
                    sb.append(CONFIG_PREFIX
                            + i + SEPARATOR + CONFIG_PREFIX1 + "0" + SEPARATOR + CONFIG_USERNOTICE_NUMBERS);
                    sb.append(":");
                    sb.append("");
                    sb.append("\n");
                    sb.append(CONFIG_PREFIX + i + SEPARATOR + CONFIG_PREFIX1 + "0" + SEPARATOR + CONFIG_USERNOTICE_TEXT);
                    sb.append(":");
                    sb.append("");
                    sb.append("\n");
                }

                for (int j = 0; j < qSize; j++) {
                    netscape.security.x509.PolicyQualifierInfo qinfo = qualifiers.getInfoAt(j);
                    ObjectIdentifier oid = qinfo.getId();
                    Qualifier qualifier = qinfo.getQualifier();

                    String cpsuriEnable = "false";
                    String usernoticeEnable = "false";
                    String cpsuri = "";
                    String org = "";
                    StringBuffer noticeNum = new StringBuffer();
                    String explicitText = "";

                    if (oid.toString().equals(netscape.security.x509.PolicyQualifierInfo.QT_CPS.toString())) {
                        cpsuriEnable = "true";
                        CPSuri content = (CPSuri) qualifier;
                        cpsuri = content.getURI();
                    } else if (oid.toString().equals(netscape.security.x509.PolicyQualifierInfo.QT_UNOTICE.toString())) {
                        usernoticeEnable = "true";
                        UserNotice content = (UserNotice) qualifier;
                        NoticeReference ref = content.getNoticeReference();
                        if (ref != null) {
                            org = ref.getOrganization().getText();
                            int[] nums = ref.getNumbers();
                            for (int k = 0; k < nums.length; k++) {
                                if (k != 0) {
                                    noticeNum.append(",");
                                    noticeNum.append(nums[k]);
                                } else
                                    noticeNum.append(nums[k]);
                            }
                        }
                        DisplayText displayText = content.getDisplayText();
                        if (displayText != null)
                            explicitText = displayText.getText();
                    }

                    sb.append(CONFIG_PREFIX + i + SEPARATOR + CONFIG_PREFIX1 + j + SEPARATOR + CONFIG_CPSURI_ENABLE);
                    sb.append(":");
                    sb.append(cpsuriEnable);
                    sb.append("\n");
                    sb.append(CONFIG_PREFIX + i + SEPARATOR + CONFIG_PREFIX1 + j + SEPARATOR + CONFIG_CPSURI_VALUE);
                    sb.append(":");
                    sb.append(cpsuri);
                    sb.append("\n");
                    sb.append(CONFIG_PREFIX + i + SEPARATOR + CONFIG_PREFIX1 + j + SEPARATOR + CONFIG_USERNOTICE_ENABLE);
                    sb.append(":");
                    sb.append(usernoticeEnable);
                    sb.append("\n");
                    sb.append(CONFIG_PREFIX + i + SEPARATOR + CONFIG_PREFIX1 + j + SEPARATOR + CONFIG_USERNOTICE_ORG);
                    sb.append(":");
                    sb.append(org);
                    sb.append("\n");
                    sb.append(CONFIG_PREFIX
                            + i + SEPARATOR + CONFIG_PREFIX1 + j + SEPARATOR + CONFIG_USERNOTICE_NUMBERS);
                    sb.append(":");
                    sb.append(noticeNum.toString());
                    sb.append("\n");
                    sb.append(CONFIG_PREFIX + i + SEPARATOR + CONFIG_PREFIX1 + j + SEPARATOR + CONFIG_USERNOTICE_TEXT);
                    sb.append(":");
                    sb.append(explicitText);
                    sb.append("\n");
                }
            } // end of for loop
            return sb.toString();
        } else {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
    }

    public String getText(Locale locale) {
        StringBuffer sb = new StringBuffer();
        int num = getNumPolicies();
        int num1 = getNumQualifiers();

        try {
            IConfigStore basesubstore = getConfigStore().getSubStore("params");
            sb.append("{");
            sb.append(CONFIG_POLICY_NUM + ":");
            sb.append(num);
            sb.append(",");
            for (int i = 0; i < num; i++) {
                sb.append("{");
                IConfigStore substore = basesubstore.getSubStore(CONFIG_PREFIX + i);
                String enable = substore.getString(CONFIG_POLICY_ENABLE, "");
                sb.append(POLICY_ID_ENABLE + ":");
                sb.append(enable);
                sb.append(",");
                String policyId = substore.getString(CONFIG_POLICY_ID, "");
                sb.append(POLICY_ID + ":");
                sb.append(policyId);
                sb.append(",");
                String qualifiersNum = substore.getString(CONFIG_POLICY_QUALIFIERS_NUM, "");
                sb.append(CONFIG_POLICY_QUALIFIERS_NUM + ":");
                sb.append(qualifiersNum);
                sb.append(",");
                for (int j = 0; j < num1; j++) {
                    IConfigStore substore1 = substore.getSubStore(CONFIG_PREFIX1 + j);
                    sb.append("{");
                    String cpsuriEnable = substore1.getString(CONFIG_CPSURI_ENABLE, "");
                    sb.append(POLICY_QUALIFIER_CPSURI_ENABLE + ":");
                    sb.append(cpsuriEnable);
                    sb.append(",");
                    String usernoticeEnable = substore1.getString(CONFIG_USERNOTICE_ENABLE, "");
                    sb.append(POLICY_QUALIFIER_USERNOTICE_ENABLE + ":");
                    sb.append(usernoticeEnable);
                    sb.append(",");
                    String org = substore1.getString(CONFIG_USERNOTICE_ORG, "");
                    sb.append(USERNOTICE_REF_ORG + ":");
                    sb.append(org);
                    sb.append(",");
                    String refNums = substore1.getString(CONFIG_USERNOTICE_NUMBERS, "");
                    sb.append(USERNOTICE_REF_NUMBERS + ":");
                    sb.append(refNums);
                    sb.append(",");
                    String explicitText = substore1.getString(CONFIG_USERNOTICE_TEXT, "");
                    sb.append(USERNOTICE_EXPLICIT_TEXT + ":");
                    sb.append(explicitText);
                    sb.append(",");
                    String cpsuri = substore1.getString(CONFIG_CPSURI_VALUE, "");
                    sb.append(CPSURI + ":");
                    sb.append(cpsuri);
                    sb.append("}");
                }
                sb.append("}");
            }
            sb.append("}");
            return CMS.getUserMessage(locale,
                    "CMS_PROFILE_DEF_CERTIFICATE_POLICIES_EXT",
                    getConfig(CONFIG_CRITICAL), sb.toString());
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * Populates the request with this policy default.
     */
    public void populate(IRequest request, X509CertInfo info)
            throws EProfileException {
        CertificatePoliciesExtension ext = createExtension();

        if (ext == null)
            return;
        addExtension(PKIXExtensions.CertificatePolicies_Id.toString(),
                ext, info);
    }

    public CertificatePoliciesExtension createExtension()
            throws EProfileException {
        CertificatePoliciesExtension ext = null;

        try {
            boolean critical = getConfigBoolean(CONFIG_CRITICAL);
            Vector<CertificatePolicyInfo> certificatePolicies = new Vector<CertificatePolicyInfo>();
            int num = getNumPolicies();
            CMS.debug("CertificatePoliciesExtension: createExtension: number of policies=" + num);
            IConfigStore config = getConfigStore();

            for (int i = 0; i < num; i++) {
                IConfigStore basesubstore = config.getSubStore("params");
                IConfigStore substore = basesubstore.getSubStore(CONFIG_PREFIX + i);
                String enable = substore.getString(CONFIG_POLICY_ENABLE);

                CMS.debug("CertificatePoliciesExtension: createExtension: CertificatePolicy " + i + " enable=" + enable);
                if (enable != null && enable.equals("true")) {
                    String policyId = substore.getString(CONFIG_POLICY_ID);
                    CertificatePolicyId cpolicyId = getPolicyId(policyId);
                    CMS.debug("CertificatePoliciesExtension: createExtension: CertificatePolicy "
                            + i + " policyId=" + policyId);
                    int qualifierNum = getNumQualifiers();
                    PolicyQualifiers policyQualifiers = new PolicyQualifiers();
                    for (int j = 0; j < qualifierNum; j++) {
                        IConfigStore substore1 = substore.getSubStore(CONFIG_PREFIX1 + j);
                        String cpsuriEnable = substore1.getString(CONFIG_CPSURI_ENABLE);
                        String usernoticeEnable = substore1.getString(CONFIG_USERNOTICE_ENABLE);

                        if (cpsuriEnable != null && cpsuriEnable.equals("true")) {
                            String cpsuri = substore1.getString(CONFIG_CPSURI_VALUE, "");
                            netscape.security.x509.PolicyQualifierInfo qualifierInfo = createCPSuri(cpsuri);
                            if (qualifierInfo != null)
                                policyQualifiers.add(qualifierInfo);
                        } else if (usernoticeEnable != null &&
                                     usernoticeEnable.equals("true")) {

                            String org = substore1.getString(CONFIG_USERNOTICE_ORG);
                            String noticenumbers = substore1.getString(CONFIG_USERNOTICE_NUMBERS);
                            String explicitText = substore1.getString(CONFIG_USERNOTICE_TEXT);
                            netscape.security.x509.PolicyQualifierInfo qualifierInfo = createUserNotice(org,
                                    noticenumbers, explicitText);
                            if (qualifierInfo != null)
                                policyQualifiers.add(qualifierInfo);
                        }
                    }

                    CertificatePolicyInfo info = null;
                    if (policyQualifiers.size() <= 0) {
                        info =
                                new CertificatePolicyInfo(cpolicyId);
                    } else {
                        info =
                                new CertificatePolicyInfo(cpolicyId, policyQualifiers);
                    }

                    if (info != null)
                        certificatePolicies.addElement(info);
                }
            }

            ext = new CertificatePoliciesExtension(critical, certificatePolicies);
        } catch (EPropertyException e) {
            throw new EProfileException(e.toString());
        } catch (EProfileException e) {
            throw e;
        } catch (Exception e) {
            CMS.debug("CertificatePoliciesExtDefault: createExtension " +
                    e.toString());
        }

        return ext;
    }

    private CertificatePolicyId getPolicyId(String policyId) throws EPropertyException {
        if (policyId == null || policyId.length() == 0)
            throw new EPropertyException(CMS.getUserMessage(
                    "CMS_PROFILE_CERTIFICATE_POLICIES_EMPTY_POLICYID"));

        CertificatePolicyId cpolicyId = null;
        try {
            cpolicyId = new CertificatePolicyId(
                    ObjectIdentifier.getObjectIdentifier(policyId));
            return cpolicyId;
        } catch (Exception e) {
            throw new EPropertyException(CMS.getUserMessage(
                    "CMS_PROFILE_CERTIFICATE_POLICIES_POLICYID_ERROR", policyId));
        }
    }

    private netscape.security.x509.PolicyQualifierInfo createCPSuri(String uri) throws EPropertyException {
        if (uri == null || uri.length() == 0)
            throw new EPropertyException(CMS.getUserMessage(
                    "CMS_PROFILE_CERTIFICATE_POLICIES_EMPTY_CPSURI"));

        CPSuri cpsURI = new CPSuri(uri);
        netscape.security.x509.PolicyQualifierInfo policyQualifierInfo2 =
                new netscape.security.x509.PolicyQualifierInfo(netscape.security.x509.PolicyQualifierInfo.QT_CPS,
                        cpsURI);

        return policyQualifierInfo2;
    }

    private netscape.security.x509.PolicyQualifierInfo createUserNotice(String organization,
            String noticeText, String noticeNums) throws EPropertyException {

        if ((organization == null || organization.length() == 0) &&
                (noticeNums == null || noticeNums.length() == 0) &&
                (noticeText == null || noticeText.length() == 0))
            return null;

        DisplayText explicitText = null;
        if (noticeText != null && noticeText.length() > 0)
            explicitText = new DisplayText(DisplayText.tag_VisibleString, noticeText);

        int nums[] = null;
        if (noticeNums != null && noticeNums.length() > 0) {
            Vector<String> numsVector = new Vector<String>();
            StringTokenizer tokens = new StringTokenizer(noticeNums, ";");
            while (tokens.hasMoreTokens()) {
                String num = tokens.nextToken().trim();
                numsVector.addElement(num);
            }

            nums = new int[numsVector.size()];
            try {
                for (int i = 0; i < numsVector.size(); i++) {
                    Integer ii = new Integer(numsVector.elementAt(i));
                    nums[i] = ii.intValue();
                }
            } catch (Exception e) {
                throw new EPropertyException("Wrong notice numbers");
            }
        }

        DisplayText orgName = null;
        if (organization != null && organization.length() > 0) {
            orgName =
                    new DisplayText(DisplayText.tag_VisibleString, organization);
        }

        NoticeReference noticeReference = null;

        if (orgName != null)
            noticeReference = new NoticeReference(orgName, nums);

        UserNotice userNotice = null;
        if (explicitText != null || noticeReference != null) {
            userNotice = new UserNotice(noticeReference, explicitText);

            netscape.security.x509.PolicyQualifierInfo policyQualifierInfo1 =
                    new netscape.security.x509.PolicyQualifierInfo(
                            netscape.security.x509.PolicyQualifierInfo.QT_UNOTICE, userNotice);
            return policyQualifierInfo1;
        }

        return null;
    }
}
