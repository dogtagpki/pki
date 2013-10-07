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

import netscape.security.x509.GeneralName;
import netscape.security.x509.GeneralNameInterface;
import netscape.security.x509.GeneralSubtree;
import netscape.security.x509.GeneralSubtrees;
import netscape.security.x509.NameConstraintsExtension;
import netscape.security.x509.PKIXExtensions;
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
 * that populates a name constraint extension
 * into the certificate template.
 *
 * @version $Revision$, $Date$
 */
public class NameConstraintsExtDefault extends EnrollExtDefault {

    public static final String CONFIG_CRITICAL = "nameConstraintsCritical";
    public static final String CONFIG_NUM_PERMITTED_SUBTREES =
            "nameConstraintsNumPermittedSubtrees";
    public static final String CONFIG_PERMITTED_MIN_VAL = "nameConstraintsPermittedSubtreeMinValue_";
    public static final String CONFIG_PERMITTED_MAX_VAL = "nameConstraintsPermittedSubtreeMaxValue_";
    public static final String CONFIG_PERMITTED_NAME_CHOICE = "nameConstraintsPermittedSubtreeNameChoice_";
    public static final String CONFIG_PERMITTED_NAME_VAL = "nameConstraintsPermittedSubtreeNameValue_";
    public static final String CONFIG_PERMITTED_ENABLE = "nameConstraintsPermittedSubtreeEnable_";

    public static final String CONFIG_NUM_EXCLUDED_SUBTREES = "nameConstraintsNumExcludedSubtrees";
    public static final String CONFIG_EXCLUDED_MIN_VAL = "nameConstraintsExcludedSubtreeMinValue_";
    public static final String CONFIG_EXCLUDED_MAX_VAL = "nameConstraintsExcludedSubtreeMaxValue_";
    public static final String CONFIG_EXCLUDED_NAME_CHOICE = "nameConstraintsExcludedSubtreeNameChoice_";
    public static final String CONFIG_EXCLUDED_NAME_VAL = "nameConstraintsExcludedSubtreeNameValue_";
    public static final String CONFIG_EXCLUDED_ENABLE = "nameConstraintsExcludedSubtreeEnable_";

    public static final String VAL_CRITICAL = "nameConstraintsCritical";
    public static final String VAL_PERMITTED_SUBTREES = "nameConstraintsPermittedSubtreesValue";
    public static final String VAL_EXCLUDED_SUBTREES = "nameConstraintsExcludedSubtreesValue";

    private static final String GENERAL_NAME_CHOICE = "GeneralNameChoice";
    private static final String GENERAL_NAME_VALUE = "GeneralNameValue";
    private static final String MIN_VALUE = "Min Value";
    private static final String MAX_VALUE = "Max Value";
    private static final String ENABLE = "Enable";

    protected static final int DEF_NUM_PERMITTED_SUBTREES = 1;
    protected static final int DEF_NUM_EXCLUDED_SUBTREES = 1;
    protected static final int MAX_NUM_EXCLUDED_SUBTREES = 100;
    protected static final int MAX_NUM_PERMITTED_SUBTREES = 100;

    public NameConstraintsExtDefault() {
        super();
    }

    public void init(IProfile profile, IConfigStore config)
            throws EProfileException {
        super.init(profile, config);
        refreshConfigAndValueNames();

    }

    protected int getNumPermitted() {
        int num = DEF_NUM_PERMITTED_SUBTREES;
        String val = getConfig(CONFIG_NUM_PERMITTED_SUBTREES);

        if (val != null) {
            try {
                num = Integer.parseInt(val);
            } catch (NumberFormatException e) {
                // ignore
            }
        }

        if (num >= MAX_NUM_PERMITTED_SUBTREES)
            num = DEF_NUM_PERMITTED_SUBTREES;
        return num;
    }

    protected int getNumExcluded() {
        int num = DEF_NUM_EXCLUDED_SUBTREES;
        String val = getConfig(CONFIG_NUM_EXCLUDED_SUBTREES);

        if (val != null) {
            try {
                num = Integer.parseInt(val);
            } catch (NumberFormatException e) {
                // ignore
            }
        }

        if (num >= MAX_NUM_EXCLUDED_SUBTREES)
            num = DEF_NUM_EXCLUDED_SUBTREES;

        return num;
    }

    public void setConfig(String name, String value)
            throws EPropertyException {
        int num = 0;
        if (name.equals(CONFIG_NUM_PERMITTED_SUBTREES)) {
            try {
                num = Integer.parseInt(value);

                if (num >= MAX_NUM_PERMITTED_SUBTREES || num < 0) {
                    throw new EPropertyException(CMS.getUserMessage(
                            "CMS_INVALID_PROPERTY", CONFIG_NUM_PERMITTED_SUBTREES));
                }

            } catch (Exception e) {
                throw new EPropertyException(CMS.getUserMessage(
                            "CMS_INVALID_PROPERTY", CONFIG_NUM_PERMITTED_SUBTREES));
            }
        } else if (name.equals(CONFIG_NUM_EXCLUDED_SUBTREES)) {

            try {
                num = Integer.parseInt(value);

                if (num >= MAX_NUM_EXCLUDED_SUBTREES || num < 0) {
                    throw new EPropertyException(CMS.getUserMessage(
                            "CMS_INVALID_PROPERTY", CONFIG_NUM_EXCLUDED_SUBTREES));
                }

            } catch (Exception e) {
                throw new EPropertyException(CMS.getUserMessage(
                            "CMS_INVALID_PROPERTY", CONFIG_NUM_EXCLUDED_SUBTREES));
            }
        }
        super.setConfig(name, value);
    }

    public Enumeration<String> getConfigNames() {
        refreshConfigAndValueNames();
        return super.getConfigNames();
    }

    protected void refreshConfigAndValueNames() {
        //refesh our config name list

        super.refreshConfigAndValueNames();

        addValueName(VAL_CRITICAL);
        addValueName(VAL_PERMITTED_SUBTREES);
        addValueName(VAL_EXCLUDED_SUBTREES);

        addConfigName(CONFIG_CRITICAL);
        int num = getNumPermitted();

        addConfigName(CONFIG_NUM_PERMITTED_SUBTREES);

        for (int i = 0; i < num; i++) {
            addConfigName(CONFIG_PERMITTED_MIN_VAL + i);
            addConfigName(CONFIG_PERMITTED_MAX_VAL + i);
            addConfigName(CONFIG_PERMITTED_NAME_CHOICE + i);
            addConfigName(CONFIG_PERMITTED_NAME_VAL + i);
            addConfigName(CONFIG_PERMITTED_ENABLE + i);
        }

        num = getNumExcluded();

        addConfigName(CONFIG_NUM_EXCLUDED_SUBTREES);
        for (int i = 0; i < num; i++) {
            addConfigName(CONFIG_EXCLUDED_MIN_VAL + i);
            addConfigName(CONFIG_EXCLUDED_MAX_VAL + i);
            addConfigName(CONFIG_EXCLUDED_NAME_CHOICE + i);
            addConfigName(CONFIG_EXCLUDED_NAME_VAL + i);
            addConfigName(CONFIG_EXCLUDED_ENABLE + i);
        }

    }

    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        if (name.equals(CONFIG_CRITICAL)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_CRITICAL"));
        } else if (name.startsWith(CONFIG_PERMITTED_MIN_VAL)) {
            return new Descriptor(IDescriptor.STRING, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_PERMITTED_MIN_VAL"));
        } else if (name.startsWith(CONFIG_PERMITTED_MAX_VAL)) {
            return new Descriptor(IDescriptor.STRING, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_PERMITTED_MAX_VAL"));
        } else if (name.startsWith(CONFIG_PERMITTED_NAME_CHOICE)) {
            return new Descriptor(IDescriptor.STRING, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_PERMITTED_NAME_CHOICE"));
        } else if (name.startsWith(CONFIG_PERMITTED_NAME_VAL)) {
            return new Descriptor(IDescriptor.STRING, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_PERMITTED_NAME_VAL"));
        } else if (name.startsWith(CONFIG_PERMITTED_ENABLE)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_ENABLE"));
        } else if (name.startsWith(CONFIG_EXCLUDED_MIN_VAL)) {
            return new Descriptor(IDescriptor.STRING, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_EXCLUDED_MIN_VAL"));
        } else if (name.startsWith(CONFIG_EXCLUDED_MAX_VAL)) {
            return new Descriptor(IDescriptor.STRING, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_EXCLUDED_MAX_VAL"));
        } else if (name.startsWith(CONFIG_EXCLUDED_NAME_CHOICE)) {
            return new Descriptor(IDescriptor.STRING, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_EXCLUDED_NAME_CHOICE"));
        } else if (name.startsWith(CONFIG_EXCLUDED_NAME_VAL)) {
            return new Descriptor(IDescriptor.STRING, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_EXCLUDED_NAME_VAL"));
        } else if (name.startsWith(CONFIG_EXCLUDED_ENABLE)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_ENABLE"));
        } else if (name.startsWith(CONFIG_NUM_EXCLUDED_SUBTREES)) {
            return new Descriptor(IDescriptor.INTEGER, null,
                    "1",
                    CMS.getUserMessage(locale, "CMS_PROFILE_NUM_EXCLUDED_SUBTREES"));
        } else if (name.startsWith(CONFIG_NUM_PERMITTED_SUBTREES)) {
            return new Descriptor(IDescriptor.INTEGER, null,
                    "1",
                    CMS.getUserMessage(locale, "CMS_PROFILE_NUM_PERMITTED_SUBTREES"));
        }
        return null;
    }

    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(VAL_CRITICAL)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_CRITICAL"));
        } else if (name.equals(VAL_PERMITTED_SUBTREES)) {
            return new Descriptor(IDescriptor.STRING_LIST, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_PERMITTED_SUBTREES"));
        } else if (name.equals(VAL_EXCLUDED_SUBTREES)) {
            return new Descriptor(IDescriptor.STRING_LIST, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_EXCLUDED_SUBTREES"));
        } else {
            return null;
        }
    }

    public void setValue(String name, Locale locale,
            X509CertInfo info, String value)
            throws EPropertyException {
        try {
            NameConstraintsExtension ext = null;

            if (name == null) {
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
            }

            ext = (NameConstraintsExtension)
                        getExtension(PKIXExtensions.NameConstraints_Id.toString(), info);

            if (ext == null) {
                populate(null, info);
            }

            if (name.equals(VAL_CRITICAL)) {
                ext = (NameConstraintsExtension)
                        getExtension(PKIXExtensions.NameConstraints_Id.toString(), info);
                boolean val = Boolean.valueOf(value).booleanValue();

                if (ext == null) {
                    return;
                }
                ext.setCritical(val);
            } else if (name.equals(VAL_PERMITTED_SUBTREES)) {
                ext = (NameConstraintsExtension)
                        getExtension(PKIXExtensions.NameConstraints_Id.toString(), info);

                if (ext == null) {
                    return;
                }
                if ((value == null) || (value.equals("null")) || (value.equals(""))) {
                    CMS.debug("NameConstraintsExtDefault:setValue : " +
                              "blank value for permitted subtrees ... returning");
                    return;
                }

                Vector<NameValuePairs> v = parseRecords(value);

                Vector<GeneralSubtree> permittedSubtrees = createSubtrees(locale, v);

                ext.set(NameConstraintsExtension.PERMITTED_SUBTREES,
                        new GeneralSubtrees(permittedSubtrees));
            } else if (name.equals(VAL_EXCLUDED_SUBTREES)) {
                ext = (NameConstraintsExtension)
                        getExtension(PKIXExtensions.NameConstraints_Id.toString(), info);

                if (ext == null) {
                    return;
                }
                if ((value == null) || (value.equals("null")) || (value.equals(""))) {
                    CMS.debug("NameConstraintsExtDefault:setValue : " +
                              "blank value for excluded subtrees ... returning");
                    return;
                }
                Vector<NameValuePairs> v = parseRecords(value);

                Vector<GeneralSubtree> excludedSubtrees = createSubtrees(locale, v);

                ext.set(NameConstraintsExtension.EXCLUDED_SUBTREES,
                        new GeneralSubtrees(excludedSubtrees));
            } else {
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
            }

            replaceExtension(PKIXExtensions.NameConstraints_Id.toString(), ext, info);
        } catch (IOException e) {
            CMS.debug("NameConstraintsExtDefault: setValue " + e.toString());
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        } catch (EProfileException e) {
            CMS.debug("NameConstraintsExtDefault: setValue " + e.toString());
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
    }

    private Vector<GeneralSubtree> createSubtrees(Locale locale, Vector<NameValuePairs> v) throws EPropertyException {
        int size = v.size();
        String choice = null;
        String val = "";
        String minS = null;
        String maxS = null;

        Vector<GeneralSubtree> subtrees = new Vector<GeneralSubtree>();

        for (int i = 0; i < size; i++) {
            NameValuePairs nvps = v.elementAt(i);

            for (String name1 : nvps.keySet()) {

                if (name1.equals(GENERAL_NAME_CHOICE)) {
                    choice = nvps.get(name1);
                } else if (name1.equals(GENERAL_NAME_VALUE)) {
                    val = nvps.get(name1);
                } else if (name1.equals(MIN_VALUE)) {
                    minS = nvps.get(name1);
                } else if (name1.equals(MAX_VALUE)) {
                    maxS = nvps.get(name1);
                }
            }

            if (choice == null || choice.length() == 0) {
                throw new EPropertyException(CMS.getUserMessage(locale,
                            "CMS_PROFILE_GENERAL_NAME_NOT_FOUND"));
            }

            if (val == null)
                val = "";

            int min = 0;
            int max = -1;

            if (minS != null && minS.length() > 0)
                min = Integer.parseInt(minS);
            if (maxS != null && maxS.length() > 0)
                max = Integer.parseInt(maxS);

            GeneralName gn = null;
            GeneralNameInterface gnI = null;

            try {
                gnI = parseGeneralName(choice + ":" + val);
            } catch (IOException e) {
                CMS.debug("NameConstraintsExtDefault: createSubtress " +
                        e.toString());
            }

            if (gnI != null) {
                gn = new GeneralName(gnI);
            } else {
                throw new EPropertyException(CMS.getUserMessage(locale,
                            "CMS_PROFILE_GENERAL_NAME_NOT_FOUND"));
            }
            GeneralSubtree subtree = new GeneralSubtree(
                    gn, min, max);

            subtrees.addElement(subtree);
        }

        return subtrees;
    }

    public String getValue(String name, Locale locale,
            X509CertInfo info)
            throws EPropertyException {
        NameConstraintsExtension ext = null;

        if (name == null) {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }

        ext = (NameConstraintsExtension)
                    getExtension(PKIXExtensions.NameConstraints_Id.toString(), info);

        if (ext == null) {
            try {
                populate(null, info);

            } catch (EProfileException e) {
                throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
            }

        }

        if (name.equals(VAL_CRITICAL)) {
            ext = (NameConstraintsExtension)
                    getExtension(PKIXExtensions.NameConstraints_Id.toString(), info);

            if (ext == null) {
                return null;
            }
            if (ext.isCritical()) {
                return "true";
            } else {
                return "false";
            }
        } else if (name.equals(VAL_PERMITTED_SUBTREES)) {
            ext = (NameConstraintsExtension)
                    getExtension(PKIXExtensions.NameConstraints_Id.toString(), info);

            if (ext == null)
                return "";

            GeneralSubtrees subtrees = null;

            try {
                subtrees = (GeneralSubtrees)
                        ext.get(NameConstraintsExtension.PERMITTED_SUBTREES);
            } catch (IOException e) {
                CMS.debug("NameConstraintExtDefault: getValue " + e.toString());
            }

            if (subtrees == null) {
                CMS.debug("NameConstraintsExtDefault::getValue() VAL_PERMITTED_SUBTREES is null!");
                throw new EPropertyException("subtrees is null");
            }

            return getSubtreesInfo(ext, subtrees);
        } else if (name.equals(VAL_EXCLUDED_SUBTREES)) {
            ext = (NameConstraintsExtension)
                    getExtension(PKIXExtensions.NameConstraints_Id.toString(), info);

            if (ext == null)
                return "";

            GeneralSubtrees subtrees = null;

            try {
                subtrees = (GeneralSubtrees)
                        ext.get(NameConstraintsExtension.EXCLUDED_SUBTREES);
            } catch (IOException e) {
                CMS.debug("NameConstraintExtDefault: getValue " + e.toString());
            }

            if (subtrees == null) {
                CMS.debug("NameConstraintsExtDefault::getValue() VAL_EXCLUDED_SUBTREES is null!");
                throw new EPropertyException("subtrees is null");
            }

            return getSubtreesInfo(ext, subtrees);
        } else {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
    }

    private String getSubtreesInfo(NameConstraintsExtension ext,
            GeneralSubtrees subtrees) throws EPropertyException {
        Vector<GeneralSubtree> trees = subtrees.getSubtrees();
        int size = trees.size();

        Vector<NameValuePairs> recs = new Vector<NameValuePairs>();

        for (int i = 0; i < size; i++) {
            GeneralSubtree tree = trees.elementAt(i);

            GeneralName gn = tree.getGeneralName();
            String type = getGeneralNameType(gn);
            int max = tree.getMaxValue();
            int min = tree.getMinValue();

            NameValuePairs pairs = new NameValuePairs();

            pairs.put(GENERAL_NAME_CHOICE, type);
            pairs.put(GENERAL_NAME_VALUE, getGeneralNameValue(gn));
            pairs.put(MIN_VALUE, Integer.toString(min));
            pairs.put(MAX_VALUE, Integer.toString(max));
            pairs.put(ENABLE, "true");

            recs.addElement(pairs);
        }

        return buildRecords(recs);
    }

    public String getText(Locale locale) {
        StringBuffer sb = new StringBuffer();
        int num = getNumPermitted();

        for (int i = 0; i < num; i++) {
            sb.append("Permitted #");
            sb.append(i);
            sb.append("{");
            sb.append(GENERAL_NAME_CHOICE + ":");
            sb.append(getConfig(CONFIG_PERMITTED_NAME_CHOICE + i));
            sb.append(",");
            sb.append(GENERAL_NAME_VALUE + ":");
            sb.append(getConfig(CONFIG_PERMITTED_NAME_VAL + i));
            sb.append(",");
            sb.append(MIN_VALUE + ":");
            sb.append(getConfig(CONFIG_PERMITTED_MIN_VAL + i));
            sb.append(",");
            sb.append(MAX_VALUE + ":");
            sb.append(getConfig(CONFIG_PERMITTED_MAX_VAL + i));
            sb.append("}");
        }
        num = getNumExcluded();
        for (int i = 0; i < num; i++) {
            sb.append("Exluded #");
            sb.append(i);
            sb.append("{");
            sb.append(GENERAL_NAME_CHOICE + ":");
            sb.append(getConfig(CONFIG_EXCLUDED_NAME_CHOICE + i));
            sb.append(",");
            sb.append(GENERAL_NAME_VALUE + ":");
            sb.append(getConfig(CONFIG_EXCLUDED_NAME_VAL + i));
            sb.append(",");
            sb.append(MIN_VALUE + ":");
            sb.append(getConfig(CONFIG_EXCLUDED_MIN_VAL + i));
            sb.append(",");
            sb.append(MAX_VALUE + ":");
            sb.append(getConfig(CONFIG_EXCLUDED_MAX_VAL + i));
            sb.append("}");
        }
        return CMS.getUserMessage(locale,
                "CMS_PROFILE_DEF_NAME_CONSTRAINTS_EXT",
                getConfig(CONFIG_CRITICAL), sb.toString());
    }

    /**
     * Populates the request with this policy default.
     */
    public void populate(IRequest request, X509CertInfo info)
            throws EProfileException {
        NameConstraintsExtension ext = createExtension();

        addExtension(PKIXExtensions.NameConstraints_Id.toString(), ext, info);
    }

    public NameConstraintsExtension createExtension() {
        NameConstraintsExtension ext = null;

        try {
            int num = getNumPermitted();

            boolean critical = getConfigBoolean(CONFIG_CRITICAL);

            Vector<GeneralSubtree> v = new Vector<GeneralSubtree>();

            for (int i = 0; i < num; i++) {
                String enable = getConfig(CONFIG_PERMITTED_ENABLE + i);

                if (enable != null && enable.equals("true")) {
                    String choice = getConfig(CONFIG_PERMITTED_NAME_CHOICE + i);
                    String value = getConfig(CONFIG_PERMITTED_NAME_VAL + i);
                    String minS = getConfig(CONFIG_PERMITTED_MIN_VAL + i);
                    String maxS = getConfig(CONFIG_PERMITTED_MAX_VAL + i);

                    v.addElement(createSubtree(choice, value, minS, maxS));
                }
            }

            Vector<GeneralSubtree> v1 = new Vector<GeneralSubtree>();

            num = getNumExcluded();
            for (int i = 0; i < num; i++) {
                String enable = getConfig(CONFIG_EXCLUDED_ENABLE + i);

                if (enable != null && enable.equals("true")) {
                    String choice = getConfig(CONFIG_EXCLUDED_NAME_CHOICE + i);
                    String value = getConfig(CONFIG_EXCLUDED_NAME_VAL + i);
                    String minS = getConfig(CONFIG_EXCLUDED_MIN_VAL + i);
                    String maxS = getConfig(CONFIG_EXCLUDED_MAX_VAL + i);

                    v1.addElement(createSubtree(choice, value, minS, maxS));
                }
            }

            ext = new NameConstraintsExtension(critical,
                        new GeneralSubtrees(v), new GeneralSubtrees(v1));
        } catch (Exception e) {
            CMS.debug("NameConstraintsExtDefault: createExtension " +
                    e.toString());
        }

        return ext;
    }

    private GeneralSubtree createSubtree(String choice, String value,
            String minS, String maxS) {
        GeneralName gn = null;
        GeneralNameInterface gnI = null;

        try {
            gnI = parseGeneralName(choice + ":" + value);
        } catch (IOException e) {
            CMS.debug(e.toString());
        }
        if (gnI != null)
            gn = new GeneralName(gnI);
        else
            //throw new EPropertyException("GeneralName must not be null");
            return null;

        int min = 0;

        if (minS != null && minS.length() > 0)
            min = Integer.parseInt(minS);
        int max = -1;

        if (maxS != null && maxS.length() > 0)
            max = Integer.parseInt(maxS);

        return (new GeneralSubtree(gn, min, max));
    }
}
