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
import java.util.StringTokenizer;
import java.util.Vector;

import netscape.security.util.DerValue;
import netscape.security.util.ObjectIdentifier;
import netscape.security.x509.AVAValueConverter;
import netscape.security.x509.Attribute;
import netscape.security.x509.PKIXExtensions;
import netscape.security.x509.SubjectDirAttributesExtension;
import netscape.security.x509.X500NameAttrMap;
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
 * that populates a subject directory attributes extension
 * into the certificate template.
 *
 * @version $Revision$, $Date$
 */
public class SubjectDirAttributesExtDefault extends EnrollExtDefault {

    public static final String CONFIG_CRITICAL = "subjDirAttrsCritical";
    public static final String CONFIG_NUM_ATTRS = "subjDirAttrsNum";
    public static final String CONFIG_ATTR_NAME = "subjDirAttrName_";
    public static final String CONFIG_PATTERN = "subjDirAttrPattern_";
    public static final String CONFIG_ENABLE = "subjDirAttrEnable_";

    public static final String VAL_CRITICAL = "subjDirAttrCritical";
    public static final String VAL_ATTR = "subjDirAttrValue";

    private static final int DEF_NUM_ATTRS = 1;
    private static final int MAX_NUM_ATTRS = 100;
    private static final String ENABLE = "Enable";
    private static final String ATTR_NAME = "Attribute Name";
    private static final String ATTR_VALUE = "Attribute Value";

    public SubjectDirAttributesExtDefault() {
        super();
    }

    public void init(IProfile profile, IConfigStore config)
            throws EProfileException {
        super.init(profile, config);
        refreshConfigAndValueNames();
    }

    protected int getNumAttrs() {
        int num = DEF_NUM_ATTRS;
        String val = getConfig(CONFIG_NUM_ATTRS);

        if (val != null) {
            try {
                num = Integer.parseInt(val);
            } catch (NumberFormatException e) {
                // ignore
            }
        }

        if (num >= MAX_NUM_ATTRS)
            num = DEF_NUM_ATTRS;

        return num;
    }

    public void setConfig(String name, String value)
            throws EPropertyException {
        int num = 0;
        if (name.equals(DEF_NUM_ATTRS)) {
            try {
                num = Integer.parseInt(value);

                if (num >= MAX_NUM_ATTRS || num < 0) {
                    throw new EPropertyException(CMS.getUserMessage(
                            "CMS_INVALID_PROPERTY", CONFIG_NUM_ATTRS));
                }

            } catch (Exception e) {
                throw new EPropertyException(CMS.getUserMessage(
                            "CMS_INVALID_PROPERTY", CONFIG_NUM_ATTRS));
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
        addValueName(VAL_ATTR);

        addConfigName(CONFIG_CRITICAL);
        int num = getNumAttrs();
        addConfigName(CONFIG_NUM_ATTRS);
        for (int i = 0; i < num; i++) {
            addConfigName(CONFIG_ATTR_NAME + i);
            addConfigName(CONFIG_PATTERN + i);
            addConfigName(CONFIG_ENABLE + i);
        }
    }

    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        if (name.equals(CONFIG_CRITICAL)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_CRITICAL"));
        } else if (name.startsWith(CONFIG_ATTR_NAME)) {
            return new Descriptor(IDescriptor.STRING, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_NUM_ATTRS"));
        } else if (name.startsWith(CONFIG_ATTR_NAME)) {
            return new Descriptor(IDescriptor.STRING, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_ATTR_NAME"));
        } else if (name.startsWith(CONFIG_PATTERN)) {
            return new Descriptor(IDescriptor.STRING, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_ATTR_VALUE"));
        } else if (name.startsWith(CONFIG_ENABLE)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_ENABLE"));
        } else if (name.startsWith(CONFIG_NUM_ATTRS)) {
            return new Descriptor(IDescriptor.INTEGER, null,
                    "1",
                    CMS.getUserMessage(locale, "CMS_PROFILE_NUM_ATTRS"));
        }

        return null;
    }

    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(VAL_CRITICAL)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_CRITICAL"));
        } else if (name.equals(VAL_ATTR)) {
            return new Descriptor(IDescriptor.STRING_LIST, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_SUBJDIR_ATTRS"));
        } else {
            return null;
        }
    }

    public void setValue(String name, Locale locale,
            X509CertInfo info, String value)
            throws EPropertyException {
        try {
            SubjectDirAttributesExtension ext = null;

            if (name == null) {
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
            }

            ext = (SubjectDirAttributesExtension)
                    getExtension(PKIXExtensions.SubjectDirectoryAttributes_Id.toString(),
                            info);

            if (name.equals(VAL_CRITICAL)) {
                ext = (SubjectDirAttributesExtension)
                        getExtension(PKIXExtensions.SubjectDirectoryAttributes_Id.toString(),
                                info);
                boolean val = Boolean.valueOf(value).booleanValue();

                if (ext == null) {
                    return;
                }
                ext.setCritical(val);
            } else if (name.equals(VAL_ATTR)) {
                ext = (SubjectDirAttributesExtension)
                        getExtension(PKIXExtensions.SubjectDirectoryAttributes_Id.toString(),
                                info);

                if (ext == null) {
                    return;
                }
                Vector<NameValuePairs> v = parseRecords(value);
                int size = v.size();

                boolean critical = ext.isCritical();

                Vector<Attribute> attrV = new Vector<Attribute>();
                for (int i = 0; i < size; i++) {
                    NameValuePairs nvps = v.elementAt(i);
                    String attrName = null;
                    String attrValue = null;
                    String enable = "false";

                    for (String name1 : nvps.keySet()) {

                        if (name1.equals(ATTR_NAME)) {
                            attrName = nvps.get(name1);
                        } else if (name1.equals(ATTR_VALUE)) {
                            attrValue = nvps.get(name1);
                        } else if (name1.equals(ENABLE)) {
                            enable = nvps.get(name1);
                        }
                    }

                    if (enable.equals("true")) {
                        AttributeConfig attributeConfig =
                                new AttributeConfig(attrName, attrValue);
                        Attribute attr = attributeConfig.mAttribute;
                        if (attr != null)
                            attrV.addElement(attr);
                    }
                }

                if (attrV.size() > 0) {
                    Attribute[] attrList = new Attribute[attrV.size()];
                    attrV.copyInto(attrList);
                    ext = new SubjectDirAttributesExtension(attrList, critical);
                } else
                    return;
            } else {
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
            }

            replaceExtension(PKIXExtensions.SubjectDirectoryAttributes_Id.toString(),
                    ext, info);
        } catch (EProfileException e) {
            CMS.debug("SubjectDirAttributesExtDefault: setValue " +
                    e.toString());
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        } catch (IOException e) {
            CMS.debug("SubjectDirAttributesExtDefault: setValue " +
                    e.toString());
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
    }

    public String getValue(String name, Locale locale,
            X509CertInfo info)
            throws EPropertyException {
        SubjectDirAttributesExtension ext = null;

        if (name == null) {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }

        ext = (SubjectDirAttributesExtension)
                getExtension(PKIXExtensions.SubjectDirectoryAttributes_Id.toString(),
                        info);

        if (name.equals(VAL_CRITICAL)) {
            ext = (SubjectDirAttributesExtension)
                    getExtension(PKIXExtensions.SubjectDirectoryAttributes_Id.toString(),
                            info);

            if (ext == null) {
                return null;
            }
            if (ext.isCritical()) {
                return "true";
            } else {
                return "false";
            }
        } else if (name.equals(VAL_ATTR)) {
            ext = (SubjectDirAttributesExtension)
                    getExtension(PKIXExtensions.SubjectDirectoryAttributes_Id.toString(),
                            info);

            if (ext == null)
                return "";

            X500NameAttrMap map = X500NameAttrMap.getDefault();

            Vector<NameValuePairs> recs = new Vector<NameValuePairs>();
            int num = getNumAttrs();
            Enumeration<Attribute> e = ext.getAttributesList();
            CMS.debug("SubjectDirAttributesExtDefault: getValue: attributesList=" + e);
            int i = 0;

            while (e.hasMoreElements()) {
                NameValuePairs pairs = new NameValuePairs();
                pairs.put(ENABLE, "true");
                Attribute attr = e.nextElement();
                CMS.debug("SubjectDirAttributesExtDefault: getValue: attribute=" + attr);
                ObjectIdentifier oid = attr.getOid();
                CMS.debug("SubjectDirAttributesExtDefault: getValue: oid=" + oid);

                String vv = map.getName(oid);

                if (vv != null)
                    pairs.put(ATTR_NAME, vv);
                else
                    pairs.put(ATTR_NAME, oid.toString());
                Enumeration<String> v = attr.getValues();

                // just support single value for now
                StringBuffer ss = new StringBuffer();
                while (v.hasMoreElements()) {
                    if (ss.length() == 0)
                        ss.append(v.nextElement());
                    else {
                        ss.append(",");
                        ss.append(v.nextElement());
                    }
                }

                pairs.put(ATTR_VALUE, ss.toString());
                recs.addElement(pairs);
                i++;
            }

            for (; i < num; i++) {
                NameValuePairs pairs = new NameValuePairs();
                pairs.put(ENABLE, "false");
                pairs.put(ATTR_NAME, "GENERATIONQUALIFIER");
                pairs.put(ATTR_VALUE, "");
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
        int num = getNumAttrs();

        for (int i = 0; i < num; i++) {
            sb.append("Record #");
            sb.append(i);
            sb.append("{");
            sb.append(ATTR_NAME + ":");
            sb.append(getConfig(CONFIG_ATTR_NAME + i));
            sb.append(",");
            sb.append(ATTR_VALUE + ":");
            sb.append(getConfig(CONFIG_PATTERN + i));
            sb.append(",");
            sb.append(ENABLE + ":");
            sb.append(getConfig(CONFIG_ENABLE + i));
            sb.append("}");
        }
        return CMS.getUserMessage(locale,
                "CMS_PROFILE_DEF_SUBJECT_DIR_ATTR_EXT",
                getConfig(CONFIG_CRITICAL),
                sb.toString());
    }

    /**
     * Populates the request with this policy default.
     */
    public void populate(IRequest request, X509CertInfo info)
            throws EProfileException {
        SubjectDirAttributesExtension ext = createExtension(request);

        if (ext == null)
            return;

        addExtension(PKIXExtensions.SubjectDirectoryAttributes_Id.toString(),
                ext, info);
    }

    public SubjectDirAttributesExtension createExtension(IRequest request)
            throws EProfileException {
        SubjectDirAttributesExtension ext = null;
        int num = 0;

        boolean critical = getConfigBoolean(CONFIG_CRITICAL);

        num = getNumAttrs();

        AttributeConfig attributeConfig = null;
        Vector<Attribute> attrs = new Vector<Attribute>();
        for (int i = 0; i < num; i++) {
            String enable = getConfig(CONFIG_ENABLE + i);
            if (enable != null && enable.equals("true")) {
                String attrName = getConfig(CONFIG_ATTR_NAME + i);
                String pattern = getConfig(CONFIG_PATTERN + i);
                if (pattern == null || pattern.equals(""))
                    pattern = " ";

                //check pattern syntax
                int startpos = pattern.indexOf("$");
                int lastpos = pattern.lastIndexOf("$");
                String attrValue = pattern;
                if (!pattern.equals("") && startpos != -1 &&
                        startpos == 0 && lastpos != -1 &&
                        lastpos == (pattern.length() - 1)) {
                    if (request != null) {
                        try {
                            attrValue = mapPattern(request, pattern);
                        } catch (IOException e) {
                            throw new EProfileException(e.toString());
                        }
                    }
                }
                try {
                    attributeConfig = new AttributeConfig(attrName, attrValue);
                } catch (EPropertyException e) {
                    throw new EProfileException(e.toString());
                }
                Attribute attr = attributeConfig.mAttribute;
                if (attr != null) {
                    attrs.addElement(attr);
                }
            }
        }

        if (attrs.size() > 0) {
            Attribute[] attrList = new Attribute[attrs.size()];
            attrs.copyInto(attrList);
            try {
                ext =
                        new SubjectDirAttributesExtension(attrList, critical);
            } catch (IOException e) {
                throw new EProfileException(e.toString());
            }
        }

        return ext;
    }
}

class AttributeConfig {

    protected ObjectIdentifier mAttributeOID = null;
    protected Attribute mAttribute = null;

    public AttributeConfig(String attrName, String attrValue)
            throws EPropertyException {
        X500NameAttrMap map = X500NameAttrMap.getDefault();

        if (attrName == null || attrName.length() == 0) {
            throw new EPropertyException(
                    CMS.getUserMessage("CMS_PROFILE_SUBJDIR_EMPTY_ATTRNAME", attrName));
        }

        if (attrValue == null || attrValue.length() == 0) {
            throw new EPropertyException(
                    CMS.getUserMessage("CMS_PROFILE_SUBJDIR_EMPTY_ATTRVAL", attrValue));
        }

        try {
            mAttributeOID = new ObjectIdentifier(attrName);
        } catch (Exception e) {
            CMS.debug("SubjectDirAttributesExtDefault: invalid OID syntax: " + attrName);
        }

        if (mAttributeOID == null) {
            mAttributeOID = map.getOid(attrName);
            if (mAttributeOID == null)
                throw new EPropertyException(
                        CMS.getUserMessage("CMS_BASE_INVALID_ATTRIBUTE", attrName));
            try {
                checkValue(mAttributeOID, attrValue);
            } catch (IOException e) {
                throw new EPropertyException(CMS.getUserMessage(
                        "CMS_BASE_INVALID_ATTR_VALUE", e.getMessage()));
            }
        }

        try {
            mAttribute = new Attribute(mAttributeOID,
                    str2MultiValues(attrValue));
        } catch (IOException e) {
            throw new EPropertyException(CMS.getUserMessage(
                    "CMS_BASE_INVALID_ATTR_VALUE", e.getMessage()));
        }
    }

    private static void checkValue(ObjectIdentifier oid, String val)
            throws IOException {
        AVAValueConverter c = X500NameAttrMap.getDefault().getValueConverter(oid);

        @SuppressWarnings("unused")
        DerValue derval = c.getValue(val); // check for errors
        return;
    }

    private Vector<String> str2MultiValues(String attrValue) {
        StringTokenizer tokenizer = new StringTokenizer(attrValue, ",");
        Vector<String> v = new Vector<String>();
        while (tokenizer.hasMoreTokens()) {
            v.addElement(tokenizer.nextToken());
        }

        return v;
    }
}
