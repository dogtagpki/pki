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
import java.util.UUID;

import netscape.security.x509.GeneralNameInterface;
import netscape.security.x509.GeneralNames;
import netscape.security.x509.PKIXExtensions;
import netscape.security.x509.SubjectAlternativeNameExtension;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IAttrSet;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.pattern.Pattern;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;

/**
 * This class implements an enrollment default policy
 * that populates a subject alternative name extension
 * into the certificate template.
 *
 * @version $Revision$, $Date$
 */
public class SubjectAltNameExtDefault extends EnrollExtDefault {

    public static final String CONFIG_CRITICAL = "subjAltNameExtCritical";
    public static final String CONFIG_NUM_GNS = "subjAltNameNumGNs";
    public static final String CONFIG_GN_ENABLE = "subjAltExtGNEnable_";
    public static final String CONFIG_TYPE = "subjAltExtType_";
    public static final String CONFIG_PATTERN = "subjAltExtPattern_";
    public static final String CONFIG_SOURCE = "subjAltExtSource_";
    public static final String CONFIG_SOURCE_UUID4 = "UUID4";

    public static final String CONFIG_OLD_TYPE = "subjAltExtType";
    public static final String CONFIG_OLD_PATTERN = "subjAltExtPattern";

    public static final String VAL_CRITICAL = "subjAltNameExtCritical";
    public static final String VAL_GENERAL_NAMES = "subjAltNames";

    private static final String GN_ENABLE = "Enable";
    private static final String GN_TYPE = "Pattern Type";
    private static final String GN_PATTERN = "Pattern";

    private static final int DEF_NUM_GN = 1;
    private static final int MAX_NUM_GN = 100;

    public SubjectAltNameExtDefault() {
        super();
    }

    protected int getNumGNs() {
        int num = DEF_NUM_GN;
        String numGNs = getConfig(CONFIG_NUM_GNS);

        if (numGNs != null) {
            try {
                num = Integer.parseInt(numGNs);
            } catch (NumberFormatException e) {
                // ignore
            }
        }

        if (num >= MAX_NUM_GN)
            num = DEF_NUM_GN;
        return num;
    }

    public void init(IProfile profile, IConfigStore config)
            throws EProfileException {

        super.init(profile, config);
        refreshConfigAndValueNames();
        // migrate old parameters to new parameters
        String old_type = null;
        String old_pattern = null;
        IConfigStore paramConfig = config.getSubStore("params");
        try {
            if (paramConfig != null) {
                old_type = paramConfig.getString(CONFIG_OLD_TYPE);
            }
        } catch (EBaseException e) {
            // nothing to do here
        }
        CMS.debug("SubjectAltNameExtDefault: Upgrading old_type=" +
                old_type);
        try {
            if (paramConfig != null) {
                old_pattern = paramConfig.getString(CONFIG_OLD_PATTERN);
            }
        } catch (EBaseException e) {
            // nothing to do here
        }
        CMS.debug("SubjectAltNameExtDefault: Upgrading old_pattern=" +
                old_pattern);
        if (old_type != null && old_pattern != null) {
            CMS.debug("SubjectAltNameExtDefault: Upgrading");
            try {
                paramConfig.putString(CONFIG_NUM_GNS, "1");
                paramConfig.putString(CONFIG_GN_ENABLE + "0", "true");
                paramConfig.putString(CONFIG_TYPE + "0", old_type);
                paramConfig.putString(CONFIG_PATTERN + "0", old_pattern);
                paramConfig.remove(CONFIG_OLD_TYPE);
                paramConfig.remove(CONFIG_OLD_PATTERN);
                profile.getConfigStore().commit(true);
            } catch (Exception e) {
                CMS.debug("SubjectAltNameExtDefault: Failed to upgrade " + e);
            }
        }
    }

    public void setConfig(String name, String value)
            throws EPropertyException {
        int num = 0;
        if (name.equals(CONFIG_NUM_GNS)) {
            try {
                num = Integer.parseInt(value);

                if (num >= MAX_NUM_GN || num < 0) {
                    throw new EPropertyException(CMS.getUserMessage(
                            "CMS_INVALID_PROPERTY", CONFIG_NUM_GNS));
                }

            } catch (Exception e) {
                throw new EPropertyException(CMS.getUserMessage(
                            "CMS_INVALID_PROPERTY", CONFIG_NUM_GNS));
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
        addValueName(VAL_GENERAL_NAMES);

        addConfigName(CONFIG_CRITICAL);
        int num = getNumGNs();
        addConfigName(CONFIG_NUM_GNS);
        for (int i = 0; i < num; i++) {
            addConfigName(CONFIG_TYPE + i);
            addConfigName(CONFIG_PATTERN + i);
            addConfigName(CONFIG_GN_ENABLE + i);
        }
    }

    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        if (name.equals(CONFIG_CRITICAL)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_CRITICAL"));
        } else if (name.startsWith(CONFIG_TYPE)) {
            return new Descriptor(IDescriptor.CHOICE,
                    "RFC822Name,DNSName,DirectoryName,EDIPartyName,URIName,IPAddress,OIDName,OtherName",
                    "RFC822Name",
                    CMS.getUserMessage(locale,
                            "CMS_PROFILE_SUBJECT_ALT_NAME_TYPE"));
        } else if (name.startsWith(CONFIG_PATTERN)) {
            return new Descriptor(IDescriptor.STRING, null,
                    null,
                    CMS.getUserMessage(locale,
                            "CMS_PROFILE_SUBJECT_ALT_NAME_PATTERN"));
        } else if (name.startsWith(CONFIG_GN_ENABLE)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_GN_ENABLE"));
        } else if (name.startsWith(CONFIG_NUM_GNS)) {
            return new Descriptor(IDescriptor.INTEGER, null,
                    "1",
                    CMS.getUserMessage(locale, "CMS_PROFILE_NUM_GNS"));
        }

        return null;
    }

    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(VAL_CRITICAL)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_CRITICAL"));
        } else if (name.equals(VAL_GENERAL_NAMES)) {
            return new Descriptor(IDescriptor.STRING_LIST, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_GENERAL_NAMES"));
        } else {
            return null;
        }
    }

    public void setValue(String name, Locale locale,
            X509CertInfo info, String value)
            throws EPropertyException {
        try {
            SubjectAlternativeNameExtension ext = null;

            if (name == null) {
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
            }

            ext =
                        (SubjectAlternativeNameExtension)
                        getExtension(PKIXExtensions.SubjectAlternativeName_Id.toString(), info);

            if (ext == null) {
                populate(null, info);
            }

            if (name.equals(VAL_CRITICAL)) {
                ext =
                        (SubjectAlternativeNameExtension)
                        getExtension(PKIXExtensions.SubjectAlternativeName_Id.toString(), info);

                if (ext == null) {
                    // it is ok, the extension is never populated or delted
                    return;
                }
                boolean critical = Boolean.valueOf(value).booleanValue();

                ext.setCritical(critical);
            } else if (name.equals(VAL_GENERAL_NAMES)) {
                ext =
                        (SubjectAlternativeNameExtension)
                        getExtension(PKIXExtensions.SubjectAlternativeName_Id.toString(), info);

                if (ext == null) {
                    // it is ok, the extension is never populated or delted
                    return;
                }
                if (value.equals("")) {
                    // if value is empty, do not add this extension
                    deleteExtension(PKIXExtensions.SubjectAlternativeName_Id.toString(), info);
                    return;
                }
                GeneralNames gn = new GeneralNames();
                StringTokenizer st = new StringTokenizer(value, "\r\n");

                while (st.hasMoreTokens()) {
                    String gname = st.nextToken();
                    CMS.debug("SubjectAltNameExtDefault: setValue GN:" + gname);

                    if (!isGeneralNameValid(gname)) {
                        continue;
                    }
                    GeneralNameInterface n = parseGeneralName(gname);
                    if (n != null) {
                        gn.addElement(n);
                    }
                }
                if (gn.size() == 0) {
                    CMS.debug("GN size is zero");
                    deleteExtension(PKIXExtensions.SubjectAlternativeName_Id.toString(), info);
                    return;
                } else {
                    CMS.debug("GN size is non zero (" + gn.size() + ")");
                    ext.set(SubjectAlternativeNameExtension.SUBJECT_NAME, gn);
                }
            } else {
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
            }
            replaceExtension(
                    PKIXExtensions.SubjectAlternativeName_Id.toString(),
                    ext, info);
        } catch (IOException e) {
            CMS.debug("SubjectAltNameExtDefault: setValue " + e.toString());
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        } catch (EProfileException e) {
            CMS.debug("SubjectAltNameExtDefault: setValue " + e.toString());
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
    }

    public String getValue(String name, Locale locale,
            X509CertInfo info)
            throws EPropertyException {
        try {
            if (name == null) {
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
            }

            SubjectAlternativeNameExtension ext =
                    (SubjectAlternativeNameExtension)
                    getExtension(PKIXExtensions.SubjectAlternativeName_Id.toString(), info);

            if (ext == null) {
                try {
                    populate(null, info);

                } catch (EProfileException e) {
                    throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
                }

            }

            if (name.equals(VAL_CRITICAL)) {
                ext =
                        (SubjectAlternativeNameExtension)
                        getExtension(PKIXExtensions.SubjectAlternativeName_Id.toString(), info);

                if (ext == null) {
                    return null;
                }
                if (ext.isCritical()) {
                    return "true";
                } else {
                    return "false";
                }
            } else if (name.equals(VAL_GENERAL_NAMES)) {
                ext =
                        (SubjectAlternativeNameExtension)
                        getExtension(PKIXExtensions.SubjectAlternativeName_Id.toString(), info);
                if (ext == null) {
                    return null;
                }

                GeneralNames names = (GeneralNames)
                        ext.get(SubjectAlternativeNameExtension.SUBJECT_NAME);
                StringBuffer sb = new StringBuffer();
                Enumeration<GeneralNameInterface> e = names.elements();

                while (e.hasMoreElements()) {
                    GeneralNameInterface gn = e.nextElement();

                    if (!sb.toString().equals("")) {
                        sb.append("\r\n");
                    }
                    sb.append(toGeneralNameString(gn));
                    CMS.debug("SubjectAltNameExtDefault: getValue append GN:" + toGeneralNameString(gn));
                }
                return sb.toString();
            } else {
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
            }
        } catch (IOException e) {
            CMS.debug("SubjectAltNameExtDefault: getValue " +
                    e.toString());
        }
        return null;
    }

    /*
     * returns text that goes into description for this extension on
     * a profile
     */
    public String getText(Locale locale) {
        StringBuffer sb = new StringBuffer();
        int num = getNumGNs();

        for (int i = 0; i < num; i++) {
            sb.append("Record #");
            sb.append(i);
            sb.append("{");
            sb.append(GN_PATTERN + ":");
            sb.append(getConfig(CONFIG_PATTERN + i));
            sb.append(",");
            sb.append(GN_TYPE + ":");
            sb.append(getConfig(CONFIG_TYPE + i));
            sb.append(",");
            sb.append(GN_ENABLE + ":");
            sb.append(getConfig(CONFIG_GN_ENABLE + i));
            sb.append("}");
        }
        ;

        return CMS.getUserMessage(locale, "CMS_PROFILE_DEF_SUBJECT_ALT_NAME_EXT", getConfig(CONFIG_CRITICAL),
                sb.toString());
    }

    /**
     * Populates the request with this policy default.
     */
    public void populate(IRequest request, X509CertInfo info)
            throws EProfileException {
        SubjectAlternativeNameExtension ext = null;

        try {
            /* read from config file*/
            ext = createExtension(request);

        } catch (IOException e) {
            CMS.debug("SubjectAltNameExtDefault: populate " + e.toString());
        }
        if (ext != null) {
            addExtension(PKIXExtensions.SubjectAlternativeName_Id.toString(),
                    ext, info);
        } else {
            CMS.debug("SubjectAltNameExtDefault: populate sees no extension.  get out");
        }
    }

    public SubjectAlternativeNameExtension createExtension(IRequest request)
            throws IOException {
        SubjectAlternativeNameExtension ext = null;
        int num = getNumGNs();

        boolean critical = Boolean.valueOf(
                getConfig(CONFIG_CRITICAL)).booleanValue();

        GeneralNames gn = new GeneralNames();
        int count = 0; // # of actual gnames
        for (int i = 0; i < num; i++) {
            String enable = getConfig(CONFIG_GN_ENABLE + i);
            if (enable != null && enable.equals("true")) {
                CMS.debug("SubjectAltNameExtDefault: createExtension i=" + i);

                String pattern = getConfig(CONFIG_PATTERN + i);
                if (pattern == null || pattern.equals("")) {
                    pattern = " ";
                }

                if (!pattern.equals("")) {
                    String gname = "";

                    // cfu - see if this is server-generated (e.g. UUID4)
                    // to use this feature, use $server.source$ in pattern
                    String source = getConfig(CONFIG_SOURCE + i);
                    String type = getConfig(CONFIG_TYPE + i);
                    if ((source != null) && (!source.equals(""))) {
                        if (type.equalsIgnoreCase("OtherName")) {
                            CMS.debug("SubjectAlternativeNameExtension: using " +
                                    source + " as gn");
                            if (source.equals(CONFIG_SOURCE_UUID4)) {
                                UUID randUUID = UUID.randomUUID();
                                // call the mapPattern that does server-side gen
                                // request is not used, but needed for the substitute
                                // function
                                if (request != null) {
                                    gname = mapPattern(randUUID.toString(), request, pattern);
                                }
                            } else { //expand more server-gen types here
                                CMS.debug("SubjectAltNameExtDefault: createExtension - unsupported server-generated type: "
                                        + source + ". Supported: UUID4");
                                continue;
                            }
                        } else {
                            CMS.debug("SubjectAltNameExtDefault: createExtension - source is only supported for subjAltExtType OtherName");
                            continue;
                        }
                    } else {
                        if (request != null) {
                            gname = mapPattern(request, pattern);
                        }
                    }

                    if (gname.equals("")) {
                        CMS.debug("gname is empty, not added");
                        continue;
                    }
                    CMS.debug("SubjectAltNameExtDefault: createExtension got gname=" + gname);

                    GeneralNameInterface n = parseGeneralName(type + ":" + gname);

                    CMS.debug("adding gname: " + gname);
                    if (n != null) {
                        CMS.debug("SubjectAlternativeNameExtension: n not null");
                        gn.addElement(n);
                        count++;
                    } else {
                        CMS.debug("SubjectAlternativeNameExtension: n null");
                    }
                }
            }
        } //for

        if (count != 0) {
            try {
                ext = new SubjectAlternativeNameExtension();
            } catch (Exception e) {
                CMS.debug(e.toString());
                throw new IOException(e.toString());
            }
            ext.set(SubjectAlternativeNameExtension.SUBJECT_NAME, gn);
            ext.setCritical(critical);
        } else {
            CMS.debug("count is 0");
        }
        return ext;
    }

    public String mapPattern(IRequest request, String pattern)
            throws IOException {
        Pattern p = new Pattern(pattern);
        IAttrSet attrSet = null;
        if (request != null) {
            attrSet = request.asIAttrSet();
        }
        return p.substitute("request", attrSet);
    }

    // for server-side generated values
    public String mapPattern(String val, IRequest request, String pattern)
            throws IOException {
        Pattern p = new Pattern(pattern);
        IAttrSet attrSet = null;
        if (request != null) {
            attrSet = request.asIAttrSet();
        }
        try {
            attrSet.set("source", val);
        } catch (Exception e) {
            CMS.debug("SubjectAlternativeNameExtension: mapPattern source " + e.toString());
        }

        return p.substitute("server", attrSet);
    }
}
