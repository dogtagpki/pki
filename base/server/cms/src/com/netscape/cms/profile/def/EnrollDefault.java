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
import java.util.NoSuchElementException;
import java.util.StringTokenizer;
import java.util.Vector;

import netscape.security.extensions.KerberosName;
import netscape.security.util.DerInputStream;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;
import netscape.security.util.ObjectIdentifier;
import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.DNSName;
import netscape.security.x509.EDIPartyName;
import netscape.security.x509.Extension;
import netscape.security.x509.GeneralName;
import netscape.security.x509.GeneralNameInterface;
import netscape.security.x509.IPAddressName;
import netscape.security.x509.OIDName;
import netscape.security.x509.OtherName;
import netscape.security.x509.RFC822Name;
import netscape.security.x509.URIName;
import netscape.security.x509.X500Name;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IAttrSet;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IPrettyPrintFormat;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.pattern.Pattern;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.ICertInfoPolicyDefault;
import com.netscape.certsrv.profile.IEnrollProfile;
import com.netscape.certsrv.profile.IPolicyDefault;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.profile.common.EnrollProfile;

/**
 * This class implements an enrollment default policy.
 *
 * @version $Revision$, $Date$
 */
public abstract class EnrollDefault implements IPolicyDefault, ICertInfoPolicyDefault {

    public static final String PROP_NAME = "name";

    public static final String GN_RFC822_NAME = "RFC822Name";
    public static final String GN_DNS_NAME = "DNSName";
    public static final String GN_URI_NAME = "URIName";
    public static final String GN_IP_NAME = "IPAddressName";
    public static final String GN_DIRECTORY_NAME = "DirectoryName";
    public static final String GN_EDI_NAME = "EDIPartyName";
    public static final String GN_ANY_NAME = "OtherName";
    public static final String GN_OID_NAME = "OIDName";

    protected IConfigStore mConfig = null;
    protected Vector<String> mConfigNames = new Vector<String>();
    protected Vector<String> mValueNames = new Vector<String>();

    public EnrollDefault() {
    }

    public Enumeration<String> getConfigNames() {
        return mConfigNames.elements();
    }

    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        return null;
    }

    public void addConfigName(String name) {
        mConfigNames.addElement(name);
    }

    public void setConfig(String name, String value)
            throws EPropertyException {
        if (mConfig.getSubStore("params") == null) {
            //
        } else {
            mConfig.getSubStore("params").putString(name, value);
        }
    }

    public String getConfig(String name) {
        try {
            if (mConfig == null)
                return null;
            if (mConfig.getSubStore("params") != null) {
                return mConfig.getSubStore("params").getString(name);
            }
        } catch (EBaseException e) {
        }
        return "";
    }

    public void init(IProfile profile, IConfigStore config)
            throws EProfileException {
        mConfig = config;
    }

    /**
     * Retrieves the localizable description of this policy.
     *
     * @param locale locale of the end user
     * @return localized description of this default policy
     */
    public abstract String getText(Locale locale);

    public IConfigStore getConfigStore() {
        return mConfig;
    }

    public String getName(Locale locale) {
        try {
            return mConfig.getString(PROP_NAME);
        } catch (EBaseException e) {
            return null;
        }
    }

    /**
     * Populates attributes into the certificate template.
     *
     * @param request enrollment request
     * @param info certificate template
     * @exception EProfileException failed to populate attributes
     *                into request
     */
    public abstract void populate(IRequest request, X509CertInfo info)
            throws EProfileException;

    /**
     * Sets values from the approval page into certificate template.
     *
     * @param name name of the attribute
     * @param locale user locale
     * @param info certificate template
     * @param value attribute value
     * @exception EProfileException failed to set attributes
     *                into request
     */
    public abstract void setValue(String name, Locale locale,
            X509CertInfo info, String value)
            throws EPropertyException;

    /**
     * Retrieves certificate template values and returns them to
     * the approval page.
     *
     * @param name name of the attribute
     * @param locale user locale
     * @param info certificate template
     * @exception EProfileException failed to get attributes
     *                from request
     */
    public abstract String getValue(String name, Locale locale,
            X509CertInfo info)
            throws EPropertyException;

    /**
     * Populates the request with this policy default.
     *
     * The current implementation extracts enrollment specific attributes
     * and calls the populate() method of the subclass.
     *
     * @param request request to be populated
     * @exception EProfileException failed to populate
     */
    public void populate(IRequest request)
            throws EProfileException {
        String name = getClass().getName();

        name = name.substring(name.lastIndexOf('.') + 1);
        CMS.debug(name + ": populate start");
        X509CertInfo info =
                request.getExtDataInCertInfo(IEnrollProfile.REQUEST_CERTINFO);

        populate(request, info);

        request.setExtData(IEnrollProfile.REQUEST_CERTINFO, info);
        CMS.debug(name + ": populate end");
    }

    public void addValueName(String name) {
        mValueNames.addElement(name);
    }

    public Enumeration<String> getValueNames() {
        return mValueNames.elements();
    }

    public IDescriptor getValueDescriptor(String name) {
        return null;
    }

    /**
     * Sets the value of the given value property by name.
     *
     * The current implementation extracts enrollment specific attributes
     * and calls the setValue() method of the subclass.
     *
     * @param name name of property
     * @param locale locale of the end user
     * @param request request
     * @param value value to be set in the given request
     * @exception EPropertyException failed to set property
     */
    public void setValue(String name, Locale locale, IRequest request,
            String value)
            throws EPropertyException {
        X509CertInfo info =
                request.getExtDataInCertInfo(IEnrollProfile.REQUEST_CERTINFO);

        setValue(name, locale, info, value);

        request.setExtData(IEnrollProfile.REQUEST_CERTINFO, info);
    }

    /**
     * Retrieves the value of the given value
     * property by name.
     *
     * The current implementation extracts enrollment specific attributes
     * and calls the getValue() method of the subclass.
     *
     * @param name name of property
     * @param locale locale of the end user
     * @param request request
     * @exception EPropertyException failed to get property
     */
    public String getValue(String name, Locale locale, IRequest request)
            throws EPropertyException {
        X509CertInfo info =
                request.getExtDataInCertInfo(IEnrollProfile.REQUEST_CERTINFO);

        String value = getValue(name, locale, info);
        request.setExtData(IEnrollProfile.REQUEST_CERTINFO, info);
        return value;
    }

    public String toHexString(byte data[]) {
        IPrettyPrintFormat pp = CMS.getPrettyPrintFormat(":");
        String s = pp.toHexString(data, 0, 16);
        StringTokenizer st = new StringTokenizer(s, "\n");
        StringBuffer buffer = new StringBuffer();

        while (st.hasMoreTokens()) {
            buffer.append(st.nextToken());
            buffer.append("\\n");
        }
        return buffer.toString();
    }

    protected void refreshConfigAndValueNames() {
        mConfigNames.removeAllElements();
        mValueNames.removeAllElements();
    }

    protected void deleteExtension(String name, X509CertInfo info) {
        CertificateExtensions exts = null;

        try {
            exts = (CertificateExtensions)
                    info.get(X509CertInfo.EXTENSIONS);
            if (exts == null)
                return;
            Enumeration<String> e = exts.getNames();

            while (e.hasMoreElements()) {
                String n = e.nextElement();
                Extension ext = (Extension) exts.get(n);

                if (ext.getExtensionId().toString().equals(name)) {
                    exts.delete(n);
                }
            }
        } catch (Exception e) {
            CMS.debug(e.toString());
        }
    }

    protected Extension getExtension(String name, X509CertInfo info) {
        CertificateExtensions exts = null;

        try {
            exts = (CertificateExtensions)
                    info.get(X509CertInfo.EXTENSIONS);
        } catch (Exception e) {
            CMS.debug("EnrollDefault: getExtension " + e.toString());
        }
        if (exts == null)
            return null;
        return getExtension(name, exts);
    }

    protected Extension getExtension(String name, CertificateExtensions exts) {
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

    protected void addExtension(String name, Extension ext, X509CertInfo info)
            throws EProfileException {
        if (ext == null) {
            throw new EProfileException("extension not found");
        }
        CertificateExtensions exts = null;

        Extension alreadyPresentExtension = getExtension(name, info);

        if (alreadyPresentExtension != null) {
            String eName = ext.toString();
            CMS.debug("EnrollDefault.addExtension: duplicate extension attempted! Name:  " + eName);
            throw new EProfileException(CMS.getUserMessage("CMS_PROFILE_DUPLICATE_EXTENSION", eName));
        }

        try {
            exts = (CertificateExtensions)
                    info.get(X509CertInfo.EXTENSIONS);
        } catch (Exception e) {
            CMS.debug("EnrollDefault: " + e.toString());
        }
        if (exts == null) {
            throw new EProfileException("extensions not found");
        }
        try {
            exts.set(name, ext);
        } catch (IOException e) {
            CMS.debug("EnrollDefault: " + e.toString());
        }
    }

    protected void replaceExtension(String name, Extension ext, X509CertInfo info)
            throws EProfileException {
        deleteExtension(name, info);
        addExtension(name, ext, info);
    }

    protected boolean isOptional(String value) {
        return value.equals("");
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

    protected boolean isGeneralNameValid(String name) {
        if (name == null)
            return false;
        int pos = name.indexOf(':');
        if (pos == -1)
            return false;
        String nameValue = name.substring(pos + 1).trim();
        if (nameValue.equals(""))
            return false;
        return true;
    }

    protected GeneralNameInterface parseGeneralName(String name)
            throws IOException {
        int pos = name.indexOf(':');
        if (pos == -1)
            return null;
        String nameType = name.substring(0, pos).trim();
        String nameValue = name.substring(pos + 1).trim();
        return parseGeneralName(nameType, nameValue);
    }

    protected boolean isGeneralNameType(String nameType) {
        if (nameType.equalsIgnoreCase("RFC822Name")) {
            return true;
        }
        if (nameType.equalsIgnoreCase("DNSName")) {
            return true;
        }
        if (nameType.equalsIgnoreCase("x400")) {
            return true;
        }
        if (nameType.equalsIgnoreCase("DirectoryName")) {
            return true;
        }
        if (nameType.equalsIgnoreCase("EDIPartyName")) {
            return true;
        }
        if (nameType.equalsIgnoreCase("URIName")) {
            return true;
        }
        if (nameType.equalsIgnoreCase("IPAddress")) {
            return true;
        }
        if (nameType.equalsIgnoreCase("OIDName")) {
            return true;
        }
        if (nameType.equalsIgnoreCase("OtherName")) {
            return true;
        }
        return false;
    }

    protected GeneralNameInterface parseGeneralName(String nameType, String nameValue)
            throws IOException {
        if (nameType.equalsIgnoreCase("RFC822Name")) {
            return new RFC822Name(nameValue);
        }
        if (nameType.equalsIgnoreCase("DNSName")) {
            return new DNSName(nameValue);
        }
        if (nameType.equalsIgnoreCase("x400")) {
            // XXX
        }
        if (nameType.equalsIgnoreCase("DirectoryName")) {
            return new X500Name(nameValue);
        }
        if (nameType.equalsIgnoreCase("EDIPartyName")) {
            return new EDIPartyName(nameValue);
        }
        if (nameType.equalsIgnoreCase("URIName")) {
            return new URIName(nameValue);
        }
        if (nameType.equalsIgnoreCase("IPAddress")) {
            CMS.debug("IP Value:" + nameValue);
            if (nameValue.indexOf('/') != -1) {
                // CIDR support for NameConstraintsExt
                StringTokenizer st = new StringTokenizer(nameValue, "/");
                String addr = st.nextToken();
                String netmask = st.nextToken();
                CMS.debug("addr:" + addr + " netmask: " + netmask);
                return new IPAddressName(addr, netmask);
            } else {
                return new IPAddressName(nameValue);
            }
        }
        if (nameType.equalsIgnoreCase("OIDName")) {
            try {
                // check if OID
                new ObjectIdentifier(nameValue);
            } catch (Exception e) {
                return null;
            }
            return new OIDName(nameValue);
        }
        if (nameType.equals("OtherName")) {
            if (nameValue == null || nameValue.length() == 0)
                nameValue = " ";
            if (nameValue.startsWith("(PrintableString)")) {
                // format: OtherName: (PrintableString)oid,value
                int pos0 = nameValue.indexOf(')');
                int pos1 = nameValue.indexOf(',');
                if (pos1 == -1)
                    return null;
                String on_oid = nameValue.substring(pos0 + 1, pos1).trim();
                String on_value = nameValue.substring(pos1 + 1).trim();
                if (isValidOID(on_oid)) {
                    return new OtherName(new ObjectIdentifier(on_oid), DerValue.tag_PrintableString, on_value);
                } else {
                    return null;
                }
            } else if (nameValue.startsWith("(KerberosName)")) {
                // Syntax: (KerberosName)Realm|NameType|NameString(s)
                int pos0 = nameValue.indexOf(')');
                int pos1 = nameValue.indexOf('|');
                int pos2 = nameValue.lastIndexOf('|');
                String realm = nameValue.substring(pos0 + 1, pos1).trim();
                String name_type = nameValue.substring(pos1 + 1, pos2).trim();
                String name_strings = nameValue.substring(pos2 + 1).trim();
                Vector<String> strings = new Vector<String>();
                StringTokenizer st = new StringTokenizer(name_strings, ",");
                while (st.hasMoreTokens()) {
                    strings.addElement(st.nextToken());
                }
                KerberosName name = new KerberosName(realm,
                        Integer.parseInt(name_type), strings);
                // krb5 OBJECT IDENTIFIER ::= { iso (1)
                //                    org (3)
                //                    dod (6)
                //                    internet (1)
                //                    security (5)
                //                    kerberosv5 (2) }
                // krb5PrincipalName OBJECT IDENTIFIER ::= { krb5 2 }
                return new OtherName(KerberosName.KRB5_PRINCIPAL_NAME,
                        name.toByteArray());
            } else if (nameValue.startsWith("(IA5String)")) {
                int pos0 = nameValue.indexOf(')');
                int pos1 = nameValue.indexOf(',');
                if (pos1 == -1)
                    return null;
                String on_oid = nameValue.substring(pos0 + 1, pos1).trim();
                String on_value = nameValue.substring(pos1 + 1).trim();
                if (isValidOID(on_oid)) {
                    return new OtherName(new ObjectIdentifier(on_oid), DerValue.tag_IA5String, on_value);
                } else {
                    return null;
                }
            } else if (nameValue.startsWith("(UTF8String)")) {
                int pos0 = nameValue.indexOf(')');
                int pos1 = nameValue.indexOf(',');
                if (pos1 == -1)
                    return null;
                String on_oid = nameValue.substring(pos0 + 1, pos1).trim();
                String on_value = nameValue.substring(pos1 + 1).trim();
                if (isValidOID(on_oid)) {
                    return new OtherName(new ObjectIdentifier(on_oid), DerValue.tag_UTF8String, on_value);
                } else {
                    return null;
                }
            } else if (nameValue.startsWith("(BMPString)")) {
                int pos0 = nameValue.indexOf(')');
                int pos1 = nameValue.indexOf(',');
                if (pos1 == -1)
                    return null;
                String on_oid = nameValue.substring(pos0 + 1, pos1).trim();
                String on_value = nameValue.substring(pos1 + 1).trim();
                if (isValidOID(on_oid)) {
                    return new OtherName(new ObjectIdentifier(on_oid), DerValue.tag_BMPString, on_value);
                } else {
                    return null;
                }
            } else if (nameValue.startsWith("(Any)")) {
                int pos0 = nameValue.indexOf(')');
                int pos1 = nameValue.indexOf(',');
                if (pos1 == -1)
                    return null;
                String on_oid = nameValue.substring(pos0 + 1, pos1).trim();
                String on_value = nameValue.substring(pos1 + 1).trim();
                if (isValidOID(on_oid)) {
                    CMS.debug("OID: " + on_oid + " Value:" + on_value);
                    return new OtherName(new ObjectIdentifier(on_oid), getBytes(on_value));
                } else {
                    CMS.debug("Invalid OID " + on_oid);
                    return null;
                }
            } else {
                return null;
            }
        }
        return null;
    }

    /**
     * Converts string containing pairs of characters in the range of '0'
     * to '9', 'a' to 'f' to an array of bytes such that each pair of
     * characters in the string represents an individual byte
     */
    public byte[] getBytes(String string) {
        if (string == null)
            return null;
        int stringLength = string.length();
        if ((stringLength == 0) || ((stringLength % 2) != 0))
            return null;
        byte[] bytes = new byte[(stringLength / 2)];
        for (int i = 0, b = 0; i < stringLength; i += 2, ++b) {
            String nextByte = string.substring(i, (i + 2));
            bytes[b] = (byte) Integer.parseInt(nextByte, 0x10);
        }
        return bytes;
    }

    /**
     * Check if a object identifier in string form is valid,
     * that is a string in the form n.n.n.n and der encode and decode-able.
     *
     * @param oid object identifier string.
     * @return true if the oid is valid
     */
    public boolean isValidOID(String oid) {
        ObjectIdentifier v = null;
        try {
            v = ObjectIdentifier.getObjectIdentifier(oid);
        } catch (Exception e) {
            return false;
        }
        if (v == null)
            return false;

        // if the OID isn't valid (ex. n.n) the error isn't caught til
        // encoding time leaving a bad request in the request queue.
        try (DerOutputStream derOut = new DerOutputStream()) {

            derOut.putOID(v);
            new ObjectIdentifier(new DerInputStream(derOut.toByteArray()));
        } catch (Exception e) {
            return false;
        }
        return true;
    }

    protected String buildRecords(Vector<NameValuePairs> recs) throws EPropertyException {
        StringBuffer sb = new StringBuffer();

        for (int i = 0; i < recs.size(); i++) {
            NameValuePairs pairs = recs.elementAt(i);

            sb.append("Record #");
            sb.append(i);
            sb.append("\r\n");

            for (String key : pairs.keySet()) {
                String val = pairs.get(key);

                sb.append(key);
                sb.append(":");
                sb.append(val);
                sb.append("\r\n");
            }
            sb.append("\r\n");

        }
        return sb.toString();
    }

    protected Vector<NameValuePairs> parseRecords(String value) throws EPropertyException {
        StringTokenizer st = new StringTokenizer(value, "\r\n");
        int num = 0;
        Vector<NameValuePairs> v = new Vector<NameValuePairs>();
        NameValuePairs nvps = null;

        while (st.hasMoreTokens()) {
            String token = st.nextToken();

            if (token.equals("Record #" + num)) {
                CMS.debug("parseRecords: Record" + num);
                nvps = new NameValuePairs();
                v.addElement(nvps);
                try {
                    token = st.nextToken();
                } catch (NoSuchElementException e) {
                    v.removeElementAt(num);
                    CMS.debug(e.toString());
                    return v;
                }
                num++;
            }

            if (nvps == null)
                throw new EPropertyException("Bad Input Format");

            int pos = token.indexOf(":");

            if (pos <= 0) {
                CMS.debug("parseRecords: No colon found in the input line");
                throw new EPropertyException("Bad Input Format");
            } else {
                if (pos == (token.length() - 1)) {
                    nvps.put(token.substring(0, pos), "");
                } else {
                    nvps.put(token.substring(0, pos), token.substring(pos + 1));
                }
            }
        }

        return v;
    }

    protected String getGeneralNameType(GeneralName gn)
            throws EPropertyException {
        int type = gn.getType();

        if (type == GeneralNameInterface.NAME_RFC822)
            return "RFC822Name";
        else if (type == GeneralNameInterface.NAME_DNS)
            return "DNSName";
        else if (type == GeneralNameInterface.NAME_URI)
            return "URIName";
        else if (type == GeneralNameInterface.NAME_IP)
            return "IPAddress";
        else if (type == GeneralNameInterface.NAME_DIRECTORY)
            return "DirectoryName";
        else if (type == GeneralNameInterface.NAME_EDI)
            return "EDIPartyName";
        else if (type == GeneralNameInterface.NAME_ANY)
            return "OtherName";
        else if (type == GeneralNameInterface.NAME_OID)
            return "OIDName";

        throw new EPropertyException("Unsupported type: " + type);
    }

    protected String getGeneralNameValue(GeneralName gn) throws EPropertyException {
        String s = gn.toString();
        int type = gn.getType();

        if (type == GeneralNameInterface.NAME_DIRECTORY)
            return s;
        else {
            int pos = s.indexOf(":");

            if (pos <= 0)
                throw new EPropertyException("Badly formatted general name: " + s);
            else {
                return s.substring(pos + 1).trim();
            }
        }
    }

    public Locale getLocale(IRequest request) {
        Locale locale = null;

        if (request == null)
            return null;

        String language = request.getExtDataInString(
                EnrollProfile.REQUEST_LOCALE);
        if (language != null) {
            locale = new Locale(language);
        }
        return locale;
    }

    public String toGeneralNameString(GeneralNameInterface gn) {
        int type = gn.getType();
        // Sun's General Name is not consistent, so we need
        // to do a special case for directory string
        if (type == GeneralNameInterface.NAME_DIRECTORY) {
            return "DirectoryName: " + gn.toString();
        }
        return gn.toString();
    }

    protected String mapPattern(IRequest request, String pattern)
            throws IOException {
        Pattern p = new Pattern(pattern);
        IAttrSet attrSet = null;
        if (request != null) {
            attrSet = request.asIAttrSet();
        }
        return p.substitute2("request", attrSet);
    }
}
