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
package com.netscape.cms.policy.extensions;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Locale;
import java.util.Vector;

import netscape.security.extensions.GenericASN1Extension;
import netscape.security.util.ObjectIdentifier;
import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.CertificateVersion;
import netscape.security.x509.OIDMap;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.policy.IEnrollmentPolicy;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.PolicyResult;
import com.netscape.cms.policy.APolicyRule;

/**
 * Private Integer extension policy.
 * If this policy is enabled, it adds an Private Integer
 * extension to the certificate.
 *
 * The following listed sample configuration parameters:
 *
 * ca.Policy.impl.privateInteger.class=com.netscape.certsrv.policy.genericASNExt
 * ca.Policy.rule.genericASNExt.enable=true
 * ca.Policy.rule.genericASNExt.name=myIntegerExtension
 * ca.Policy.rule.genericASNExt.pattern={{{12}34}5}
 * ca.Policy.rule.genericASNExt.oid=280.230.123.1234.1
 * ca.Policy.rule.genericASNExt.critical=false
 * ca.Policy.rule.genericASNExt.attribute1.type=integer
 * ca.Policy.rule.genericASNExt.attribute1.source=value
 * ca.Policy.rule.genericASNExt.attribute1.value=9999
 * ca.Policy.rule.genericASNExt.attribute2.type=ia5string
 * ca.Policy.rule.genericASNExt.attribute2.source=value
 * ca.Policy.rule.genericASNExt.attribute2.value=hello
 * ca.Policy.rule.genericASNExt.attribute3.type=octetstring
 * ca.Policy.rule.genericASNExt.attribute3.source=value
 * ca.Policy.rule.genericASNExt.attribute3.value=hellohello
 * ca.Policy.rule.genericASNExt.attribute4.type=octetstring
 * ca.Policy.rule.genericASNExt.attribute4.source=file
 * ca.Policy.rule.genericASNExt.attribute4.value=c:/tmp/test.txt
 * ca.Policy.rule.genericASNExt.attribute5.type=
 * ca.Policy.rule.genericASNExt.attribute5.source=
 * ca.Policy.rule.genericASNExt.attribute5.value=
 * ca.Policy.rule.genericASNExt.implName=genericASNExt
 * ca.Policy.rule.genericASNExt.predicate=
 * <P>
 *
 * <PRE>
 * NOTE:  The Policy Framework has been replaced by the Profile Framework.
 * </PRE>
 * <P>
 *
 * @deprecated
 * @version $Revision$, $Date$
 */
public class GenericASN1Ext extends APolicyRule implements
        IEnrollmentPolicy, IExtendedPluginInfo {
    protected static final int MAX_ATTR = 10;

    protected static final String PROP_CRITICAL =
            "critical";
    protected static final String PROP_NAME =
            "name";
    protected static final String PROP_OID =
            "oid";
    protected static final String PROP_PATTERN =
            "pattern";
    protected static final String PROP_ATTRIBUTE =
            "attribute";
    protected static final String PROP_TYPE =
            "type";
    protected static final String PROP_SOURCE =
            "source";
    protected static final String PROP_VALUE =
            "value";
    protected static final String PROP_PREDICATE =
            "predicate";

    protected static final String PROP_ENABLE =
            "enable";

    public IConfigStore mConfig = null;

    private String pattern = null;

    public String[] getExtendedPluginInfo(Locale locale) {
        String s[] = {
                "enable" + ";boolean;Enable this policy",
                "predicate" + ";string;",
                PROP_CRITICAL + ";boolean;",
                PROP_NAME + ";string;Name for this extension.",
                PROP_OID + ";string;OID number for this extension. It should be unique.",
                PROP_PATTERN + ";string;Pattern for extension; {012}34",
                // Attribute 0
                PROP_ATTRIBUTE + "." + "0" + "." + PROP_TYPE
                    + ";choice(Integer,IA5String,OctetString,PrintableString,VisibleString,UTCTime,OID,Boolean);Attribute type for extension",
                PROP_ATTRIBUTE + "." + "0" + "." + PROP_SOURCE
                    + ";choice(Value,File);Data Source for the extension. You can specify the value here or file name has value.",
                PROP_ATTRIBUTE + "." + "0" + "." + PROP_VALUE
                    + ";string;If data source is 'value', specity value here. If data source is 'file', specify the file name with full path.",
                // Attribute 1
                PROP_ATTRIBUTE + "." + "1" + "." + PROP_TYPE
                    + ";choice(Integer,IA5String,OctetString,PrintableString,VisibleString,UTCTime,OID,Boolean);Attribute type for extension",
                PROP_ATTRIBUTE + "." + "1" + "." + PROP_SOURCE
                    + ";choice(Value,File);Data Source for the extension. You can specify the value here or file name has value.",
                PROP_ATTRIBUTE + "." + "1" + "." + PROP_VALUE
                    + ";string;If data source is 'value', specity value here. If data source is 'file', specify the file name with full path.",
                // Attribute 2
                PROP_ATTRIBUTE + "." + "2" + "." + PROP_TYPE
                    + ";choice(Integer,IA5String,OctetString,PrintableString,VisibleString,UTCTime,OID,Boolean);Attribute type for extension",
                PROP_ATTRIBUTE + "." + "2" + "." + PROP_SOURCE
                    + ";choice(Value,File);Data Source for the extension. You can specify the value here or file name has value.",
                PROP_ATTRIBUTE + "." + "2" + "." + PROP_VALUE
                    + ";string;If data source is 'value', specity value here. If data source is 'file', specify the file name with full path.",
                // Attribute 3
                PROP_ATTRIBUTE + "." + "3" + "." + PROP_TYPE
                    + ";choice(Integer,IA5String,OctetString,PrintableString,VisibleString,UTCTime,OID,Boolean);Attribute type for extension",
                PROP_ATTRIBUTE + "." + "3" + "." + PROP_SOURCE
                    + ";choice(Value,File);Data Source for the extension. You can specify the value here or file name has value.",
                PROP_ATTRIBUTE + "." + "3" + "." + PROP_VALUE
                    + ";string;If data source is 'value', specity value here. If data source is 'file', specify the file name with full path.",
                // Attribute 4
                PROP_ATTRIBUTE + "." + "4" + "." + PROP_TYPE
                    + ";choice(Integer,IA5String,OctetString,PrintableString,VisibleString,UTCTime,OID,Boolean);Attribute type for extension",
                PROP_ATTRIBUTE + "." + "4" + "." + PROP_SOURCE
                    + ";choice(Value,File);Data Source for the extension. You can specify the value here or file name has value.",
                PROP_ATTRIBUTE + "." + "4" + "." + PROP_VALUE
                    + ";string;If data source is 'value', specity value here. If data source is 'file', specify the file name with full path.",
                // Attribute 5
                PROP_ATTRIBUTE + "." + "5" + "." + PROP_TYPE
                    + ";choice(Integer,IA5String,OctetString,PrintableString,VisibleString,UTCTime,OID,Boolean);Attribute type for extension",
                PROP_ATTRIBUTE + "." + "5" + "." + PROP_SOURCE
                    + ";choice(Value,File);Data Source for the extension. You can specify the value here or file name has value.",
                PROP_ATTRIBUTE + "." + "5" + "." + PROP_VALUE
                    + ";string;If data source is 'value', specity value here. If data source is 'file', specify the file name with full path.",
                // Attribute 6
                PROP_ATTRIBUTE + "." + "6" + "." + PROP_TYPE
                    + ";choice(Integer,IA5String,OctetString,PrintableString,VisibleString,UTCTime,OID,Boolean);Attribute type for extension",
                PROP_ATTRIBUTE + "." + "6" + "." + PROP_SOURCE
                    + ";choice(Value,File);Data Source for the extension. You can specify the value here or file name has value.",
                PROP_ATTRIBUTE + "." + "6" + "." + PROP_VALUE
                    + ";string;If data source is 'value', specity value here. If data source is 'file', specify the file name with full path.",
                // Attribute 7
                PROP_ATTRIBUTE + "." + "7" + "." + PROP_TYPE
                    + ";choice(Integer,IA5String,OctetString,PrintableString,VisibleString,UTCTime,OID,Boolean);Attribute type for extension",
                PROP_ATTRIBUTE + "." + "7" + "." + PROP_SOURCE
                    + ";choice(Value,File);Data Source for the extension. You can specify the value here or file name has value.",
                PROP_ATTRIBUTE + "." + "7" + "." + PROP_VALUE
                    + ";string;If data source is 'value', specity value here. If data source is 'file', specify the file name with full path.",
                // Attribute 8
                PROP_ATTRIBUTE + "." + "8" + "." + PROP_TYPE
                    + ";choice(Integer,IA5String,OctetString,PrintableString,VisibleString,UTCTime,OID,Boolean);Attribute type for extension",
                PROP_ATTRIBUTE + "." + "8" + "." + PROP_SOURCE
                    + ";choice(Value,File);Data Source for the extension. You can specify the value here or file name has value.",
                PROP_ATTRIBUTE + "." + "8" + "." + PROP_VALUE
                    + ";string;If data source is 'value', specity value here. If data source is 'file', specify the file name with full path.",
                // Attribute 9
                PROP_ATTRIBUTE + "." + "9" + "." + PROP_TYPE
                    + ";choice(Integer,IA5String,OctetString,PrintableString,VisibleString,UTCTime,OID,Boolean);Attribute type for extension",
                PROP_ATTRIBUTE + "." + "9" + "." + PROP_SOURCE
                    + ";choice(Value,File);Data Source for the extension. You can specify the value here or file name has value.",
                PROP_ATTRIBUTE + "." + "9" + "." + PROP_VALUE
                    + ";string;If data source is 'value', specity value here. If data source is 'file', specify the file name with full path.",
                IExtendedPluginInfo.HELP_TOKEN +
                        ";configuration-policyrules-genericasn1ext",
                IExtendedPluginInfo.HELP_TEXT +
                        ";Adds Private extension based on ASN1. See manual"
            };

        return s;
    }

    public GenericASN1Ext() {
        NAME = "GenericASN1Ext";
        DESC = "Sets Generic extension for certificates";
    }

    /**
     * Initializes this policy rule.
     * <P>
     *
     * The entries may be of the form:
     *
     * ca.Policy.rule.<ruleName>.implName=genericASNExt ca.Policy.rule.<ruleName>.enable=true
     * ca.Policy.rule.<ruleName>.predicate=
     *
     * @param config The config store reference
     */
    public void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {
        mConfig = config;
        if (mConfig == null) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("POLICY_INIT_ERROR"));
            return;
        }

        boolean enable = mConfig.getBoolean(PROP_ENABLE, false);

        if (enable == false)
            return;

        String oid = mConfig.getString(PROP_OID, null);

        if ((oid == null) || (oid.length() == 0)) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("POLICY_INIT_ERROR"));
            return;
        }

        String name = mConfig.getString(PROP_NAME, null);

        if ((name == null) || (name.length() == 0)) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("POLICY_INIT_ERROR"));
            return;
        }

        try {
            if (File.separatorChar == '\\') {
                pattern = mConfig.getString(PROP_PATTERN, null);
                checkFilename(0);
            }
        } catch (IOException e) {
            log(ILogger.LL_FAILURE, "" + e.toString());
        } catch (EBaseException e) {
            log(ILogger.LL_FAILURE, "" + e.toString());
        }

        // Check OID value
        CMS.checkOID(name, oid);
        pattern = mConfig.getString(PROP_PATTERN, null);
        checkOID(0);

        try {
            ObjectIdentifier tmpid = new ObjectIdentifier(oid);

            if (OIDMap.getName(tmpid) == null)
                OIDMap.addAttribute("netscape.security.extensions.GenericASN1Extension", oid, name);
        } catch (CertificateException e) {
            log(ILogger.LL_FAILURE, "" + e.toString());
        }

    }

    // Check filename
    private int checkFilename(int index)
            throws IOException, EBaseException {
        String source = null;

        while (index < pattern.length()) {
            char ch = pattern.charAt(index);

            switch (ch) {
            case '{':
                index++;
                index = checkFilename(index);
                break;

            case '}':
                return index;

            default:
                source = mConfig.getString(PROP_ATTRIBUTE + "." + ch + "." + PROP_SOURCE, null);
                if ((source != null) && (source.equalsIgnoreCase("file"))) {
                    String oValue = mConfig.getString(PROP_ATTRIBUTE + "." + ch + "." + PROP_VALUE, null);
                    String nValue = oValue.replace('\\', '/');

                    mConfig.putString(PROP_ATTRIBUTE + "." + ch + "." + PROP_VALUE, nValue);
                    FileInputStream fis = new FileInputStream(nValue);
                    fis.close();
                }
            }
            index++;
        }

        return index;
    }

    // Check oid
    private int checkOID(int index)
            throws EBaseException {
        String type = null;
        String oid = null;

        while (index < pattern.length()) {
            char ch = pattern.charAt(index);

            switch (ch) {
            case '{':
                index++;
                index = checkOID(index);
                break;

            case '}':
                return index;

            default:
                type = mConfig.getString(PROP_ATTRIBUTE + "." + ch + "." + PROP_TYPE, null);
                if ((type != null) && (type.equalsIgnoreCase("OID"))) {
                    oid = mConfig.getString(PROP_ATTRIBUTE + "." + ch + "." + PROP_VALUE, null);
                    CMS.checkOID(oid, oid);
                }
            }
            index++;
        }

        return index;
    }

    /**
     * If this policy is enabled, add the private Integer
     * information extension to the certificate.
     * <P>
     *
     * @param req The request on which to apply policy.
     * @return The policy result object.
     */
    public PolicyResult apply(IRequest req) {
        PolicyResult res = PolicyResult.ACCEPTED;
        X509CertInfo certInfo;
        X509CertInfo[] ci = req.getExtDataInCertInfoArray(IRequest.CERT_INFO);

        if (ci == null) {
            setError(req, CMS.getUserMessage("CMS_POLICY_NO_CERT_INFO"), NAME);
            return PolicyResult.REJECTED; // unrecoverable error.
        }

        for (int j = 0; j < ci.length; j++) {

            certInfo = ci[j];
            if (certInfo == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CA_CERT_INFO_ERROR", ""));
                setError(req, CMS.getUserMessage("CMS_POLICY_UNEXPECTED_POLICY_ERROR"), NAME,
                        "Configuration Info Error");
                return PolicyResult.REJECTED; // unrecoverable error.
            }

            try {
                // Find the extensions in the certInfo
                CertificateExtensions extensions = (CertificateExtensions) certInfo.get(X509CertInfo.EXTENSIONS);

                if (extensions == null) {
                    // create extension if not exist
                    certInfo.set(X509CertInfo.VERSION,
                            new CertificateVersion(CertificateVersion.V3));
                    extensions = new CertificateExtensions();
                    certInfo.set(X509CertInfo.EXTENSIONS, extensions);
                } else {
                    //
                    // Remove any previousely computed extension
                    //
                    try {
                        extensions.delete(mConfig.getString(PROP_NAME, ""));
                    } catch (Exception e) {/* extension isn't there */
                    }
                }

                // Create the extension
                GenericASN1Extension priExt = mkExtension();

                extensions.set(priExt.getName(), priExt);

            } catch (IOException e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("BASE_IO_ERROR", e.getMessage()));
                setError(req, CMS.getUserMessage("CMS_POLICY_UNEXPECTED_POLICY_ERROR"),
                        NAME, e.getMessage());
                return PolicyResult.REJECTED; // unrecoverable error.
            } catch (EBaseException e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CA_CERT_INFO_ERROR", e.getMessage()));
                setError(req, CMS.getUserMessage("CMS_POLICY_UNEXPECTED_POLICY_ERROR"),
                        NAME, "Configuration Info Error");
                return PolicyResult.REJECTED; // unrecoverable error.
            } catch (CertificateException e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CA_CERT_INFO_ERROR", e.getMessage()));
                setError(req, CMS.getUserMessage("CMS_POLICY_UNEXPECTED_POLICY_ERROR"),
                        NAME, "Certificate Info Error");
                return PolicyResult.REJECTED; // unrecoverable error.
            } catch (ParseException e) {
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("BASE_EXTENSION_ERROR", e.getMessage()));
                setError(req, CMS.getUserMessage("CMS_POLICY_UNEXPECTED_POLICY_ERROR"),
                        NAME, "Pattern parsing error");
                return PolicyResult.REJECTED; // unrecoverable error.
            } catch (Exception e) {
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("BASE_UNKNOWN_EXCEPTION", e.getMessage()));
                setError(req, CMS.getUserMessage("CMS_POLICY_UNEXPECTED_POLICY_ERROR"),
                        NAME, "Unknown Error");
                return PolicyResult.REJECTED; // unrecoverable error.
            }
        }
        return res;
    }

    /**
     * Construct GenericASN1Extension with value from CMS.cfg
     */
    protected GenericASN1Extension mkExtension()
            throws IOException, EBaseException, ParseException {
        GenericASN1Extension ext;

        Hashtable<String, String> h = new Hashtable<String, String>();
        // This only show one level, not substores!
        Enumeration<String> e = mConfig.getPropertyNames();

        while (e.hasMoreElements()) {
            String n = e.nextElement();

            h.put(n, mConfig.getString(n));
        }
        for (int idx = 0; idx < MAX_ATTR; idx++) {
            String proptype = PROP_ATTRIBUTE + "." + idx + "." + PROP_TYPE;
            String propsource = PROP_ATTRIBUTE + "." + idx + "." + PROP_SOURCE;
            String propvalue = PROP_ATTRIBUTE + "." + idx + "." + PROP_VALUE;

            h.put(proptype, mConfig.getString(proptype, null));
            h.put(propsource, mConfig.getString(propsource, null));
            h.put(propvalue, mConfig.getString(propvalue, null));
        }
        ext = new GenericASN1Extension(h);
        return ext;
    }

    /**
     * Return configured parameters for a policy rule instance.
     *
     * @return nvPairs A Vector of name/value pairs.
     */
    public Vector<String> getInstanceParams() {
        int idx = 0;
        Vector<String> params = new Vector<String>();

        try {
            params.addElement(PROP_CRITICAL + "=" + mConfig.getBoolean(PROP_CRITICAL, false));
            params.addElement(PROP_NAME + "=" + mConfig.getString(PROP_NAME, null));
            params.addElement(PROP_OID + "=" + mConfig.getString(PROP_OID, null));
            params.addElement(PROP_PATTERN + "=" + mConfig.getString(PROP_PATTERN, null));

            for (idx = 0; idx < MAX_ATTR; idx++) {
                String proptype = PROP_ATTRIBUTE + "." + idx + "." + PROP_TYPE;
                String propsource = PROP_ATTRIBUTE + "." + idx + "." + PROP_SOURCE;
                String propvalue = PROP_ATTRIBUTE + "." + idx + "." + PROP_VALUE;

                params.addElement(proptype + "=" + mConfig.getString(proptype, null));
                params.addElement(propsource + "=" + mConfig.getString(propsource, null));
                params.addElement(propvalue + "=" + mConfig.getString(propvalue, null));
            }
            params.addElement(PROP_PREDICATE + "=" + mConfig.getString(PROP_PREDICATE, null));
        } catch (EBaseException e) {
            ;
        }

        return params;
    }

    /**
     * Return default parameters for a policy implementation.
     *
     * @return nvPairs A Vector of name/value pairs.
     */
    public Vector<String> getDefaultParams() {
        int idx = 0;

        Vector<String> defParams = new Vector<String>();

        defParams.addElement(PROP_CRITICAL + "=false");
        defParams.addElement(PROP_NAME + "=");
        defParams.addElement(PROP_OID + "=");
        defParams.addElement(PROP_PATTERN + "=");

        for (idx = 0; idx < MAX_ATTR; idx++) {
            defParams.addElement(PROP_ATTRIBUTE + "." + idx + "." + PROP_TYPE + "=");
            defParams.addElement(PROP_ATTRIBUTE + "." + idx + "." + PROP_SOURCE + "=");
            defParams.addElement(PROP_ATTRIBUTE + "." + idx + "." + PROP_VALUE + "=");
        }

        return defParams;
    }
}
