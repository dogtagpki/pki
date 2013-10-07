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

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Vector;

import netscape.security.util.DerValue;
import netscape.security.util.ObjectIdentifier;
import netscape.security.x509.AVAValueConverter;
import netscape.security.x509.Attribute;
import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.CertificateVersion;
import netscape.security.x509.SubjectDirAttributesExtension;
import netscape.security.x509.X500NameAttrMap;
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
 * Policy to add the subject directory attributes extension.
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
public class SubjectDirectoryAttributesExt extends APolicyRule
        implements IEnrollmentPolicy, IExtendedPluginInfo {
    protected static final String PROP_CRITICAL = "critical";
    protected static final String PROP_ATTRIBUTE = "attribute";
    protected static final String PROP_NUM_ATTRIBUTES = "numAttributes";

    protected static final boolean DEF_CRITICAL = false;
    protected static final int DEF_NUM_ATTRIBUTES = 3;
    protected static final int MAX_NUM_ATTRIBUTES = 10;

    protected boolean mCritical;
    protected int mNumAttributes;
    protected AttributeConfig[] mAttributes = null;

    protected IConfigStore mConfig;
    protected SubjectDirAttributesExtension mExt = null;

    protected Vector<String> mParams = new Vector<String>();
    private String[] mEPI = null; // extended plugin info
    protected static Vector<String> mDefParams = new Vector<String>();

    static {
        setDefaultParams();
    }

    public SubjectDirectoryAttributesExt() {
        NAME = "SubjectDirectoryAttributesExtPolicy";
        DESC = "Sets Subject Directory Attributes Extension in certificates.";
        setExtendedPluginInfo();
    }

    public void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {
        boolean enabled = config.getBoolean("enabled", false);

        mConfig = config;

        mCritical = mConfig.getBoolean(PROP_CRITICAL, false);
        mNumAttributes = mConfig.getInteger(PROP_NUM_ATTRIBUTES, DEF_NUM_ATTRIBUTES);
        if (mNumAttributes < 1) {
            EBaseException ex = new EBaseException(
                    CMS.getUserMessage("CMS_BASE_MUST_BE_POSITIVE_NUMBER", PROP_NUM_ATTRIBUTES));

            log(ILogger.LL_FAILURE, NAME + " Error: " + ex.toString());
            throw ex;
        }
        mAttributes = new AttributeConfig[mNumAttributes];
        for (int i = 0; i < mNumAttributes; i++) {
            String name = PROP_ATTRIBUTE + i;
            IConfigStore c = mConfig.getSubStore(name);

            mAttributes[i] = new AttributeConfig(name, c, enabled);
        }
        if (enabled) {
            try {
                mExt = formExt(null);
            } catch (IOException e) {
                log(ILogger.LL_FAILURE, NAME + " Error: " + e.getMessage());
                throw new EBaseException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR",
                            "Error forming Subject Directory Attributes Extension. " +
                                    "See log file for details."));
            }
        }
        setInstanceParams();
    }

    public PolicyResult apply(IRequest req) {
        X509CertInfo[] ci =
                req.getExtDataInCertInfoArray(IRequest.CERT_INFO);

        if (ci == null || ci[0] == null) {
            setError(req, CMS.getUserMessage("CMS_POLICY_NO_CERT_INFO"), NAME);
            return PolicyResult.REJECTED; // unrecoverable error.
        }

        for (int i = 0; i < ci.length; i++) {
            PolicyResult r = applyCert(req, ci[i]);

            if (r == PolicyResult.REJECTED)
                return r;
        }
        return PolicyResult.ACCEPTED;
    }

    public PolicyResult applyCert(IRequest req, X509CertInfo certInfo) {
        CertificateExtensions extensions = null;

        try {
            // get extension and remove if exists.
            extensions = (CertificateExtensions)
                    certInfo.get(X509CertInfo.EXTENSIONS);
            if (extensions == null) {
                extensions = new CertificateExtensions();
                certInfo.set(X509CertInfo.VERSION,
                        new CertificateVersion(CertificateVersion.V3));
                certInfo.set(X509CertInfo.EXTENSIONS, extensions);
            } else {
                try {
                    extensions.delete(SubjectDirAttributesExtension.NAME);
                } catch (IOException ee) {
                    // if name is not found, try deleting the extension using the OID
                    try {
                        extensions.delete("2.5.29.9");
                    } catch (IOException eee) {
                    }
                }
            }

            // form extension and set.
            if (mExt != null) {
                extensions.set(SubjectDirAttributesExtension.NAME, mExt);
            } else {
                SubjectDirAttributesExtension ext = formExt(req);

                if (ext != null)
                    extensions.set(SubjectDirAttributesExtension.NAME, formExt(req));
            }
            return PolicyResult.ACCEPTED;
        } catch (CertificateException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CA_CERT_INFO_ERROR", e.getMessage()));

            setError(req, CMS.getUserMessage("CMS_POLICY_UNEXPECTED_POLICY_ERROR"),
                    NAME, "Certificate Info Error");
            return PolicyResult.REJECTED; // unrecoverable error.
        } catch (IOException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("BASE_IO_ERROR", e.getMessage()));
            setError(req, CMS.getUserMessage("CMS_POLICY_UNEXPECTED_POLICY_ERROR"),
                    NAME, "IOException Error");
            return PolicyResult.REJECTED;
        }
    }

    public Vector<String> getInstanceParams() {
        return mParams; // inited in init()
    }

    public Vector<String> getDefaultParams() {
        return mDefParams;
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        return mEPI; // inited in the constructor.
    }

    private void setInstanceParams() {
        mParams.addElement(PROP_CRITICAL + "=" + mCritical);
        mParams.addElement(PROP_NUM_ATTRIBUTES + "=" + mNumAttributes);
        for (int i = 0; i < mNumAttributes; i++) {
            mAttributes[i].getInstanceParams(mParams);
        }
        // clean up others if exists. expensive.
        for (int j = mNumAttributes; j < MAX_NUM_ATTRIBUTES; j++) {
            mConfig.removeSubStore(PROP_ATTRIBUTE + j);
        }
    }

    private static void setDefaultParams() {
        mDefParams.addElement(PROP_CRITICAL + "=" + DEF_CRITICAL);
        mDefParams.addElement(PROP_NUM_ATTRIBUTES + "=" + DEF_NUM_ATTRIBUTES);
        for (int i = 0; i < DEF_NUM_ATTRIBUTES; i++) {
            AttributeConfig.getDefaultParams(PROP_ATTRIBUTE + i, mDefParams);
        }
    }

    private void setExtendedPluginInfo() {
        Vector<String> v = new Vector<String>();

        v.addElement(PROP_CRITICAL + ";boolean;" +
                "RFC 2459 recommendation: MUST be non-critical.");
        v.addElement(PROP_NUM_ATTRIBUTES + ";number;" +
                "Number of Attributes in the extension.");

        for (int i = 0; i < MAX_NUM_ATTRIBUTES; i++) {
            AttributeConfig.getExtendedPluginInfo(PROP_ATTRIBUTE + i, v);
        }

        v.addElement(IExtendedPluginInfo.HELP_TOKEN +
                ";configuration-policyrules-subjectdirectoryattributes");
        v.addElement(IExtendedPluginInfo.HELP_TEXT
                +
                ";Adds Subject Directory Attributes extension. See RFC 2459 (4.2.1.9). It's not recommended as an essential part of the profile, but may be used in local environments.");

        mEPI = com.netscape.cmsutil.util.Utils.getStringArrayFromVector(v);
    }

    private SubjectDirAttributesExtension formExt(IRequest req)
            throws IOException {
        Vector<Attribute> attrs = new Vector<Attribute>();

        // if we're called from init and one attribute is from request attribute
        // the ext can't be formed yet.
        if (req == null) {
            for (int i = 0; i < mNumAttributes; i++) {
                if (mAttributes[i].mWhereToGetValue == AttributeConfig.USE_REQUEST_ATTR)
                    return null;
            }
        }
        // either we're called from apply or all values are fixed.
        for (int i = 0; i < mNumAttributes; i++) {
            if (mAttributes[i].mAttribute != null) {
                attrs.addElement(mAttributes[i].mAttribute);
            } else {
                // skip attribute if request attribute doesn't exist.
                Attribute a = mAttributes[i].formAttr(req);

                if (a == null)
                    continue;
                attrs.addElement(a);
            }
        }
        if (attrs.size() == 0)
            return null;
        Attribute[] attrList = new Attribute[attrs.size()];

        attrs.copyInto(attrList);
        SubjectDirAttributesExtension ext =
                new SubjectDirAttributesExtension(attrList);

        return ext;
    }
}

class AttributeConfig {

    protected static final String PROP_ATTRIBUTE_NAME = "attributeName";
    protected static final String PROP_WTG_VALUE = "whereToGetValue";
    protected static final String PROP_VALUE = "value";

    protected static final String USE_REQUEST_ATTR = "Request Attribute";
    protected static final String USE_FIXED = "Fixed Value";

    protected String mAttributeName = null;
    protected String mWhereToGetValue = null;
    protected String mValue = null;

    protected String mPrefix = null;
    protected String mReqAttr = null;
    protected ObjectIdentifier mAttributeOID = null;

    protected String mName = null;
    protected IConfigStore mConfig = null;
    protected Attribute mAttribute = null;

    protected static final String ATTRIBUTE_NAME_INFO = "Attribute name.";
    protected static final String WTG_VALUE_INFO =
            PROP_WTG_VALUE + ";choice(" + USE_REQUEST_ATTR + "," + USE_FIXED + ");" +
                    "Get value from a request attribute or use a fixed value specified below.";
    protected static final String VALUE_INFO =
            PROP_VALUE + ";string;" +
                    "Request attribute name or a fixed value to put into the extension.";

    public AttributeConfig(String name, IConfigStore config, boolean enabled)
            throws EBaseException {
        X500NameAttrMap map = X500NameAttrMap.getDefault();

        mName = name;
        mConfig = config;
        if (enabled) {
            mAttributeName = mConfig.getString(PROP_ATTRIBUTE_NAME);
            mWhereToGetValue = mConfig.getString(PROP_WTG_VALUE);
            mValue = mConfig.getString(PROP_VALUE);
        } else {
            mAttributeName = mConfig.getString(PROP_ATTRIBUTE_NAME, "");
            mWhereToGetValue = mConfig.getString(PROP_WTG_VALUE, USE_REQUEST_ATTR);
            mValue = mConfig.getString(PROP_VALUE, "");
        }

        if (mAttributeName.length() > 0) {
            mAttributeOID = map.getOid(mAttributeName);
            if (mAttributeOID == null)
                throw new EBaseException(
                        CMS.getUserMessage("CMS_BASE_INVALID_ATTRIBUTE", mAttributeName));
        }

        if (mWhereToGetValue.equalsIgnoreCase(USE_REQUEST_ATTR)) {
            mWhereToGetValue = USE_REQUEST_ATTR;
            if (enabled && mValue.length() == 0) {
                throw new EBaseException(CMS.getUserMessage("CMS_BASE_GET_PROPERTY_FAILED", PROP_VALUE));
            }
            int dot = mValue.indexOf('.');

            if (dot != -1) {
                mPrefix = mValue.substring(0, dot);
                mReqAttr = mValue.substring(dot + 1);
                if (mPrefix == null || mPrefix.length() == 0 ||
                        mReqAttr == null || mReqAttr.length() == 0) {
                    throw new EBaseException(
                            CMS.getUserMessage("CMS_BASE_INVALID_ATTRIBUTE", mValue));
                }
            } else {
                mPrefix = null;
                mReqAttr = mValue;
            }
        } else if (mWhereToGetValue.equalsIgnoreCase(USE_FIXED)) {
            mWhereToGetValue = USE_FIXED;
            if (mAttributeOID != null) {
                try {
                    checkValue(mAttributeOID, mValue);
                    mAttribute = new Attribute(mAttributeOID, mValue);
                } catch (Exception e) {
                    throw new EBaseException(
                            CMS.getUserMessage("CMS_BASE_INVALID_ATTR_VALUE",
                                    mAttributeName, e.getMessage()));
                }
            }
        } else if (enabled || mWhereToGetValue.length() > 0) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_VALUE_FOR_TYPE", PROP_WTG_VALUE,
                        "Must be either '" + USE_REQUEST_ATTR + "' or '" + USE_FIXED + "'."));
        }
    }

    public static void getDefaultParams(String name, Vector<String> v) {
        String nameDot = name + ".";

        v.addElement(nameDot + PROP_ATTRIBUTE_NAME + "=");
        v.addElement(nameDot + PROP_WTG_VALUE + "=" + USE_REQUEST_ATTR);
        v.addElement(nameDot + PROP_VALUE + "=");
    }

    public static void getExtendedPluginInfo(String name, Vector<String> v) {
        String nameDot = name + ".";
        String attrChoices = getAllNames();

        v.addElement(nameDot + PROP_ATTRIBUTE_NAME + ";choice(" + attrChoices + ");" +
                ATTRIBUTE_NAME_INFO);
        v.addElement(nameDot + WTG_VALUE_INFO);
        v.addElement(nameDot + VALUE_INFO);
    }

    public void getInstanceParams(Vector<String> v) {
        String nameDot = mName + ".";

        v.addElement(nameDot + PROP_ATTRIBUTE_NAME + "=" + mAttributeName);
        v.addElement(nameDot + PROP_WTG_VALUE + "=" + mWhereToGetValue);
        v.addElement(nameDot + PROP_VALUE + "=" + mValue);
    }

    public Attribute formAttr(IRequest req)
            throws IOException {
        String val = req.getExtDataInString(mPrefix, mReqAttr);

        if (val == null || val.length() == 0) {
            return null;
        }
        checkValue(mAttributeOID, val);
        return new Attribute(mAttributeOID, val);
    }

    static private String getAllNames() {
        Enumeration<String> n = X500NameAttrMap.getDefault().getAllNames();
        StringBuffer sb = new StringBuffer();
        sb.append(n.nextElement());

        while (n.hasMoreElements()) {
            sb.append(",");
            sb.append(n.nextElement());
        }
        return sb.toString();
    }

    private static void checkValue(ObjectIdentifier oid, String val)
            throws IOException {
        AVAValueConverter c = X500NameAttrMap.getDefault().getValueConverter(oid);

        @SuppressWarnings("unused")
        DerValue derval = c.getValue(val); // check for errors
        return;
    }

}
