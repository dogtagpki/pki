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
import java.util.Locale;
import java.util.Vector;

import netscape.security.extensions.ExtendedKeyUsageExtension;
import netscape.security.util.ObjectIdentifier;
import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.CertificateVersion;
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
 * This implements the extended key usage extension.
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
public class ExtendedKeyUsageExt extends APolicyRule
        implements IEnrollmentPolicy, IExtendedPluginInfo {
    public static final String PROP_CRITICAL = "critical";
    protected static final String PROP_PURPOSE_ID = "id";
    protected static final String PROP_NUM_IDS = "numIds";
    protected static int MAX_PURPOSE_ID = 10;
    private boolean mCritical = false;
    private IConfigStore mConfig = null;
    private Vector<ObjectIdentifier> mUsages = null;

    private String[] mParams = null;

    // PKIX specifies the that the extension SHOULD NOT be critical
    public static final boolean DEFAULT_CRITICALITY = false;

    private ExtendedKeyUsageExtension mExtendedKeyUsage = null;

    /**
     * Constructs extended Key Usage extension.
     */
    public ExtendedKeyUsageExt() {
        NAME = "ExtendedKeyUsageExt";
        DESC = "Sets ExtendedKeyUsage extension for certificates";
    }

    /**
     * Performs one-time initialization of the policy.
     */
    public void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {
        mConfig = config;
        setExtendedPluginInfo();
        setupParams();
        mExtendedKeyUsage = new ExtendedKeyUsageExtension(mCritical, mUsages);
    }

    /**
     * Applies the policy to the given request.
     */
    public PolicyResult apply(IRequest req) {

        // if the extension was not configured correctly, just skip it
        if (mExtendedKeyUsage == null) {
            return PolicyResult.ACCEPTED;
        }

        X509CertInfo[] ci =
                req.getExtDataInCertInfoArray(IRequest.CERT_INFO);

        if (ci == null || ci[0] == null) {
            setError(req, CMS.getUserMessage("CMS_POLICY_NO_CERT_INFO"), NAME);
            return PolicyResult.REJECTED;
        }

        for (int i = 0; i < ci.length; i++) {
            PolicyResult certRes = applyCert(req, ci[i]);

            if (certRes == PolicyResult.REJECTED)
                return certRes;
        }
        return PolicyResult.ACCEPTED;
    }

    public PolicyResult applyCert(IRequest req, X509CertInfo certInfo) {
        try {
            // find the extensions in the certInfo
            CertificateExtensions extensions = (CertificateExtensions)
                    certInfo.get(X509CertInfo.EXTENSIONS);

            // prepare the extensions data structure
            if (extensions == null) {
                certInfo.set(X509CertInfo.VERSION,
                        new CertificateVersion(CertificateVersion.V3));
                extensions = new CertificateExtensions();
                certInfo.set(X509CertInfo.VERSION,
                        new CertificateVersion(CertificateVersion.V3));
                certInfo.set(X509CertInfo.EXTENSIONS, extensions);
            } else {
                try {
                    extensions.delete(ExtendedKeyUsageExtension.NAME);
                } catch (IOException ex) {
                    // ExtendedKeyUsage extension is not already there
                }
            }

            extensions.set(ExtendedKeyUsageExtension.NAME, mExtendedKeyUsage);

            return PolicyResult.ACCEPTED;
        } catch (IOException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("BASE_IO_ERROR", e.getMessage()));
            setError(req, CMS.getUserMessage("CMS_POLICY_UNEXPECTED_POLICY_ERROR"), NAME,
                    e.getMessage());
            return PolicyResult.REJECTED;
        } catch (CertificateException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CA_CERT_INFO_ERROR",
                    e.getMessage()));
            setError(req, CMS.getUserMessage("CMS_POLICY_UNEXPECTED_POLICY_ERROR"), NAME,
                    e.getMessage());
            return PolicyResult.REJECTED;
        }
    }

    /**
     * Returns instance specific parameters.
     */
    public Vector<String> getInstanceParams() {
        Vector<String> params = new Vector<String>();

        params.addElement(PROP_CRITICAL + "=" + mCritical);
        int numIds = MAX_PURPOSE_ID;

        try {
            numIds = mConfig.getInteger(PROP_NUM_IDS, MAX_PURPOSE_ID);
        } catch (EBaseException e) {
        }
        params.addElement(PROP_NUM_IDS + "=" + numIds);
        String usage = null;

        for (int i = 0; i < numIds; i++) {
            if (mUsages.size() <= i) {
                params.addElement(PROP_PURPOSE_ID +
                        Integer.toString(i) + "=");
            } else {
                usage = mUsages.elementAt(i).toString();
                if (usage == null) {
                    params.addElement(PROP_PURPOSE_ID +
                            Integer.toString(i) + "=");
                } else {
                    params.addElement(PROP_PURPOSE_ID +
                            Integer.toString(i) + "=" + usage);
                }
            }
        }
        return params;
    }

    private void setExtendedPluginInfo() {
        Vector<String> v = new Vector<String>();
        int mNum = MAX_PURPOSE_ID;

        if (mConfig != null) {
            try {
                mConfig.getInteger(PROP_NUM_IDS, MAX_PURPOSE_ID);
            } catch (EBaseException e) {
            }
        }
        for (int i = 0; i < mNum; i++) {
            v.addElement(PROP_PURPOSE_ID
                    + Integer.toString(i)
                    + ";string;"
                    +
                    "A unique,valid OID specified in dot-separated numeric component notation. e.g. 2.16.840.1.113730.1.99");
        }

        v.addElement(PROP_NUM_IDS + ";number;The total number of policy IDs.");
        v.addElement(PROP_CRITICAL
                +
                ";boolean;RFC 2459 recommendation: This extension may, at the option of the certificate issuer, be either critical or non-critical.");
        v.addElement(IExtendedPluginInfo.HELP_TOKEN +
                ";configuration-policyrules-extendedkeyusage");
        v.addElement(IExtendedPluginInfo.HELP_TEXT +
                ";Adds Extended Key Usage Extension. Defined in RFC 2459 " +
                "(4.2.1.13)");

        mParams = com.netscape.cmsutil.util.Utils.getStringArrayFromVector(v);
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        if (mParams == null) {
            setExtendedPluginInfo();
        }
        return mParams;
    }

    /**
     * Returns default parameters.
     */
    public Vector<String> getDefaultParams() {
        Vector<String> defParams = new Vector<String>();

        defParams.addElement(PROP_CRITICAL + "=false");
        defParams.addElement(PROP_NUM_IDS + "=" + MAX_PURPOSE_ID);
        for (int i = 0; i < MAX_PURPOSE_ID; i++) {
            defParams.addElement(PROP_PURPOSE_ID + Integer.toString(i) + "=");
        }
        return defParams;
    }

    /**
     * Setups parameters.
     */
    private void setupParams() throws EBaseException {

        mCritical = mConfig.getBoolean(PROP_CRITICAL, false);
        if (mUsages == null) {
            mUsages = new Vector<ObjectIdentifier>();
        }

        int mNum = mConfig.getInteger(PROP_NUM_IDS, MAX_PURPOSE_ID);

        for (int i = 0; i < mNum; i++) {
            ObjectIdentifier usageOID = null;

            String usage = mConfig.getString(PROP_PURPOSE_ID +
                    Integer.toString(i), null);

            try {

                if (usage == null)
                    break;
                usage = usage.trim();
                if (usage.equals(""))
                    break;
                if (usage.equalsIgnoreCase("ocspsigning")) {
                    usageOID = ObjectIdentifier.getObjectIdentifier(ExtendedKeyUsageExtension.OID_OCSPSigning);
                } else if (usage.equalsIgnoreCase("codesigning")) {
                    usageOID = ObjectIdentifier.getObjectIdentifier(ExtendedKeyUsageExtension.OID_CODESigning);
                } else {
                    // it could be an object identifier, test it
                    usageOID = ObjectIdentifier.getObjectIdentifier(usage);
                }
            } catch (IOException ex) {
                throw new EBaseException(this.getClass().getName() + ":" +
                        ex.getMessage());
            } catch (NumberFormatException ex) {
                throw new EBaseException(this.getClass().getName() + ":" +
                        "OID '" + usage + "' format error");
            }
            mUsages.addElement(usageOID);
        }
    }
}
