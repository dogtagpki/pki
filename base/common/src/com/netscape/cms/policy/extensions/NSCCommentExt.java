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

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.Locale;
import java.util.Vector;

import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.CertificateVersion;
import netscape.security.x509.NSCCommentExtension;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.policy.EPolicyException;
import com.netscape.certsrv.policy.IEnrollmentPolicy;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.PolicyResult;
import com.netscape.cms.policy.APolicyRule;

/**
 * Netscape comment
 * Adds Netscape comment policy
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
public class NSCCommentExt extends APolicyRule
        implements IEnrollmentPolicy, IExtendedPluginInfo {

    protected static final String PROP_USER_NOTICE_DISPLAY_TEXT = "displayText";
    protected static final String PROP_COMMENT_FILE = "commentFile";
    protected static final String PROP_CRITICAL = "critical";
    protected static final String PROP_INPUT_TYPE = "inputType";
    protected static final String TEXT = "Text";
    protected static final String FILE = "File";

    protected String mUserNoticeDisplayText;
    protected String mCommentFile;
    protected String mInputType;
    protected boolean mCritical;
    private Vector<String> mParams = new Vector<String>();

    protected String tempCommentFile;
    protected boolean certApplied = false;

    /**
     * Adds the Netscape comment in the end-entity certificates or
     * CA certificates. The policy is set to be non-critical with the
     * provided OID.
     */
    public NSCCommentExt() {
        NAME = "NSCCommentExt";
        DESC = "Sets non-critical Netscape Comment extension in certs";
    }

    /**
     * Initializes this policy rule.
     * <p>
     * The entries may be of the form:
     *
     * ca.Policy.rule.<ruleName>.implName=NSCCommentExtImpl ca.Policy.rule.<ruleName>.displayText=<n>
     * ca.Policy.rule.<ruleName>.commentFile=<n> ca.Policy.rule.<ruleName>.enable=false
     *
     * @param config The config store reference
     */
    public void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {

        FileInputStream fileStream = null;

        try {
            mCritical = config.getBoolean(PROP_CRITICAL, false);
            mParams.addElement(PROP_CRITICAL + "=" + mCritical);

            mInputType = config.getString(PROP_INPUT_TYPE, null);
            mParams.addElement(PROP_INPUT_TYPE + "=" + mInputType);

            mUserNoticeDisplayText = config.getString(PROP_USER_NOTICE_DISPLAY_TEXT, "");
            mParams.addElement(PROP_USER_NOTICE_DISPLAY_TEXT + "=" + mUserNoticeDisplayText);

            tempCommentFile = config.getString(PROP_COMMENT_FILE, "");

            boolean enable = config.getBoolean(PROP_ENABLE, false);

            if ((enable == true)) {

                if (mInputType.equals("File")) {
                    if (tempCommentFile.equals(""))
                        throw new Exception("No file name provided");

                    fileStream = new FileInputStream(tempCommentFile);
                    fileStream.close();
                }
            }

            if (tempCommentFile.equals(""))
                mCommentFile = "";
            else
                mCommentFile = tempCommentFile.replace('\\', '/');

            config.putString(PROP_COMMENT_FILE, mCommentFile);

            mParams.addElement(PROP_COMMENT_FILE + "=" + mCommentFile);
        } catch (FileNotFoundException e) {
            Object[] params = { getInstanceName(), "File not found : " + tempCommentFile };

            throw new EPolicyException(CMS.getUserMessage("CMS_POLICY_INVALID_POLICY_CONFIG"), params);
        } catch (Exception e) {
            Object[] params = { getInstanceName(), e.getMessage() };

            throw new EPolicyException(CMS.getUserMessage("CMS_POLICY_INVALID_POLICY_CONFIG"), params);
        }
    }

    /**
     * Applies the policy on the given Request.
     * <p>
     *
     * @param req The request on which to apply policy.
     * @return The policy result object.
     */
    public PolicyResult apply(IRequest req) {
        PolicyResult res = PolicyResult.ACCEPTED;

        // get cert info.
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
        return res;
    }

    public PolicyResult applyCert(IRequest req, X509CertInfo certInfo) {

        certApplied = false;
        CertificateExtensions extensions = null;

        try {
            extensions = (CertificateExtensions)
                    certInfo.get(X509CertInfo.EXTENSIONS);
        } catch (IOException e) {
        } catch (CertificateException e) {
        }

        if (extensions == null) {
            extensions = new CertificateExtensions();
            try {
                certInfo.set(X509CertInfo.VERSION,
                        new CertificateVersion(CertificateVersion.V3));
                certInfo.set(X509CertInfo.EXTENSIONS, extensions);
            } catch (Exception e) {
            }
        } else {
            // remove any previously computed version of the extension
            try {
                extensions.delete(NSCCommentExtension.NAME);

            } catch (IOException e) {
                // this is the hack: for some reason, the key which is the name
                // of the policy has been converted into the OID
                try {
                    extensions.delete("2.16.840.1.113730.1.13");
                } catch (IOException ee) {
                }
            }
        }
        if (mInputType.equals("File")) {
            //		if ((mUserNoticeDisplayText.equals("")) && !(mCommentFile.equals(""))) {
            try {
                // Read the comments file
                BufferedReader fis = new BufferedReader(new FileReader(mCommentFile));

                String line = null;
                StringBuffer buffer = new StringBuffer();

                while ((line = fis.readLine()) != null)
                    buffer.append(line);
                mUserNoticeDisplayText = new String(buffer);
                fis.close();
            } catch (IOException e) {
                setError(req, CMS.getUserMessage("CMS_POLICY_UNEXPECTED_POLICY_ERROR"),
                        NAME, " Comment Text file not found : " + mCommentFile);
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("POLICY_COMMENT_FILE_NOT_FOUND", e.toString()));
                return PolicyResult.REJECTED;

            }

        }

        certApplied = true;

        try {
            NSCCommentExtension cpExt =
                    new NSCCommentExtension(mCritical, mUserNoticeDisplayText);

            extensions.set(NSCCommentExtension.NAME, cpExt);
        } catch (Exception e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("POLICY_ERROR_CERTIFICATE_POLICIES_1", NAME));
            setError(req,
                    CMS.getUserMessage("CMS_POLICY_CERTIFICATE_POLICIES_ERROR"), NAME);
            return PolicyResult.REJECTED;
        }
        return PolicyResult.ACCEPTED;
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        String[] params = {
                PROP_CRITICAL + ";boolean;Netscape recommendation: non-critical.",
                PROP_INPUT_TYPE + ";choice(Text,File);Whether the comments " +
                        "would be entered in the displayText field or come from " +
                        "a file.",
                PROP_USER_NOTICE_DISPLAY_TEXT + ";string;The comment that may be " +
                        "displayed to the user when the certificate is viewed.",
                PROP_COMMENT_FILE + ";string; If data source is 'File', specify " +
                        "the file name with full path.",
                IExtendedPluginInfo.HELP_TOKEN +
                        ";configuration-policyrules-nsccomment",
                IExtendedPluginInfo.HELP_TEXT +
                        ";Adds 'netscape comment' extension. See manual"
            };

        return params;

    }

    /**
     * Return configured parameters for a policy rule instance.
     *
     * @return nvPairs A Vector of name/value pairs.
     */
    public Vector<String> getInstanceParams() {
        return mParams;
    }

    /**
     * Return default parameters for a policy implementation.
     *
     * @return nvPairs A Vector of name/value pairs.
     */
    public Vector<String> getDefaultParams() {
        Vector<String> defParams = new Vector<String>();

        defParams.addElement(PROP_CRITICAL + "=false");
        defParams.addElement(PROP_INPUT_TYPE + "=" + TEXT);
        defParams.addElement(PROP_USER_NOTICE_DISPLAY_TEXT + "=");
        defParams.addElement(PROP_COMMENT_FILE + "=");
        return defParams;
    }
}
