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
package com.netscape.cms.policy.constraints;

import java.util.Enumeration;
import java.util.Locale;
import java.util.StringTokenizer;
import java.util.Vector;

import netscape.security.provider.RSAPublicKey;
import netscape.security.util.BigInt;
import netscape.security.x509.AlgorithmId;
import netscape.security.x509.CertificateX509Key;
import netscape.security.x509.X509CertInfo;
import netscape.security.x509.X509Key;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.policy.EPolicyException;
import com.netscape.certsrv.policy.IEnrollmentPolicy;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.PolicyResult;
import com.netscape.cms.policy.APolicyRule;

/**
 * RSAKeyConstraints policy enforces min and max size of the key.
 * Optionally checks the exponents.
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
public class RSAKeyConstraints extends APolicyRule
        implements IEnrollmentPolicy, IExtendedPluginInfo {
    private Vector<BigInt> mExponents;
    private int mMinSize;
    private int mMaxSize;

    private final static int DEF_MIN_SIZE = 512;
    private final static int DEF_MAX_SIZE = 2048;
    private final static String PROP_MIN_SIZE = "minSize";
    private final static String PROP_MAX_SIZE = "maxSize";
    private final static String PROP_EXPONENTS = "exponents";
    private final static String RSA = "RSA";

    private final static Vector<String> defConfParams = new Vector<String>();

    static {
        defConfParams.addElement(PROP_MIN_SIZE + "=" + DEF_MIN_SIZE);
        defConfParams.addElement(PROP_MAX_SIZE + "=" + DEF_MAX_SIZE);
        defConfParams.addElement(PROP_EXPONENTS + "=" + " ");
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        String[] params = {
                PROP_MIN_SIZE + ";number;Minimum size of user's RSA key (bits)",
                PROP_MAX_SIZE + ";number;Maximum size of user's RSA key (bits)",
                PROP_EXPONENTS + ";string;Comma-separated list of permissible exponents",
                IExtendedPluginInfo.HELP_TOKEN +
                        ";configuration-policyrules-rsakeyconstraints",
                IExtendedPluginInfo.HELP_TEXT +
                        ";Reject request if RSA key length is not within the " +
                        "specified constraints"
            };

        return params;
    }

    public RSAKeyConstraints() {
        NAME = "RSAKeyConstraints";
        DESC = "Enforces RSA Key Constraints.";
    }

    /**
     * Initializes this policy rule.
     * <P>
     *
     * The entries probably are of the form:
     *
     * ra.Policy.rule.<ruleName>.implName=RSAKeyConstraints ra.Policy.rule.<ruleName>.enable=true
     * ra.Policy.rule.<ruleName>.minSize=512 ra.Policy.rule.<ruleName>.maxSize=2048
     * ra.Policy.rule.<ruleName>.predicate=ou==Marketing
     *
     * @param config The config store reference
     */
    public void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {

        if (config == null || config.size() == 0)
            throw new EPolicyException(
                    CMS.getUserMessage("CMS_POLICY_MISSING_POLICY_CONFIG",
                            getInstanceName()));
        String exponents = null;

        // Get Min and Max sizes
        mMinSize = config.getInteger(PROP_MIN_SIZE, DEF_MIN_SIZE);
        mMaxSize = config.getInteger(PROP_MAX_SIZE, DEF_MAX_SIZE);

        if (mMinSize <= 0)
            throw new EBaseException(
                    CMS.getUserMessage("CMS_BASE_MUST_BE_POSITIVE_NUMBER", PROP_MIN_SIZE));
        if (mMaxSize <= 0)
            throw new EBaseException(
                    CMS.getUserMessage("CMS_BASE_MUST_BE_POSITIVE_NUMBER", PROP_MAX_SIZE));

        if (mMinSize > mMaxSize)
            throw new EBaseException(
                    CMS.getUserMessage("CMS_BASE_A_GREATER_THAN_EQUAL_B", PROP_MIN_SIZE, PROP_MAX_SIZE));

        mExponents = new Vector<BigInt>();

        // Get exponents
        exponents = config.getString(PROP_EXPONENTS, null);

        if (exponents != null) {
            StringTokenizer tok = new StringTokenizer(exponents, ",");

            try {
                while (tok.hasMoreTokens()) {
                    String exp = tok.nextToken().trim();

                    mExponents.addElement(new BigInt(Integer.parseInt(exp)));
                }
            } catch (Exception e) {
                // e.printStackTrace();
                String[] params = { getInstanceName(), exponents,
                        PROP_EXPONENTS };

                throw new EPolicyException(
                        CMS.getUserMessage("CMS_POLICY_INVALID_CONFIG_PARAM", params));
            }
        }
    }

    /**
     * Applies the policy on the given Request.
     * <P>
     *
     * @param req The request on which to apply policy.
     * @return The policy result object.
     */
    public PolicyResult apply(IRequest req) {

        PolicyResult result = PolicyResult.ACCEPTED;

        try {
            // Get the certificate info from the request
            X509CertInfo certInfo[] =
                    req.getExtDataInCertInfoArray(IRequest.CERT_INFO);

            // There should be a certificate info set.
            if (certInfo == null) {
                setError(req, CMS.getUserMessage("CMS_POLICY_NO_CERT_INFO",
                        getInstanceName()), "");
                return PolicyResult.REJECTED;
            }

            // Else check if the key size(s) are within the limit.
            for (int i = 0; i < certInfo.length; i++) {
                CertificateX509Key certKey = (CertificateX509Key)
                        certInfo[i].get(X509CertInfo.KEY);
                X509Key key = (X509Key) certKey.get(CertificateX509Key.KEY);
                String alg = key.getAlgorithmId().toString();

                if (!alg.equalsIgnoreCase(RSA))
                    continue;
                X509Key newkey = null;

                try {
                    newkey = new X509Key(AlgorithmId.get("RSA"),
                                key.getKey());
                } catch (Exception e) {
                    CMS.debug("RSAKeyConstraints::apply() - "
                             + "Exception=" + e.toString());
                    setError(req,
                              CMS.getUserMessage("CMS_POLICY_KEY_SIZE_VIOLATION",
                                                  getInstanceName()),
                              "");
                    return PolicyResult.REJECTED;
                }
                RSAPublicKey rsaKey = new RSAPublicKey(newkey.getEncoded());
                int keySize = rsaKey.getKeySize();

                if (keySize < mMinSize || keySize > mMaxSize) {
                    String[] params = { getInstanceName(),
                            String.valueOf(keySize),
                            String.valueOf(mMinSize),
                            String.valueOf(mMaxSize) };

                    setError(req, CMS.getUserMessage("CMS_POLICY_KEY_SIZE_VIOLATION",
                            params), "");
                    result = PolicyResult.REJECTED;
                }

                // If the exponents are configured, see if the key's
                // exponent is a configured one.
                if (mExponents.size() > 0) {
                    BigInt exp = rsaKey.getPublicExponent();

                    if (!mExponents.contains(exp)) {
                        StringBuffer sb = new StringBuffer();

                        for (Enumeration<BigInt> e = mExponents.elements(); e.hasMoreElements();) {
                            BigInt bi = e.nextElement();

                            sb.append(bi.toBigInteger().toString());
                            sb.append(" ");
                        }
                        String[] params = { getInstanceName(),
                                exp.toBigInteger().toString(), new String(sb) };

                        setError(req, CMS.getUserMessage("CMS_POLICY_EXPONENT_VIOLATION", params), "");
                        result = PolicyResult.REJECTED;
                    }
                }
            }
        } catch (Exception e) {
            // e.printStackTrace();
            String params[] = { getInstanceName(), e.toString() };

            setError(req, CMS.getUserMessage("CMS_POLICY_UNEXPECTED_POLICY_ERROR", params), "");
            result = PolicyResult.REJECTED;
        }
        return result;
    }

    /**
     * Return configured parameters for a policy rule instance.
     *
     * @return nvPairs A Vector of name/value pairs.
     */
    public Vector<String> getInstanceParams() {
        Vector<String> confParams = new Vector<String>();

        confParams.addElement(PROP_MIN_SIZE + "=" + mMinSize);
        confParams.addElement(PROP_MAX_SIZE + "=" + mMaxSize);
        StringBuffer sb = new StringBuffer();

        for (Enumeration<BigInt> e = mExponents.elements(); e.hasMoreElements();) {
            sb.append(e.nextElement().toInt());
            sb.append(",");
        }
        if (sb.length() > 0)
            sb.setLength(sb.length() - 1);
        confParams.addElement(PROP_EXPONENTS + "=" + sb.toString());
        return confParams;
    }

    /**
     * Return default parameters for a policy implementation.
     *
     * @return nvPairs A Vector of name/value pairs.
     */
    public Vector<String> getDefaultParams() {
        return defConfParams;
    }
}
