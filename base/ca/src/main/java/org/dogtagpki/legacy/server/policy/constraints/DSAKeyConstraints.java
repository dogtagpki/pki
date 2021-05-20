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
package org.dogtagpki.legacy.server.policy.constraints;

import java.math.BigInteger;
import java.security.interfaces.DSAParams;
import java.util.Locale;
import java.util.Vector;

import org.dogtagpki.legacy.policy.EPolicyException;
import org.dogtagpki.legacy.policy.IEnrollmentPolicy;
import org.dogtagpki.legacy.policy.IPolicyProcessor;
import org.dogtagpki.legacy.server.policy.APolicyRule;
import org.mozilla.jss.netscape.security.provider.DSAPublicKey;
import org.mozilla.jss.netscape.security.x509.CertificateX509Key;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.mozilla.jss.netscape.security.x509.X509Key;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.PolicyResult;
import com.netscape.cmscore.apps.CMS;

/**
 * DSAKeyConstraints policy enforces min and max size of the key.
 * <P>
 *
 * <PRE>
 * NOTE:  The Policy Framework has been replaced by the Profile Framework.
 * </PRE>
 * <P>
 *
 * @version $Revision$, $Date$
 */
public class DSAKeyConstraints extends APolicyRule
        implements IEnrollmentPolicy, IExtendedPluginInfo {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(DSAKeyConstraints.class);

    private int mMinSize;
    private int mMaxSize;

    private final static int INCREMENT = 64;
    private final static int DEF_MIN_SIZE = 512;
    private final static int DEF_MAX_SIZE = 1024;

    private final static String DSA = "DSA";
    private final static String PROP_MIN_SIZE = "minSize";
    private final static String PROP_MAX_SIZE = "maxSize";

    private final static Vector<String> defConfParams = new Vector<>();

    private IConfigStore mConfig = null;

    static {
        defConfParams.addElement(PROP_MIN_SIZE + "=" + DEF_MIN_SIZE);
        defConfParams.addElement(PROP_MAX_SIZE + "=" + DEF_MAX_SIZE);
    }

    public DSAKeyConstraints() {
        NAME = "DSAKeyConstraints";
        DESC = "Enforces DSA Key Constraints.";
    }

    @Override
    public String[] getExtendedPluginInfo(Locale locale) {
        String[] params = {
                PROP_MIN_SIZE + ";number;Minimum key size",
                PROP_MAX_SIZE + ";number;Maximum key size",
                IExtendedPluginInfo.HELP_TOKEN +
                        ";configuration-policyrules-dsakeyconstraints",
                IExtendedPluginInfo.HELP_TEXT +
                        ";Rejects request if DSA key size is out of range"
            };

        return params;
    }

    /**
     * Initializes this policy rule.
     * <P>
     *
     * The entries probably are of the form ra.Policy.rule.<ruleName>.implName=DSAKeyConstraints
     * ra.Policy.rule.<ruleName>.enable=true ra.Policy.rule.<ruleName>.minSize=512
     * ra.Policy.rule.<ruleName>.maxSize=1024 ra.Policy.rule.<ruleName>.predicate= ou == engineering AND o ==
     * netscape.com
     *
     * @param config The config store reference
     */
    @Override
    public void init(IPolicyProcessor owner, IConfigStore config)
            throws EPolicyException {

        // Get Min and Max sizes
        mConfig = config;

        try {
            mMinSize = config.getInteger(PROP_MIN_SIZE, DEF_MIN_SIZE);
            mMaxSize = config.getInteger(PROP_MAX_SIZE, DEF_MAX_SIZE);

            if (mMaxSize > DEF_MAX_SIZE) {
                String msg = "cannot be more than " + DEF_MAX_SIZE;

                logger.error(PROP_MAX_SIZE + " " + msg);
                throw new EBaseException(
                        CMS.getUserMessage("CMS_BASE_INVALID_ATTR_VALUE",
                                PROP_MAX_SIZE, msg));
            }
            if (mMinSize < DEF_MIN_SIZE) {
                String msg = "cannot be less than " + DEF_MIN_SIZE;

                logger.error(PROP_MIN_SIZE + " " + msg);
                throw new EBaseException(
                        CMS.getUserMessage("CMS_BASE_INVALID_ATTR_VALUE",
                                PROP_MIN_SIZE, msg));
            }
            if (mMaxSize % INCREMENT != 0) {
                String msg = "must be in increments of " + INCREMENT;

                logger.error(PROP_MAX_SIZE + " " + msg);
                throw new EBaseException(
                        CMS.getUserMessage("CMS_BASE_INVALID_ATTR_VALUE",
                                PROP_MIN_SIZE, msg));
            }
            if (mMaxSize % INCREMENT != 0) {
                String msg = "must be in increments of " + INCREMENT;

                logger.error(PROP_MIN_SIZE + " " + msg);
                throw new EBaseException(
                        CMS.getUserMessage("CMS_BASE_INVALID_ATTR_VALUE",
                                PROP_MIN_SIZE, msg));
            }

            config.putInteger(PROP_MIN_SIZE, mMinSize);
            config.putInteger(PROP_MAX_SIZE, mMaxSize);

        } catch (Exception e) {
            throw new EPolicyException(
                    CMS.getUserMessage("CMS_POLICY_INVALID_POLICY_CONFIG", getInstanceName(), e.toString()));
        }
    }

    /**
     * Applies the policy on the given Request.
     * <P>
     *
     * @param req The request on which to apply policy.
     * @return The policy result object.
     */
    @Override
    public PolicyResult apply(IRequest req) {

        PolicyResult result = PolicyResult.ACCEPTED;

        try {
            // Get the certificate info from the request
            X509CertInfo ci[] =
                    req.getExtDataInCertInfoArray(IRequest.CERT_INFO);

            // There should be a certificate info set.
            if (ci == null || ci[0] == null) {
                setError(req, CMS.getUserMessage("CMS_POLICY_NO_CERT_INFO", NAME), "");
                return PolicyResult.REJECTED;
            }

            // Else check if the key size(s) are within the limit.
            for (int i = 0; i < ci.length; i++) {
                CertificateX509Key certKey = (CertificateX509Key)
                        ci[i].get(X509CertInfo.KEY);
                X509Key key = (X509Key) certKey.get(CertificateX509Key.KEY);
                String alg = key.getAlgorithmId().toString();

                if (!alg.equalsIgnoreCase(DSA))
                    continue;

                // Check DSAKey parameters.
                // size refers to the p parameter.
                DSAPublicKey dsaKey = new DSAPublicKey(key.getEncoded());
                DSAParams keyParams = dsaKey.getParams();

                if (keyParams == null) {
                    // key parameters could not be parsed.
                    setError(req,
                            CMS.getUserMessage("CMS_POLICY_NO_KEY_PARAMS", getInstanceName(), String.valueOf(i + 1)),
                            "");
                    return PolicyResult.REJECTED;
                }
                BigInteger p = keyParams.getP();
                int len = p.bitLength();

                if (len < mMinSize || len > mMaxSize ||
                        (len % INCREMENT) != 0) {
                    String[] parms = new String[] {
                            getInstanceName(),
                            String.valueOf(len),
                            String.valueOf(mMinSize),
                            String.valueOf(mMaxSize),
                            String.valueOf(INCREMENT) };

                    setError(req, CMS.getUserMessage("CMS_POLICY_KEY_SIZE_VIOLATION_1", parms), "");
                    return PolicyResult.REJECTED;
                }
            }
        } catch (Exception e) {
            // e.printStackTrace();
            String[] params = { getInstanceName(), e.toString() };

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
    @Override
    public Vector<String> getInstanceParams() {
        Vector<String> confParams = new Vector<>();

        try {
            confParams.addElement(PROP_MIN_SIZE + "=" + mConfig.getInteger(PROP_MIN_SIZE, DEF_MIN_SIZE));
            confParams.addElement(PROP_MAX_SIZE + "=" + mConfig.getInteger(PROP_MAX_SIZE, DEF_MAX_SIZE));
        } catch (EBaseException e) {
            ;
        }
        return confParams;
    }

    /**
     * Return default parameters for a policy implementation.
     *
     * @return nvPairs A Vector of name/value pairs.
     */
    @Override
    public Vector<String> getDefaultParams() {
        return defConfParams;
    }
}
