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

import netscape.security.x509.CertificateX509Key;
import netscape.security.x509.X509CertInfo;
import netscape.security.x509.X509Key;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.policy.EPolicyException;
import com.netscape.certsrv.policy.IEnrollmentPolicy;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.PolicyResult;
import com.netscape.cms.policy.APolicyRule;

/**
 * KeyAlgorithmConstraints enforces a constraint that the RA or a CA
 * honor only the keys generated using one of the permitted algorithms
 * such as RSA, DSA or DH.
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
public class KeyAlgorithmConstraints extends APolicyRule
        implements IEnrollmentPolicy, IExtendedPluginInfo {
    private Vector<String> mAlgorithms;
    private final static String DEF_KEY_ALGORITHM = "RSA,DSA";
    private final static String PROP_ALGORITHMS = "algorithms";
    private final static String[] supportedAlgorithms =
        { "RSA", "DSA", "DH" };

    private final static Vector<String> defConfParams = new Vector<String>();

    static {
        defConfParams.addElement(PROP_ALGORITHMS + "=" +
                DEF_KEY_ALGORITHM);
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        String params[] = {
                "algorithms;choice(RSA\\,DSA,RSA,DSA);Certificate's key can be one of these algorithms",
                IExtendedPluginInfo.HELP_TOKEN +
                        ";configuration-policyrules-keyalgorithmconstraints",
                IExtendedPluginInfo.HELP_TEXT +
                        ";Rejects the request if the key in the certificate is " +
                        "not of the type specified"
            };

        return params;
    }

    public KeyAlgorithmConstraints() {
        NAME = "KeyAlgorithmConstraints";
        DESC = "Enforces Key Algorithm Constraints.";
    }

    /**
     * Initializes this policy rule.
     * <P>
     *
     * The entries probably are of the form ra.Policy.rule.<ruleName>.implName=KeyAlgorithmConstraints
     * ra.Policy.rule.<ruleName>.algorithms=RSA,DSA ra.Policy.rule.<ruleName>.enable=true
     * ra.Policy.rule.<ruleName>.predicate=ou==Sales
     *
     * @param config The config store reference
     */
    public void init(ISubsystem owner, IConfigStore config)
            throws EPolicyException {

        mAlgorithms = new Vector<String>();

        if (config == null || config.size() == 0) {
            mAlgorithms.addElement(DEF_KEY_ALGORITHM);
            return;
        }

        // Get Algorithm names
        String algNames = null;

        try {
            algNames = config.getString(PROP_ALGORITHMS, null);
        } catch (Exception e) {
            String[] params = { getInstanceName(), e.toString() };

            throw new EPolicyException(
                    CMS.getUserMessage("CMS_POLICY_INVALID_POLICY_CONFIG", params));
        }

        if (algNames == null) {
            mAlgorithms.addElement(DEF_KEY_ALGORITHM);
            return;
        }
        StringTokenizer tok = new StringTokenizer(algNames, ",");

        while (tok.hasMoreTokens()) {
            String alg = tok.nextToken().trim().toUpperCase();

            if (alg.length() == 0)
                continue;
            mAlgorithms.addElement(alg);
        }

        // Check if configured algorithms are supported.
        for (Enumeration<String> e = mAlgorithms.elements(); e.hasMoreElements();) {
            int i;
            String configuredAlg = e.nextElement();

            // See if it is a supported algorithm.
            for (i = 0; i < supportedAlgorithms.length; i++) {
                if (configuredAlg.equals(supportedAlgorithms[i]))
                    break;
            }

            // Did we not find it?
            if (i == supportedAlgorithms.length)
                throw new EPolicyException(
                        CMS.getUserMessage("CMS_POLICY_UNSUPPORTED_KEY_ALG",
                                getInstanceName(), configuredAlg));
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
            // X509CertInfo certInfo[] = (X509CertInfo[])
            //    req.get(IRequest.CERT_INFO);
            X509CertInfo certInfo[] = req.getExtDataInCertInfoArray(IRequest.CERT_INFO);

            // We need to have a certificate info set
            if (certInfo == null) {
                setError(req, CMS.getUserMessage("CMS_POLICY_NO_CERT_INFO",
                        getInstanceName()), "");
                return PolicyResult.REJECTED;
            }

            // Else check if the key algorithm is supported.
            for (int i = 0; i < certInfo.length; i++) {
                CertificateX509Key certKey = (CertificateX509Key)
                        certInfo[i].get(X509CertInfo.KEY);
                X509Key key = (X509Key) certKey.get(CertificateX509Key.KEY);
                String alg = key.getAlgorithmId().getName().toUpperCase();

                if (!mAlgorithms.contains(alg)) {
                    setError(req, CMS.getUserMessage("CMS_POLICY_KEY_ALG_VIOLATION",
                            getInstanceName(), alg), "");
                    result = PolicyResult.REJECTED;
                }
            }
        } catch (Exception e) {
            String params[] = { getInstanceName(), e.toString() };

            setError(req, CMS.getUserMessage("CMS_POLICY_UNEXPECTED_POLICY_ERROR",
                    params), "");
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
        Vector<String> v = new Vector<String>();
        StringBuffer sb = new StringBuffer();

        for (Enumeration<String> e = mAlgorithms.elements(); e.hasMoreElements();) {
            sb.append(e.nextElement());
            sb.append(",");
        }
        if (sb.length() > 0)
            sb.setLength(sb.length() - 1);
        v.addElement(PROP_ALGORITHMS + "=" + sb.toString());
        return v;
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
