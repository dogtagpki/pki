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
package com.netscape.cms.profile.constraint;

import java.util.Locale;
import java.util.StringTokenizer;
import java.util.Vector;

import netscape.security.x509.AlgorithmId;
import netscape.security.x509.CertificateAlgorithmId;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.ERejectException;
import com.netscape.certsrv.profile.IPolicyDefault;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.profile.def.NoDefault;
import com.netscape.cms.profile.def.SigningAlgDefault;
import com.netscape.cms.profile.def.UserSigningAlgDefault;

/**
 * This class implements the signing algorithm constraint.
 * It checks if the signing algorithm in the certificate
 * template satisfies the criteria.
 *
 * @version $Revision$, $Date$
 */
public class SigningAlgConstraint extends EnrollConstraint {

    public static final String CONFIG_ALGORITHMS_ALLOWED = "signingAlgsAllowed";

    private static StringBuffer sb = new StringBuffer("");
    static {
        for (int i = 0; i < AlgorithmId.ALL_SIGNING_ALGORITHMS.length; i++) {
            if (i > 0) {
                sb.append(",");
            }
            sb.append(AlgorithmId.ALL_SIGNING_ALGORITHMS[i]);
        }
    }
    public static final String DEF_CONFIG_ALGORITHMS = new String(sb);

    public SigningAlgConstraint() {
        super();
        addConfigName(CONFIG_ALGORITHMS_ALLOWED);
    }

    public void init(IProfile profile, IConfigStore config)
            throws EProfileException {
        super.init(profile, config);
    }

    public void setConfig(String name, String value)
            throws EPropertyException {

        if (mConfig.getSubStore("params") == null) {
            CMS.debug("SigningAlgConstraint: mConfig.getSubStore is null");
        } else {
            CMS.debug("SigningAlgConstraint: setConfig name=" + name +
                    " value=" + value);

            if (name.equals(CONFIG_ALGORITHMS_ALLOWED)) {
                StringTokenizer st = new StringTokenizer(value, ",");
                while (st.hasMoreTokens()) {
                    String v = st.nextToken();
                    if (DEF_CONFIG_ALGORITHMS.indexOf(v) == -1) {
                        throw new EPropertyException(
                                CMS.getUserMessage("CMS_PROFILE_PROPERTY_ERROR", v));
                    }
                }
            }
            mConfig.getSubStore("params").putString(name, value);
        }
    }

    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        if (name.equals(CONFIG_ALGORITHMS_ALLOWED)) {
            return new Descriptor(IDescriptor.STRING, null,
                    DEF_CONFIG_ALGORITHMS,
                    CMS.getUserMessage(locale,
                            "CMS_PROFILE_SIGNING_ALGORITHMS_ALLOWED"));
        }
        return null;
    }

    /**
     * Validates the request. The request is not modified
     * during the validation.
     */
    public void validate(IRequest request, X509CertInfo info)
            throws ERejectException {
        CertificateAlgorithmId algId = null;

        try {
            algId = (CertificateAlgorithmId) info.get(X509CertInfo.ALGORITHM_ID);
            AlgorithmId id = (AlgorithmId)
                    algId.get(CertificateAlgorithmId.ALGORITHM);

            Vector<String> mCache = new Vector<String>();
            StringTokenizer st = new StringTokenizer(
                    getConfig(CONFIG_ALGORITHMS_ALLOWED), ",");

            while (st.hasMoreTokens()) {
                String token = st.nextToken();

                mCache.addElement(token);
            }

            if (!mCache.contains(id.toString())) {
                throw new ERejectException(CMS.getUserMessage(
                            getLocale(request),
                            "CMS_PROFILE_SIGNING_ALGORITHM_NOT_MATCHED", id.toString()));
            }
        } catch (Exception e) {
            if (e instanceof ERejectException) {
                throw (ERejectException) e;
            }
            CMS.debug("SigningAlgConstraint: " + e.toString());
            throw new ERejectException(CMS.getUserMessage(
                        getLocale(request), "CMS_PROFILE_SIGNING_ALGORITHM_NOT_FOUND"));
        }

    }

    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_CONSTRAINT_SIGNING_ALG_TEXT",
                getConfig(CONFIG_ALGORITHMS_ALLOWED));
    }

    public boolean isApplicable(IPolicyDefault def) {
        if (def instanceof NoDefault)
            return true;
        if (def instanceof UserSigningAlgDefault)
            return true;
        if (def instanceof SigningAlgDefault)
            return true;
        return false;
    }
}
