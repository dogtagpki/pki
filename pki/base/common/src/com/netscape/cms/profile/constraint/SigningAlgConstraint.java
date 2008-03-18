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


import java.util.*;
import java.io.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.ca.*;
import com.netscape.certsrv.profile.*;
import com.netscape.certsrv.request.*;
import com.netscape.certsrv.property.*;
import com.netscape.certsrv.apps.*;

import com.netscape.cms.profile.def.*;

import netscape.security.x509.*;


/**
 * This class implements the signing algorithm constraint.
 * It checks if the signing algorithm in the certificate
 * template satisfies the criteria.
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public class SigningAlgConstraint extends EnrollConstraint {

    public static final String CONFIG_ALGORITHMS_ALLOWED = "signingAlgsAllowed";

    public static final String DEF_CONFIG_ALGORITHMS =
      "MD5withRSA,MD2withRSA,SHA1withRSA,SHA256withRSA,SHA512withRSA";

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

            if(name.equals(CONFIG_ALGORITHMS_ALLOWED))
            {
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

            Vector mCache = new Vector();
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
        return CMS.getUserMessage(locale, "CMS_PROFILE_CONSTRAINT_SIGNING_ALG_TEXT", getConfig(CONFIG_ALGORITHMS_ALLOWED));
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
