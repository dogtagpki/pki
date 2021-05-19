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
package com.netscape.cms.profile.input;

import java.util.Locale;
import java.util.Map;

import org.mozilla.jss.netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.profile.common.EnrollProfile;
import com.netscape.cms.profile.common.Profile;
import com.netscape.cmscore.apps.CMS;

/**
 * This class implements the certificate request input from TPS.
 * This input populates 2 main fields to the enrollment "page":
 * 1/ id, 2/ publickey
 * <p>
 *
 * This input usually is used by an enrollment profile for certificate requests coming from TPS.
 *
 * @version $Revision$, $Date$
 */
public class nsNKeyCertReqInput extends EnrollInput {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(nsNKeyCertReqInput.class);

    public static final String VAL_SN = "screenname";
    public static final String VAL_PUBLIC_KEY = "publickey";

    public EnrollProfile mEnrollProfile = null;

    public nsNKeyCertReqInput() {
        addValueName(VAL_SN);
        addValueName(VAL_PUBLIC_KEY);
    }

    /**
     * Initializes this default policy.
     */
    @Override
    public void init(Profile profile, IConfigStore config)
            throws EProfileException {
        super.init(profile, config);

        mEnrollProfile = (EnrollProfile) profile;
    }

    /**
     * Retrieves the localizable name of this policy.
     */
    @Override
    public String getName(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_INPUT_TOKENKEY_CERT_REQ_NAME");
    }

    /**
     * Retrieves the localizable description of this policy.
     */
    @Override
    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_INPUT_TOKENKEY_CERT_REQ_TEXT");
    }

    /**
     * Populates the request with this policy default.
     */
    @Override
    public void populate(Map<String, String> ctx, IRequest request) throws Exception {

        String sn = ctx.get(VAL_SN);
        String pk = ctx.get(VAL_PUBLIC_KEY);
        X509CertInfo info =
                request.getExtDataInCertInfo(EnrollProfile.REQUEST_CERTINFO);

        if (sn == null) {
            logger.error("nsNKeyCertReqInput: populate - id not found");
            throw new EProfileException(
                    CMS.getUserMessage(getLocale(request),
                            "CMS_PROFILE_TOKENKEY_NO_ID",
                            ""));
        }
        if (pk == null) {
            logger.error("nsNKeyCertReqInput: populate - public key not found");
            throw new EProfileException(
                    CMS.getUserMessage(getLocale(request),
                            "CMS_PROFILE_TOKENKEY_NO_PUBLIC_KEY",
                            ""));
        }

        mEnrollProfile.fillNSNKEY(getLocale(request), sn, pk, info, request);
        request.setExtData(EnrollProfile.REQUEST_CERTINFO, info);
    }

    /**
     * Retrieves the descriptor of the given value
     * parameter by name.
     */
    @Override
    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(VAL_SN)) {
            return new Descriptor(IDescriptor.STRING, null,
                    null,
                    CMS.getUserMessage(locale,
                            "CMS_PROFILE_INPUT_TOKENKEY_CERT_REQ_UID"));
        } else if (name.equals(VAL_PUBLIC_KEY)) {
            return new Descriptor(IDescriptor.STRING, null,
                    null,
                    CMS.getUserMessage(locale,
                            "CMS_PROFILE_INPUT_TOKENKEY_CERT_REQ_PK"));
        }
        return null;
    }
}
