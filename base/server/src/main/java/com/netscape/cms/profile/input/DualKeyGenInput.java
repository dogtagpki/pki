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

import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.util.DerInputStream;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.mozilla.jss.pkix.crmf.CertReqMsg;

import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.profile.common.EnrollProfile;
import com.netscape.cms.profile.common.Profile;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.cert.CertUtils;

/**
 * This class implements the dual key generation input.
 * This input populates parameters to the enrollment
 * pages so that a CRMF request containing 2 certificate
 * requests will be generated.
 * <p>
 *
 * This input can only be used with Netscape 7.x or later clients.
 * <p>
 *
 * @version $Revision$, $Date$
 */
public class DualKeyGenInput extends EnrollInput {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(DualKeyGenInput.class);

    public static final String VAL_KEYGEN_REQUEST_TYPE =
            EnrollProfile.CTX_CERT_REQUEST_TYPE;
    public static final String VAL_KEYGEN_REQUEST =
            IRequest.CTX_CERT_REQUEST;

    public EnrollProfile mEnrollProfile = null;

    public DualKeyGenInput() {
        addValueName(VAL_KEYGEN_REQUEST_TYPE);
        addValueName(VAL_KEYGEN_REQUEST);
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
        return CMS.getUserMessage(locale, "CMS_PROFILE_INPUT_DUAL_KEY_NAME");
    }

    /**
     * Retrieves the localizable description of this policy.
     */
    @Override
    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_INPUT_DUAL_KEY_TEXT");
    }

    /**
     * Populates the request with this policy default.
     */
    @Override
    public void populate(Map<String, String> ctx, IRequest request) throws Exception {

        String keygen_request_type = ctx.get(VAL_KEYGEN_REQUEST_TYPE);
        String keygen_request = ctx.get(VAL_KEYGEN_REQUEST);

        X509CertInfo info =
                request.getExtDataInCertInfo(EnrollProfile.REQUEST_CERTINFO);

        if (keygen_request_type == null) {
            logger.error("DualKeyGenInput: populate - invalid cert request type");
            throw new EProfileException(
                    CMS.getUserMessage(getLocale(request),
                            "CMS_PROFILE_UNKNOWN_CERT_REQ_TYPE",
                            ""));
        }
        if (keygen_request == null) {
            logger.error("DualKeyGenInput: populate - invalid certificate request");
            throw new EProfileException(CMS.getUserMessage(
                        getLocale(request), "CMS_PROFILE_NO_CERT_REQ"));
        }
        if (keygen_request_type.startsWith("pkcs10")) {

            PKCS10 pkcs10 = CertUtils.parsePKCS10(getLocale(request), keygen_request);
            mEnrollProfile.fillPKCS10(getLocale(request), pkcs10, info, request);
        } else if (keygen_request_type.startsWith("keygen")) {

            DerInputStream keygen = CertUtils.parseKeyGen(getLocale(request), keygen_request);

            mEnrollProfile.fillKeyGen(getLocale(request), keygen, info, request);
        } else if (keygen_request_type.startsWith("crmf")) {

            CertReqMsg[] msgs = CertUtils.parseCRMF(getLocale(request), keygen_request);

            if (msgs == null) {
                throw new EProfileException(CMS.getUserMessage(
                            getLocale(request), "CMS_PROFILE_NO_CERT_REQ"));
            }
            for (int x = 0; x < msgs.length; x++) {
                verifyPOP(getLocale(request), msgs[x]);
            }
            // This profile only handle the first request in CRMF
            Integer seqNum = request.getExtDataInInteger(EnrollProfile.REQUEST_SEQ_NUM);

            if (seqNum == null) {
                throw new EProfileException(
                        CMS.getUserMessage(getLocale(request),
                                "CMS_PROFILE_UNKNOWN_SEQ_NUM"));
            }

            mEnrollProfile.fillCertReqMsg(getLocale(request), msgs[seqNum.intValue()], info, request);
        } else {
            logger.error("DualKeyGenInput: populate - invalid cert request type " + keygen_request_type);
            throw new EProfileException(CMS.getUserMessage(
                        getLocale(request),
                        "CMS_PROFILE_UNKNOWN_CERT_REQ_TYPE",
                        keygen_request_type));
        }
        request.setExtData(EnrollProfile.REQUEST_CERTINFO, info);
    }

    /**
     * Retrieves the descriptor of the given value
     * parameter by name.
     */
    @Override
    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(VAL_KEYGEN_REQUEST_TYPE)) {
            return new Descriptor(IDescriptor.DUAL_KEYGEN_REQUEST_TYPE, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_INPUT_KEYGEN_REQ_TYPE"));
        } else if (name.equals(VAL_KEYGEN_REQUEST)) {
            return new Descriptor(IDescriptor.DUAL_KEYGEN_REQUEST, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_INPUT_KEYGEN_REQ"));
        }
        return null;
    }
}
