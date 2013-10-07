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

import netscape.security.pkcs.PKCS10;
import netscape.security.util.DerInputStream;
import netscape.security.x509.X509CertInfo;

import org.mozilla.jss.pkix.cmc.TaggedRequest;
import org.mozilla.jss.pkix.crmf.CertReqMsg;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.profile.IProfileContext;
import com.netscape.certsrv.profile.IProfileInput;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.profile.common.EnrollProfile;

/**
 * This class implements the certificate request input.
 * This input populates 2 main fields to the enrollment page:
 * 1/ Certificate Request Type, 2/ Certificate Request
 * <p>
 *
 * This input usually is used by an enrollment profile for certificate requests.
 *
 * @version $Revision$, $Date$
 */
public class CertReqInput extends EnrollInput implements IProfileInput {
    public static final String VAL_CERT_REQUEST_TYPE =
            EnrollProfile.CTX_CERT_REQUEST_TYPE;
    public static final String VAL_CERT_REQUEST =
            EnrollProfile.CTX_CERT_REQUEST;

    public EnrollProfile mEnrollProfile = null;

    public CertReqInput() {
        addValueName(VAL_CERT_REQUEST_TYPE);
        addValueName(VAL_CERT_REQUEST);
    }

    /**
     * Initializes this default policy.
     */
    public void init(IProfile profile, IConfigStore config)
            throws EProfileException {
        super.init(profile, config);

        mEnrollProfile = (EnrollProfile) profile;
    }

    /**
     * Retrieves the localizable name of this policy.
     */
    public String getName(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_INPUT_CERT_REQ_NAME");
    }

    /**
     * Retrieves the localizable description of this policy.
     */
    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_INPUT_CERT_REQ_TEXT");
    }

    /**
     * Populates the request with this policy default.
     */
    public void populate(IProfileContext ctx, IRequest request)
            throws EProfileException {
        String cert_request_type = ctx.get(VAL_CERT_REQUEST_TYPE);
        String cert_request = ctx.get(VAL_CERT_REQUEST);
        X509CertInfo info =
                request.getExtDataInCertInfo(EnrollProfile.REQUEST_CERTINFO);

        if (cert_request_type == null) {
            CMS.debug("CertReqInput: populate - invalid cert request type " +
                    "");
            throw new EProfileException(
                    CMS.getUserMessage(getLocale(request),
                            "CMS_PROFILE_UNKNOWN_CERT_REQ_TYPE",
                            ""));
        }
        if (cert_request == null) {
            CMS.debug("CertReqInput: populate - invalid certificate request");
            throw new EProfileException(CMS.getUserMessage(
                        getLocale(request), "CMS_PROFILE_NO_CERT_REQ"));
        }

        if (cert_request_type.equals(EnrollProfile.REQ_TYPE_PKCS10)) {
            PKCS10 pkcs10 = mEnrollProfile.parsePKCS10(getLocale(request), cert_request);

            if (pkcs10 == null) {
                throw new EProfileException(CMS.getUserMessage(
                            getLocale(request), "CMS_PROFILE_NO_CERT_REQ"));
            }

            mEnrollProfile.fillPKCS10(getLocale(request), pkcs10, info, request);
        } else if (cert_request_type.startsWith(EnrollProfile.REQ_TYPE_KEYGEN)) {
            DerInputStream keygen = mEnrollProfile.parseKeyGen(getLocale(request), cert_request);

            if (keygen == null) {
                throw new EProfileException(CMS.getUserMessage(
                            getLocale(request), "CMS_PROFILE_NO_CERT_REQ"));
            }

            mEnrollProfile.fillKeyGen(getLocale(request), keygen, info, request);
        } else if (cert_request_type.startsWith(EnrollProfile.REQ_TYPE_CRMF)) {
            CertReqMsg msgs[] = mEnrollProfile.parseCRMF(getLocale(request), cert_request);

            if (msgs == null) {
                throw new EProfileException(CMS.getUserMessage(
                            getLocale(request), "CMS_PROFILE_NO_CERT_REQ"));
            }
            for (int x = 0; x < msgs.length; x++) {
                verifyPOP(getLocale(request), msgs[x]);
            }
            // This profile only handle the first request in CRMF
            Integer seqNum = request.getExtDataInInteger(EnrollProfile.REQUEST_SEQ_NUM);

            mEnrollProfile.fillCertReqMsg(getLocale(request), msgs[seqNum.intValue()], info, request
                    );
        } else if (cert_request_type.startsWith(EnrollProfile.REQ_TYPE_CMC)) {
            TaggedRequest msgs[] = mEnrollProfile.parseCMC(getLocale(request), cert_request);

            if (msgs == null) {
                throw new EProfileException(CMS.getUserMessage(
                            getLocale(request), "CMS_PROFILE_NO_CERT_REQ"));
            }
            // This profile only handle the first request in CRMF
            Integer seqNum = request.getExtDataInInteger(EnrollProfile.REQUEST_SEQ_NUM);
            if (seqNum == null) {
                throw new EProfileException(
                        CMS.getUserMessage(getLocale(request),
                                "CMS_PROFILE_UNKNOWN_SEQ_NUM"));
            }

            mEnrollProfile.fillTaggedRequest(getLocale(request), msgs[seqNum.intValue()], info, request);
        } else {
            // error
            CMS.debug("CertReqInput: populate - invalid cert request type " +
                    cert_request_type);
            throw new EProfileException(
                    CMS.getUserMessage(getLocale(request),
                            "CMS_PROFILE_UNKNOWN_CERT_REQ_TYPE",
                            cert_request_type));
        }
        request.setExtData(EnrollProfile.REQUEST_CERTINFO, info);
    }

    /**
     * Retrieves the descriptor of the given value
     * parameter by name.
     */
    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(VAL_CERT_REQUEST_TYPE)) {
            return new Descriptor(IDescriptor.CERT_REQUEST_TYPE, null,
                    null,
                    CMS.getUserMessage(locale,
                            "CMS_PROFILE_INPUT_CERT_REQ_TYPE"));
        } else if (name.equals(VAL_CERT_REQUEST)) {
            return new Descriptor(IDescriptor.CERT_REQUEST, null,
                    null,
                    CMS.getUserMessage(locale,
                            "CMS_PROFILE_INPUT_CERT_REQ"));
        }
        return null;
    }
}
