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


import java.security.cert.*;
import java.io.*;
import java.util.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.profile.*;
import com.netscape.certsrv.request.*;
import com.netscape.certsrv.property.*;
import com.netscape.certsrv.apps.*;

import netscape.security.x509.*;
import netscape.security.util.*;
import netscape.security.pkcs.*;

import com.netscape.cms.profile.common.*;

import org.mozilla.jss.asn1.*;
import org.mozilla.jss.pkix.primitive.*;
import org.mozilla.jss.pkix.crmf.*;
import org.mozilla.jss.pkix.cmc.*;
import org.mozilla.jss.pkcs10.*;


/**
 * This class implements the certificate request input.
 * This input populates 2 main fields to the enrollment page:
 * 1/ Certificate Request Type, 2/ Certificate Request
 * <p>
 * 
 * This input usually is used by an enrollment profile for
 * certificate requests.
 *
 * @version $Revision$, $Date$
 */
public class CMCCertReqInput extends EnrollInput implements IProfileInput { 
    public static final String VAL_CERT_REQUEST_TYPE = 
        EnrollProfile.CTX_CERT_REQUEST_TYPE;
    public static final String VAL_CERT_REQUEST =
        EnrollProfile.CTX_CERT_REQUEST;

    public EnrollProfile mEnrollProfile = null;

    public CMCCertReqInput() {
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
        String cert_request = ctx.get(VAL_CERT_REQUEST);
        X509CertInfo info =
            request.getExtDataInCertInfo(EnrollProfile.REQUEST_CERTINFO);

        if (cert_request == null) {
            CMS.debug("CMCCertReqInput: populate - invalid certificate request");
            throw new EProfileException(CMS.getUserMessage(
                        getLocale(request), "CMS_PROFILE_NO_CERT_REQ"));
        }
        TaggedRequest msgs[] = mEnrollProfile.parseCMC(getLocale(request), cert_request);

        if (msgs == null) {
            CMS.debug("CMCCertReqInput: populate - parseCMC returns null TaggedRequest msgs");
            return; 
        }
        // This profile only handle the first request in CRMF
        Integer seqNum = request.getExtDataInInteger(EnrollProfile.REQUEST_SEQ_NUM);
        if (seqNum == null) {
           throw new EProfileException(
            CMS.getUserMessage(getLocale(request),
                "CMS_PROFILE_UNKNOWN_SEQ_NUM")); 
        }

        mEnrollProfile.fillTaggedRequest(getLocale(request), msgs[seqNum.intValue()], info, request);
        request.setExtData(EnrollProfile.REQUEST_CERTINFO, info);
    }

    /**
     * Retrieves the descriptor of the given value
     * parameter by name.
     */
    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(VAL_CERT_REQUEST)) {
            return new Descriptor(IDescriptor.CERT_REQUEST, null,
                    null,
                    CMS.getUserMessage(locale,
                        "CMS_PROFILE_INPUT_CERT_REQ"));
        } 
        return null;
    }
}
