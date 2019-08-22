//--- BEGIN COPYRIGHT BLOCK ---
//This program is free software; you can redistribute it and/or modify
//it under the terms of the GNU General Public License as published by
//the Free Software Foundation; version 2 of the License.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License along
//with this program; if not, write to the Free Software Foundation, Inc.,
//51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
//(C) 2012 Red Hat, Inc.
//All rights reserved.
//--- END COPYRIGHT BLOCK ---
package com.netscape.cms.servlet.cert;

import java.util.Enumeration;
import java.util.Locale;

import javax.servlet.http.HttpServletRequest;

import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.cert.CertEnrollmentRequest;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.profile.IProfileInput;
import com.netscape.certsrv.profile.ProfileInput;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.profile.ProfileInputFactory;

public class CertEnrollmentRequestFactory {

    public static CertEnrollmentRequest create(CMSRequest cmsReq, IProfile profile, Locale locale)
            throws EProfileException {
        IArgBlock params = cmsReq.getHttpParams();

        CertEnrollmentRequest request = create(params, profile, locale);

        HttpServletRequest httpRequest = cmsReq.getHttpReq();
        request.setRemoteHost(httpRequest.getRemoteHost());
        request.setRemoteAddr(httpRequest.getRemoteAddr());

        return request;
    }

    public static CertEnrollmentRequest create(IArgBlock params, IProfile profile, Locale locale)
            throws EProfileException {
        CertEnrollmentRequest request = new CertEnrollmentRequest();
        request.setProfileId(profile.getId());

        // populate profile inputs
        Enumeration<String> inputIds = profile.getProfileInputIds();
        while (inputIds.hasMoreElements()) {
            IProfileInput input = profile.getProfileInput(inputIds.nextElement());
            ProfileInput addInput = ProfileInputFactory.create(input, params, locale);
            request.addInput(addInput);
        }

        return request;
    }

}
