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
import javax.ws.rs.core.UriInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.cert.CertReviewResponse;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.IPolicyDefault;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.profile.IProfileInput;
import com.netscape.certsrv.profile.IProfilePolicy;
import com.netscape.certsrv.profile.PolicyConstraint;
import com.netscape.certsrv.profile.PolicyDefault;
import com.netscape.certsrv.profile.ProfileInput;
import com.netscape.certsrv.profile.ProfilePolicy;
import com.netscape.certsrv.profile.ProfilePolicySet;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.processors.CAProcessor;
import com.netscape.cms.servlet.profile.PolicyConstraintFactory;
import com.netscape.cms.servlet.profile.PolicyDefaultFactory;
import com.netscape.cms.servlet.profile.ProfileInputFactory;

public class CertReviewResponseFactory {

    public static CertReviewResponse create(IRequest request, IProfile profile, UriInfo uriInfo, Locale locale) throws EBaseException {
        CertReviewResponse ret = new CertReviewResponse();

        if (request.getRequestType().equals("renewal")) {
            ret.setRenewal(true);
        } else {
            ret.setRenewal(false);
        }

        ret.setRequestId(request.getRequestId());
        ret.setRequestType(request.getRequestType());
        ret.setRequestStatus(request.getRequestStatus().toString());
        if (request.getRequestOwner() == null) {
            ret.setRequestOwner("");
        } else {
            ret.setRequestOwner(request.getRequestOwner());
        }
        ret.setRequestCreationTime(request.getCreationTime().toString());
        ret.setRequestModificationTime(request.getModificationTime().toString());

        ret.setProfileId(profile.getId());
        ret.setProfileApprovedBy(request.getExtDataInString("profileApprovedBy"));
        ret.setProfileSetId(request.getExtDataInString("profileSetId"));
        if (profile.isVisible()) {
            ret.setProfileIsVisible("true");
        } else {
            ret.setProfileIsVisible("false");
        }

        ret.setProfileName(profile.getName(locale));
        ret.setProfileDescription(profile.getDescription(locale));
        ret.setProfileRemoteHost(request.getExtDataInString("profileRemoteHost"));
        ret.setProfileRemoteAddr(request.getExtDataInString("profileRemoteAddr"));
        if (request.getExtDataInString("requestNotes") == null) {
            ret.setRequestNotes("");
        } else {
            ret.setRequestNotes(request.getExtDataInString("requestNotes"));
        }

        // populate profile inputs
        Enumeration<String> inputIds = profile.getProfileInputIds();
        while (inputIds.hasMoreElements()) {
            IProfileInput input = profile.getProfileInput(inputIds.nextElement());
            ProfileInput addInput = ProfileInputFactory.create(input, request, locale);
            ret.addInput(addInput);
        }

        String profileSetId = request.getExtDataInString("profileSetId");
        CMS.debug("createAgentCertRequestInfo: profileSetId=" + profileSetId);
        Enumeration<String> policyIds = (profileSetId != null && profileSetId.length() > 0) ?
                profile.getProfilePolicyIds(profileSetId) : null;
        ProfilePolicySet dataPolicySet = new ProfilePolicySet();

        if (policyIds != null) {
            while (policyIds.hasMoreElements()) {
                String id = policyIds.nextElement();
                CMS.debug("policyId:" + id);
                IProfilePolicy policy = profile.getProfilePolicy(profileSetId, id);
                ProfilePolicy dataPolicy = new ProfilePolicy();

                //populate defaults
                IPolicyDefault def = policy.getDefault();
                PolicyDefault dataDef = PolicyDefaultFactory.create(request, locale, def);
                dataPolicy.setDef(dataDef);

                //populate constraints
                // TODO - fix this.
                PolicyConstraint dataCons = PolicyConstraintFactory.create(locale, policy.getConstraint(),
                        policy.getConstraint().getClass().getSimpleName());
                dataPolicy.setConstraint(dataCons);

                dataPolicySet.addPolicy(dataPolicy);
            }
        }


        ret.addProfilePolicySet(dataPolicySet);

        // TODO populate profile outputs
        return ret;
    }

    public static CertReviewResponse create(
            CMSRequest cmsReq, IProfile profile, boolean noncesEnabled, Locale locale)
            throws EPropertyException, EProfileException {
        HttpServletRequest req = cmsReq.getHttpReq();
        IRequest ireq = cmsReq.getIRequest();
        IArgBlock params = cmsReq.getHttpParams();

        CertReviewResponse ret = new CertReviewResponse();
        ret.setProfileId(profile.getId());
        ret.setRequestNotes(req.getParameter("requestNotes"));
        ret.setRequestId(ireq.getRequestId());

        if (noncesEnabled) {
            ret.setNonce(req.getParameter(CAProcessor.ARG_REQUEST_NONCE));
        }

        // populate profile policy values
        String profileSetId = ireq.getExtDataInString("profileSetId");
        Enumeration<String> policyIds = (profileSetId != null && profileSetId.length() > 0) ?
                profile.getProfilePolicyIds(profileSetId) : null;
        ProfilePolicySet dataPolicySet = new ProfilePolicySet();

        if (policyIds != null) {
            while (policyIds.hasMoreElements()) {
                String id = policyIds.nextElement();
                CMS.debug("policyId:" + id);
                IProfilePolicy policy = profile.getProfilePolicy(profileSetId, id);
                com.netscape.certsrv.profile.ProfilePolicy dataPolicy =
                        new com.netscape.certsrv.profile.ProfilePolicy();

                //populate defaults
                IPolicyDefault def = policy.getDefault();
                PolicyDefault dataDef = PolicyDefaultFactory.create(params, locale, def);
                dataPolicy.setDef(dataDef);

                dataPolicySet.addPolicy(dataPolicy);
                CMS.debug(dataPolicy.toString());
            }
        }

        ret.addProfilePolicySet(dataPolicySet);

        return ret;
    }

}
