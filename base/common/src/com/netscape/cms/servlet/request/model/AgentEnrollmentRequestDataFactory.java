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
package com.netscape.cms.servlet.request.model;

import java.util.Enumeration;
import java.util.Locale;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.UriInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.base.Nonces;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.IPolicyDefault;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.profile.IProfileInput;
import com.netscape.certsrv.profile.IProfilePolicy;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.processors.Processor;
import com.netscape.cms.servlet.profile.model.PolicyConstraint;
import com.netscape.cms.servlet.profile.model.PolicyConstraintFactory;
import com.netscape.cms.servlet.profile.model.PolicyDefault;
import com.netscape.cms.servlet.profile.model.PolicyDefaultFactory;
import com.netscape.cms.servlet.profile.model.ProfileInput;
import com.netscape.cms.servlet.profile.model.ProfileInputFactory;
import com.netscape.cms.servlet.profile.model.ProfilePolicy;
import com.netscape.cms.servlet.profile.model.ProfilePolicySet;

public class AgentEnrollmentRequestDataFactory {

    public static AgentEnrollmentRequestData create(IRequest request, IProfile profile, UriInfo uriInfo, Locale locale) throws EBaseException {
        AgentEnrollmentRequestData ret = new AgentEnrollmentRequestData();

        if (request.getRequestType().equals("renewal")) {
            ret.setIsRenewal(true);
        } else {
            ret.setIsRenewal(false);
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
                PolicyConstraint dataCons = PolicyConstraintFactory.create(locale, policy.getConstraint());
                dataPolicy.setConstraint(dataCons);

                dataPolicySet.addPolicy(dataPolicy);
            }
        }


        ret.addProfilePolicySet(dataPolicySet);

        // TODO populate profile outputs
        return ret;
    }

    public static AgentEnrollmentRequestData create(CMSRequest cmsReq, IProfile profile, Nonces nonces, Locale locale)
            throws EPropertyException, EProfileException {
        HttpServletRequest req = cmsReq.getHttpReq();
        IRequest ireq = cmsReq.getIRequest();
        IArgBlock params = cmsReq.getHttpParams();

        AgentEnrollmentRequestData ret = new AgentEnrollmentRequestData();
        ret.setProfileId(profile.getId());
        ret.setRequestNotes(req.getParameter("requestNotes"));
        ret.setRequestId(ireq.getRequestId());

        if (nonces != null) {
            ret.setNonce(req.getParameter(Processor.ARG_REQUEST_NONCE));
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
                com.netscape.cms.servlet.profile.model.ProfilePolicy dataPolicy =
                        new com.netscape.cms.servlet.profile.model.ProfilePolicy();

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
