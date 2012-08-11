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
package com.netscape.certsrv.cert;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

import com.netscape.certsrv.profile.PolicyDefault;
import com.netscape.certsrv.profile.ProfileAttribute;
import com.netscape.certsrv.profile.ProfilePolicy;
import com.netscape.certsrv.profile.ProfilePolicySet;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestIdAdapter;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class CertReviewResponse extends CertEnrollmentRequest {

    @XmlElement(name="ProfilePolicySet")
    protected List<ProfilePolicySet> policySets = new ArrayList<ProfilePolicySet>();

    protected String nonce;

    @XmlElement
    @XmlJavaTypeAdapter(RequestIdAdapter.class)
    protected RequestId requestId;

    protected String requestType;

    protected String requestStatus;

    protected String requestOwner;

    protected String requestCreationTime;

    protected String requestModificationTime;

    protected String requestNotes;

    protected String profileApprovedBy;

    protected String profileSetId;

    protected String profileIsVisible;

    protected String profileName;

    protected String profileDescription;

    protected String profileRemoteHost;

    protected String profileRemoteAddr;

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public RequestId getRequestId() {
        return requestId;
    }

    public void setRequestId(RequestId requestId) {
        this.requestId = requestId;
    }

    public String getRequestType() {
        return requestType;
    }

    public void setRequestType(String requestType) {
        this.requestType = requestType;
    }

    public String getRequestStatus() {
        return requestStatus;
    }

    public void setRequestStatus(String requestStatus) {
        this.requestStatus = requestStatus;
    }

    public String getRequestOwner() {
        return requestOwner;
    }

    public void setRequestOwner(String requestOwner) {
        this.requestOwner = requestOwner;
    }

    public String getRequestCreationTime() {
        return requestCreationTime;
    }

    public void setRequestCreationTime(String requestCreationTime) {
        this.requestCreationTime = requestCreationTime;
    }

    public String getRequestModificationTime() {
        return requestModificationTime;
    }

    public void setRequestModificationTime(String requestModificationTime) {
        this.requestModificationTime = requestModificationTime;
    }

    public String getRequestNotes() {
        return requestNotes;
    }

    public void setRequestNotes(String requestNotes) {
        this.requestNotes = requestNotes;
    }

    public String getProfileApprovedBy() {
        return profileApprovedBy;
    }

    public void setProfileApprovedBy(String profileApprovedBy) {
        this.profileApprovedBy = profileApprovedBy;
    }

    public String getProfileSetId() {
        return profileSetId;
    }

    public void setProfileSetId(String profileSetId) {
        this.profileSetId = profileSetId;
    }

    public String getProfileIsVisible() {
        return profileIsVisible;
    }

    public void setProfileIsVisible(String profileIsVisible) {
        this.profileIsVisible = profileIsVisible;
    }

    public String getProfileName() {
        return profileName;
    }

    public void setProfileName(String profileName) {
        this.profileName = profileName;
    }

    public String getProfileDescription() {
        return profileDescription;
    }

    public void setProfileDescription(String profileDescription) {
        this.profileDescription = profileDescription;
    }

    public String getProfileRemoteHost() {
        return profileRemoteHost;
    }

    public void setProfileRemoteHost(String profileRemoteHost) {
        this.profileRemoteHost = profileRemoteHost;
    }

    public String getProfileRemoteAddr() {
        return profileRemoteAddr;
    }

    public void setProfileRemoteAddr(String profileRemoteAddr) {
        this.profileRemoteAddr = profileRemoteAddr;
    }

    public String toString() {
        try {
            JAXBContext context = JAXBContext.newInstance(CertReviewResponse.class);
            Marshaller marshaller = context.createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

            ByteArrayOutputStream stream = new ByteArrayOutputStream();

            marshaller.marshal(this, stream);
            return stream.toString();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public List<ProfilePolicySet> getPolicySets() {
        return policySets;
    }

    public void setPolicySets(List<ProfilePolicySet> policySets) {
        this.policySets = policySets;
    }

    public void addProfilePolicySet(ProfilePolicySet policySet) {
        policySets.add(policySet);
    }

    public void removeProfilePolicySet(ProfilePolicySet policySet) {
        policySets.remove(policySet);
    }

    @Override
    public HashMap<String,String> toParams() {
        HashMap<String,String> ret = super.toParams();

        if (requestId != null) ret.put("requestId", requestId.toString());
        if (requestNotes != null) ret.put("requestNotes", requestNotes);
        if (nonce != null) ret.put("nonces", nonce);
        if (requestType != null) ret.put("requestType", requestType);

        for (ProfilePolicySet policySet: policySets) {
            for (ProfilePolicy policy: policySet.getPolicies()) {
                PolicyDefault def = policy.getDef();
                List<ProfileAttribute> attrs = def.getAttributes();
                for (ProfileAttribute attr: attrs) {
                    ret.put(attr.getName(), attr.getValue());
                }
            }
        }
        return ret;
    }

}
