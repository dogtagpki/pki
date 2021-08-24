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

import java.io.StringReader;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.netscape.certsrv.profile.PolicyDefault;
import com.netscape.certsrv.profile.ProfileAttribute;
import com.netscape.certsrv.profile.ProfilePolicy;
import com.netscape.certsrv.profile.ProfilePolicySet;
import com.netscape.certsrv.request.RequestId;

@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class CertReviewResponse extends CertEnrollmentRequest {

    @JsonProperty("ProfilePolicySet")
    protected List<ProfilePolicySet> policySets = new ArrayList<>();

    @JsonProperty
    protected String nonce;

    @JsonProperty
    protected RequestId requestId;

    @JsonProperty
    protected String requestType;

    @JsonProperty
    protected String requestStatus;

    @JsonProperty
    protected String requestOwner;

    @JsonProperty
    protected String requestCreationTime;

    @JsonProperty
    protected String requestModificationTime;

    @JsonProperty
    protected String requestNotes;

    @JsonProperty
    protected String profileApprovedBy;

    @JsonProperty
    protected String profileSetId;

    @JsonProperty
    protected String profileIsVisible;

    @JsonProperty
    protected String profileName;

    @JsonProperty
    protected String profileDescription;

    @JsonProperty
    protected String profileRemoteHost;

    @JsonProperty
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

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + Objects.hash(nonce, policySets, profileApprovedBy, profileDescription,
                profileIsVisible, profileName, profileRemoteAddr, profileRemoteHost, profileSetId, requestCreationTime,
                requestId, requestModificationTime, requestNotes, requestOwner, requestStatus, requestType);
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (!super.equals(obj))
            return false;
        if (getClass() != obj.getClass())
            return false;
        CertReviewResponse other = (CertReviewResponse) obj;
        return Objects.equals(nonce, other.nonce) && Objects.equals(policySets, other.policySets)
                && Objects.equals(profileApprovedBy, other.profileApprovedBy)
                && Objects.equals(profileDescription, other.profileDescription)
                && Objects.equals(profileIsVisible, other.profileIsVisible)
                && Objects.equals(profileName, other.profileName)
                && Objects.equals(profileRemoteAddr, other.profileRemoteAddr)
                && Objects.equals(profileRemoteHost, other.profileRemoteHost)
                && Objects.equals(profileSetId, other.profileSetId)
                && Objects.equals(requestCreationTime, other.requestCreationTime)
                && Objects.equals(requestId, other.requestId)
                && Objects.equals(requestModificationTime, other.requestModificationTime)
                && Objects.equals(requestNotes, other.requestNotes) && Objects.equals(requestOwner, other.requestOwner)
                && Objects.equals(requestStatus, other.requestStatus) && Objects.equals(requestType, other.requestType);
    }

    public Element toDOM(Document document) {

        Element element = document.createElement("certReviewResponse");

        toDOM(document, element);

        for (ProfilePolicySet profilePolicySet : policySets) {
            Element policySetElement = profilePolicySet.toDOM(document);
            element.appendChild(policySetElement);
        }

        if (nonce != null) {
            Element nonceElement = document.createElement("nonce");
            nonceElement.appendChild(document.createTextNode(nonce));
            element.appendChild(nonceElement);
        }

        if (requestId != null) {
            Element requestIdElement = document.createElement("requestId");
            requestIdElement.appendChild(document.createTextNode(requestId.toString()));
            element.appendChild(requestIdElement);
        }

        if (requestType != null) {
            Element requestTypeElement = document.createElement("requestType");
            requestTypeElement.appendChild(document.createTextNode(requestType));
            element.appendChild(requestTypeElement);
        }

        if (requestStatus != null) {
            Element requestStatusElement = document.createElement("requestStatus");
            requestStatusElement.appendChild(document.createTextNode(requestStatus));
            element.appendChild(requestStatusElement);
        }

        if (requestOwner != null) {
            Element requestOwnerElement = document.createElement("requestOwner");
            requestOwnerElement.appendChild(document.createTextNode(requestOwner));
            element.appendChild(requestOwnerElement);
        }

        if (requestCreationTime != null) {
            Element requestCreationTimeElement = document.createElement("requestCreationTime");
            requestCreationTimeElement.appendChild(document.createTextNode(requestCreationTime));
            element.appendChild(requestCreationTimeElement);
        }

        if (requestModificationTime != null) {
            Element requestModificationTimeElement = document.createElement("requestModificationTime");
            requestModificationTimeElement.appendChild(document.createTextNode(requestModificationTime));
            element.appendChild(requestModificationTimeElement);
        }

        if (requestNotes != null) {
            Element requestNotesElement = document.createElement("requestNotes");
            requestNotesElement.appendChild(document.createTextNode(requestNotes));
            element.appendChild(requestNotesElement);
        }

        if (profileApprovedBy != null) {
            Element profileApprovedByElement = document.createElement("profileApprovedBy");
            profileApprovedByElement.appendChild(document.createTextNode(profileApprovedBy));
            element.appendChild(profileApprovedByElement);
        }

        if (profileSetId != null) {
            Element profileSetIdElement = document.createElement("profileSetId");
            profileSetIdElement.appendChild(document.createTextNode(profileSetId));
            element.appendChild(profileSetIdElement);
        }

        if (profileIsVisible != null) {
            Element profileIsVisibleElement = document.createElement("profileIsVisible");
            profileIsVisibleElement.appendChild(document.createTextNode(profileIsVisible));
            element.appendChild(profileIsVisibleElement);
        }

        if (profileName != null) {
            Element profileNameElement = document.createElement("profileName");
            profileNameElement.appendChild(document.createTextNode(profileName));
            element.appendChild(profileNameElement);
        }

        if (profileDescription != null) {
            Element profileDescriptionElement = document.createElement("profileDescription");
            profileDescriptionElement.appendChild(document.createTextNode(profileDescription));
            element.appendChild(profileDescriptionElement);
        }

        if (profileRemoteHost != null) {
            Element profileRemoteHostElement = document.createElement("profileRemoteHost");
            profileRemoteHostElement.appendChild(document.createTextNode(profileRemoteHost));
            element.appendChild(profileRemoteHostElement);
        }

        if (profileRemoteAddr != null) {
            Element profileRemoteAddrElement = document.createElement("profileRemoteAddr");
            profileRemoteAddrElement.appendChild(document.createTextNode(profileRemoteAddr));
            element.appendChild(profileRemoteAddrElement);
        }

        return element;
    }

    public static CertReviewResponse fromDOM(Element element) {

        CertReviewResponse response = new CertReviewResponse();

        CertEnrollmentRequest.fromDOM(element, response);

        NodeList profilePolicySetList = element.getElementsByTagName("ProfilePolicySet");
        int profilePolicySetCount = profilePolicySetList.getLength();
        for (int i=0; i<profilePolicySetCount; i++) {
           Element profilePolicySetElement = (Element) profilePolicySetList.item(i);
           ProfilePolicySet info = ProfilePolicySet.fromDOM(profilePolicySetElement);
           response.addProfilePolicySet(info);
        }

        NodeList nonceList = element.getElementsByTagName("nonce");
        if (nonceList.getLength() > 0) {
            String value = nonceList.item(0).getTextContent();
            response.setNonce(value);
        }

        NodeList requestIdList = element.getElementsByTagName("requestId");
        if (requestIdList.getLength() > 0) {
            String value = requestIdList.item(0).getTextContent();
            response.setRequestId(new RequestId(value));
        }

        NodeList requestTypeList = element.getElementsByTagName("requestType");
        if (requestTypeList.getLength() > 0) {
            String value = requestTypeList.item(0).getTextContent();
            response.setRequestType(value);
        }

        NodeList requestStatusList = element.getElementsByTagName("requestStatus");
        if (requestStatusList.getLength() > 0) {
            String value = requestStatusList.item(0).getTextContent();
            response.setRequestStatus(value);
        }

        NodeList requestOwnerList = element.getElementsByTagName("requestOwner");
        if (requestOwnerList.getLength() > 0) {
            String value = requestOwnerList.item(0).getTextContent();
            response.setRequestOwner(value);
        }

        NodeList requestCreationTimeList = element.getElementsByTagName("requestCreationTime");
        if (requestCreationTimeList.getLength() > 0) {
            String value = requestCreationTimeList.item(0).getTextContent();
            response.setRequestCreationTime(value);
        }

        NodeList requestModificationTimeList = element.getElementsByTagName("requestModificationTime");
        if (requestModificationTimeList.getLength() > 0) {
            String value = requestModificationTimeList.item(0).getTextContent();
            response.setRequestModificationTime(value);
        }

        NodeList requestNotesList = element.getElementsByTagName("requestNotes");
        if (requestNotesList.getLength() > 0) {
            String value = requestNotesList.item(0).getTextContent();
            response.setRequestNotes(value);
        }

        NodeList profileApprovedByList = element.getElementsByTagName("profileApprovedBy");
        if (profileApprovedByList.getLength() > 0) {
            String value = profileApprovedByList.item(0).getTextContent();
            response.setProfileApprovedBy(value);
        }

        NodeList profileSetIdList = element.getElementsByTagName("profileSetId");
        if (profileSetIdList.getLength() > 0) {
            String value = profileSetIdList.item(0).getTextContent();
            response.setProfileSetId(value);
        }

        NodeList profileIsVisibleList = element.getElementsByTagName("profileIsVisible");
        if (profileIsVisibleList.getLength() > 0) {
            String value = profileIsVisibleList.item(0).getTextContent();
            response.setProfileIsVisible(value);
        }

        NodeList profileNameList = element.getElementsByTagName("profileName");
        if (profileNameList.getLength() > 0) {
            String value = profileNameList.item(0).getTextContent();
            response.setProfileName(value);
        }

        NodeList profileDescriptionList = element.getElementsByTagName("profileDescription");
        if (profileDescriptionList.getLength() > 0) {
            String value = profileDescriptionList.item(0).getTextContent();
            response.setProfileDescription(value);
        }

        NodeList profileRemoteHostList = element.getElementsByTagName("profileRemoteHost");
        if (profileRemoteHostList.getLength() > 0) {
            String value = profileRemoteHostList.item(0).getTextContent();
            response.setProfileRemoteHost(value);
        }

        NodeList profileRemoteAddrList = element.getElementsByTagName("profileRemoteAddr");
        if (profileRemoteAddrList.getLength() > 0) {
            String value = profileRemoteAddrList.item(0).getTextContent();
            response.setProfileRemoteAddr(value);
        }

        return response;
    }

    public String toXML() throws Exception {

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.newDocument();

        Element element = toDOM(document);
        document.appendChild(element);

        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");

        DOMSource domSource = new DOMSource(document);
        StringWriter sw = new StringWriter();
        StreamResult streamResult = new StreamResult(sw);
        transformer.transform(domSource, streamResult);

        return sw.toString();
    }

    public static CertReviewResponse fromXML(String xml) throws Exception {

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(new InputSource(new StringReader(xml)));

        Element element = document.getDocumentElement();
        return fromDOM(element);
    }
}
