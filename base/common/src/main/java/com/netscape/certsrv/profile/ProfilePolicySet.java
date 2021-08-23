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
package com.netscape.certsrv.profile;

import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class ProfilePolicySet {
    @XmlElement
    protected List<ProfilePolicy> policies = new ArrayList<>();

    public List<ProfilePolicy> getPolicies() {
        return policies;
    }

    public void setPolicies(List<ProfilePolicy> policies) {
        this.policies = policies;
    }

    public void addPolicy(ProfilePolicy policy) {
        policies.add(policy);
    }

    public void removePolicy(ProfilePolicy policy) {
        policies.remove(policy);
    }

    public Element toDOM(Document document) {

        Element element = document.createElement("ProfilePolicySet");

        for (ProfilePolicy profilePolicy : policies) {
            Element policyElement = profilePolicy.toDOM(document);
            element.appendChild(policyElement);
        }

        return element;
    }

    public static ProfilePolicySet fromDOM(Element element) {

        ProfilePolicySet set = new ProfilePolicySet();

        NodeList policiesList = element.getElementsByTagName("policies");
        int policiesCount = policiesList.getLength();
        for (int i=0; i<policiesCount; i++) {
           Element policyElement = (Element) policiesList.item(i);
           ProfilePolicy policy = ProfilePolicy.fromDOM(policyElement);
           set.addPolicy(policy);
        }

        return set;
    }
}
