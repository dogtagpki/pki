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
// (C) 2011 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

/**
 *
 */
package com.netscape.certsrv.profile;

import java.io.StringReader;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Vector;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.adapters.XmlAdapter;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.netscape.certsrv.base.Link;

/**
 * @author jmagne
 *
 */

@XmlRootElement(name = "Profile")
@XmlAccessorType(XmlAccessType.FIELD)
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class ProfileData {

    @XmlAttribute
    protected String id;

    @XmlElement
    protected String classId;

    @XmlElement
    protected String name;

    @XmlElement
    protected String description;

    @XmlElement
    protected boolean enabled;

    @XmlElement
    protected boolean visible;

    @XmlElement
    protected String enabledBy;

    @XmlElement
    protected String authenticatorId;

    @XmlElement
    protected String authzAcl;

    @XmlElement
    protected boolean renewal;

    @XmlElement
    protected boolean xmlOutput;

    @XmlElement(name = "Input")
    protected List<ProfileInput> inputs = new ArrayList<>();

    @XmlElement(name = "Output")
    protected List<ProfileOutput> outputs = new ArrayList<>();

    @XmlElement(name = "PolicySets")
    @XmlJavaTypeAdapter(PolicySetAdapter.class)
    protected Map<String, List<ProfilePolicy>> policySets = new LinkedHashMap<>();

    protected Link link;

    public Link getLink() {
        return link;
    }

    public void setLink(Link link) {
        this.link = link;
    }

    public String getAuthenticatorId() {
        return authenticatorId;
    }

    public void setAuthenticatorId(String authenticatorId) {
        this.authenticatorId = authenticatorId;
    }

    public String getAuthzAcl() {
        return authzAcl;
    }

    public void setAuthzAcl(String authzAcl) {
        this.authzAcl = authzAcl;
    }

    public boolean isRenewal() {
        return  renewal;
    }

    public void setRenewal(boolean renewal) {
        this.renewal = renewal;
    }

    public boolean isXMLOutput() {
        return xmlOutput;
    }

    public void setXMLOutput(boolean isXMLOutput) {
        this.xmlOutput = isXMLOutput;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setVisible(boolean visible) {
        this.visible = visible;
    }

    public boolean isVisible() {
        return visible;
    }

    public void setEnabledBy(String enabledBy) {
        this.enabledBy = enabledBy;
    }

    public String getEnabledBy() {
        return enabledBy;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getId() {
        return id;
    }

    public String getClassId() {
        return classId;
    }

    public void setClassId(String classId) {
        this.classId = classId;
    }

    public void addProfileInput(ProfileInput input) {
        inputs.add(input);
    }

    public ProfileInput getProfileInput(String id) {
        for (ProfileInput input: inputs) {
            if (input.getId().equals(id)) return input;
        }
        return null;
    }

    public List<ProfileInput> getInputs() {
        return inputs;
    }

    public void setInputs(List<ProfileInput> inputs) {
        this.inputs = inputs;
    }

    public List<ProfileOutput> getOutputs() {
        return outputs;
    }

    public void setOutputs(List<ProfileOutput> outputs) {
        this.outputs = outputs;
    }

    public Map<String, List<ProfilePolicy>> getPolicySets() {
        return policySets;
    }

    public void setPolicySets(Map<String, List<ProfilePolicy>> policySets) {
        this.policySets = policySets;
    }

    public void addProfilePolicySet(String id, Vector<ProfilePolicy> policySet) {
        this.policySets.put(id, policySet);
    }

    public void addProfileOutput(ProfileOutput output) {
        outputs.add(output);
    }

    public ProfileOutput getProfileOutput(String id) {
        for (ProfileOutput output: outputs) {
            if (output.getId().equals(id)) return output;
        }
        return null;
    }

    @Override
    public int hashCode() {
        return Objects.hash(authenticatorId, authzAcl, classId, description, enabled, enabledBy, id, inputs, link, name,
                outputs, policySets, renewal, visible, xmlOutput);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        ProfileData other = (ProfileData) obj;
        return Objects.equals(authenticatorId, other.authenticatorId) && Objects.equals(authzAcl, other.authzAcl)
                && Objects.equals(classId, other.classId) && Objects.equals(description, other.description)
                && enabled == other.enabled && Objects.equals(enabledBy, other.enabledBy)
                && Objects.equals(id, other.id) && Objects.equals(inputs, other.inputs)
                && Objects.equals(link, other.link) && Objects.equals(name, other.name)
                && Objects.equals(outputs, other.outputs) && Objects.equals(policySets, other.policySets)
                && renewal == other.renewal && visible == other.visible && xmlOutput == other.xmlOutput;
    }

    public String toXML() throws Exception {
        Marshaller marshaller = JAXBContext.newInstance(ProfileData.class).createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

        StringWriter sw = new StringWriter();
        marshaller.marshal(this, sw);
        return sw.toString();
    }

    public static ProfileData fromXML(String xml) throws Exception {
        Unmarshaller unmarshaller = JAXBContext.newInstance(ProfileData.class).createUnmarshaller();
        return (ProfileData) unmarshaller.unmarshal(new StringReader(xml));
    }

    public String toJSON() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.writeValueAsString(this);
    }

    public static ProfileData fromJSON(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(json, ProfileData.class);
    }

    public static class PolicySetAdapter extends XmlAdapter<PolicySetList, Map<String, Vector<ProfilePolicy>>> {

        @Override
        public PolicySetList marshal(Map<String,Vector<ProfilePolicy>> map) {
            PolicySetList list = new PolicySetList();
            for (Map.Entry<String, Vector<ProfilePolicy>> entry : map.entrySet()) {
                PolicySet pset = new PolicySet();
                pset.name = entry.getKey();
                pset.value = entry.getValue();
                list.psets.add(pset);
            }
            return list;
        }

        @Override
        public Map<String, Vector<ProfilePolicy>> unmarshal(PolicySetList list) {
            Map<String, Vector<ProfilePolicy>> map = new LinkedHashMap<>();
            for (PolicySet pset : list.psets) {
                map.put(pset.name, pset.value);
            }
            return map;
        }
    }

    public static class PolicySetList {
        @XmlElement(name="PolicySet")
        public List<PolicySet> psets = new ArrayList<>();
    }

    public static class PolicySet {

        @XmlElement(name="id")
        public String name;

        @XmlElement
        public Vector<ProfilePolicy> value;
    }

}