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

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Vector;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.adapters.XmlAdapter;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

/**
 * @author jmagne
 *
 */

@XmlRootElement(name = "ProfileData")
@XmlAccessorType(XmlAccessType.FIELD)
public class ProfileData {

    @XmlElement
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

    @XmlElement(name = "Inputs")
    @XmlJavaTypeAdapter(InputAdapter.class)
    protected Map<String, ProfileInput> inputs = new LinkedHashMap<String, ProfileInput>();

    @XmlElement(name = "Outputs")
    @XmlJavaTypeAdapter(OutputAdapter.class)
    protected Map<String, ProfileOutput> outputs = new LinkedHashMap<String, ProfileOutput>();

    @XmlElement(name = "PolicySets")
    @XmlJavaTypeAdapter(PolicySetAdapter.class)
    protected Map<String, List<ProfilePolicy>> policySets = new LinkedHashMap<String, List<ProfilePolicy>>();


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

    public void addProfileInput(String id, ProfileInput input) {
        inputs.put(id, input);
    }

    public ProfileInput getProfileInput(String id) {
        return inputs.get(id);
    }

    public Map<String, ProfileInput> getInputs() {
        return inputs;
    }

    public void setInputs(Map<String, ProfileInput> inputs) {
        this.inputs = inputs;
    }

    public Map<String, ProfileOutput> getOutputs() {
        return outputs;
    }

    public void setOutputs(Map<String, ProfileOutput> outputs) {
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

    public void addProfileOutput(String id, ProfileOutput output) {
        outputs.put(id, output);
    }

    public ProfileOutput getProfileOutput(String id) {
        return outputs.get(id);
    }

    public static class InputAdapter extends XmlAdapter<InputList, Map<String, ProfileInput>> {

        public InputList marshal(Map<String,ProfileInput> map) {
            InputList list = new InputList();
            for (Map.Entry<String, ProfileInput> entry : map.entrySet()) {
                Input input = new Input();
                input.name = entry.getKey();
                input.value = entry.getValue();
                list.inputs.add(input);
            }
            return list;
        }

        public Map<String, ProfileInput> unmarshal(InputList list) {
            Map<String, ProfileInput> map = new LinkedHashMap<String, ProfileInput>();
            for (Input input : list.inputs) {
                map.put(input.name, input.value);
            }
            return map;
        }
    }

    public static class InputList {
        @XmlElement(name="input")
        public List<Input> inputs = new ArrayList<Input>();
    }

    public static class Input {

        @XmlElement(name="id")
        public String name;

        @XmlElement
        public ProfileInput value;
    }

    public static class OutputAdapter extends XmlAdapter<OutputList, Map<String, ProfileOutput>> {

        public OutputList marshal(Map<String,ProfileOutput> map) {
            OutputList list = new OutputList();
            for (Map.Entry<String, ProfileOutput> entry : map.entrySet()) {
                Output output = new Output();
                output.name = entry.getKey();
                output.value = entry.getValue();
                list.outputs.add(output);
            }
            return list;
        }

        public Map<String, ProfileOutput> unmarshal(OutputList list) {
            Map<String, ProfileOutput> map = new LinkedHashMap<String, ProfileOutput>();
            for (Output output : list.outputs) {
                map.put(output.name, output.value);
            }
            return map;
        }
    }

    public static class OutputList {
        @XmlElement(name="output")
        public List<Output> outputs = new ArrayList<Output>();
    }

    public static class Output {

        @XmlElement(name="id")
        public String name;

        @XmlElement
        public ProfileOutput value;
    }

    public static class PolicySetAdapter extends XmlAdapter<PolicySetList, Map<String, Vector<ProfilePolicy>>> {

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

        public Map<String, Vector<ProfilePolicy>> unmarshal(PolicySetList list) {
            Map<String, Vector<ProfilePolicy>> map = new LinkedHashMap<String, Vector<ProfilePolicy>>();
            for (PolicySet pset : list.psets) {
                map.put(pset.name, pset.value);
            }
            return map;
        }
    }

    public static class PolicySetList {
        @XmlElement(name="PolicySet")
        public List<PolicySet> psets = new ArrayList<PolicySet>();
    }

    public static class PolicySet {

        @XmlElement(name="id")
        public String name;

        @XmlElement
        public Vector<ProfilePolicy> value;
    }

    public static void main(String args[]) throws Exception {
        Map<String, ProfileInput> inputs = new LinkedHashMap<String, ProfileInput>();
        //ProfileInput input = new ProfileInput();
        //input.setClassId(classId);
        //input.setInputId(inputId);
        //input.setName(name);
        //input.setText(text);


        ProfileData data = new ProfileData();
        data.setClassId("com.netscape.cms.profile.common.CAEnrollProfile");
        data.setDescription("This certificate profile is for enrolling user certificates.");
        data.setEnabled(true);
        data.setEnabledBy("admin");
        data.setId("caUserCertEnrollImpl");
        data.setInputs(inputs);
        data.setName("Manual User Dual-Use Certificate Enrollment");
        //data.setOutputs(outputs);
        //data.setPolicySets(policySets);
        data.setRenewal(false);
        data.setVisible(true);
        data.setXMLOutput(false);
    }

}