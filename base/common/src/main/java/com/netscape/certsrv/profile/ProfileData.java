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
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Vector;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.adapters.XmlAdapter;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.netscape.certsrv.base.Link;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * @author jmagne
 *
 */

@XmlRootElement(name = "Profile")
@XmlAccessorType(XmlAccessType.FIELD)
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class ProfileData implements JSONSerializer {

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

    public Element toDOM(Document document) {

        Element pdElement = document.createElement("Profile");
        pdElement.setAttribute("id", id);
        if (classId != null) {
            Element classIdElement = document.createElement("classId");
            classIdElement.appendChild(document.createTextNode(classId));
            pdElement.appendChild(classIdElement);
        }
        if (name != null) {
            Element nameElement = document.createElement("name");
            nameElement.appendChild(document.createTextNode(name));
            pdElement.appendChild(nameElement);
        }
        if (description != null) {
            Element descriptionElement = document.createElement("description");
            descriptionElement.appendChild(document.createTextNode(description));
            pdElement.appendChild(descriptionElement);
        }
        Element enabledElement = document.createElement("enabled");
        enabledElement.appendChild(document.createTextNode(Boolean.toString(enabled)));
        pdElement.appendChild(enabledElement);

        Element visibleElement = document.createElement("visible");
        visibleElement.appendChild(document.createTextNode(Boolean.toString(visible)));
        pdElement.appendChild(visibleElement);
        if (enabledBy != null) {
            Element enabledByElement = document.createElement("enabledBy");
            enabledByElement.appendChild(document.createTextNode(enabledBy));
            pdElement.appendChild(enabledByElement);
        }
        if (authenticatorId != null) {
            Element authenticatorIdElement = document.createElement("authenticatorId");
            authenticatorIdElement.appendChild(document.createTextNode(authenticatorId));
            pdElement.appendChild(authenticatorIdElement);
        }
        if (authzAcl != null) {
            Element authzAclElement = document.createElement("authzAcl");
            authzAclElement.appendChild(document.createTextNode(authzAcl));
            pdElement.appendChild(authzAclElement);
        }
        Element renewalElement = document.createElement("renewal");
        renewalElement.appendChild(document.createTextNode(Boolean.toString(renewal)));
        pdElement.appendChild(renewalElement);

        Element xmlOutputElement = document.createElement("xmlOutput");
        xmlOutputElement.appendChild(document.createTextNode(Boolean.toString(xmlOutput)));
        pdElement.appendChild(xmlOutputElement);
        for (ProfileInput pi : inputs) {
            Element piElement = pi.toDOM(document);
            pdElement.appendChild(piElement);
        }
        for (ProfileOutput po : outputs) {
            Element poElement = po.toDOM(document, "Output");
            pdElement.appendChild(poElement);
        }
        if (!policySets.isEmpty()) {
            Element policysetsElement = document.createElement("PolicySets");
            for (Entry<String, List<ProfilePolicy>> policySet : getPolicySets().entrySet()) {
                Element policysetElement = document.createElement("PolicySet");
                Element idElement = document.createElement("id");
                idElement.appendChild(document.createTextNode(policySet.getKey()));
                policysetElement.appendChild(idElement);
                for (ProfilePolicy pp : policySet.getValue()) {
                    Element valueElement = document.createElement("value");
                    valueElement.setAttribute("id", pp.getId());
                    if (pp.getDef() != null) {
                        Element defElement = document.createElement("def");
                        defElement.setAttribute("id", pp.getDef().getName());
                        defElement.setAttribute("classId", pp.getDef().getClassId());
                        valueElement.appendChild(defElement);
                        if (pp.getDef().getText() != null) {
                            Element descriptionElement = document.createElement("description");
                            descriptionElement.appendChild(document.createTextNode(pp.getDef().getText()));
                            defElement.appendChild(descriptionElement);
                        }
                        for (ProfileAttribute attribute : pp.getDef().getAttributes()) {
                            Element attributeElement = document.createElement("policyAttribute");
                            if (attribute.getName() != null) {
                                attributeElement.setAttribute("name", attribute.getName());
                            }
                            if (attribute.getValue() != null) {
                                Element ppValueElement = document.createElement("Value");
                                ppValueElement.appendChild(document.createTextNode(attribute.getValue()));
                                attributeElement.appendChild(ppValueElement);
                            }
                            Descriptor descriptor = attribute.getDescriptor();
                            if (descriptor != null) {
                                Element descriptorElement = descriptor.toDOM(document);
                                attributeElement.appendChild(descriptorElement);
                            }
                            defElement.appendChild(attributeElement);
                        }
                        for (ProfileParameter param : pp.getDef().getParams()) {
                            Element parameterElement = document.createElement("params");
                            if (param.getName() != null) {
                                parameterElement.setAttribute("name", param.getName());
                            }
                            if (param.getValue() != null) {
                                Element paramValueElement = document.createElement("value");
                                paramValueElement.appendChild(document.createTextNode(param.getValue()));
                                parameterElement.appendChild(paramValueElement);
                            }
                            defElement.appendChild(parameterElement);
                        }
                    }
                    if (pp.getConstraint() != null) {
                        Element pcElement = document.createElement("constraint");
                        pcElement.setAttribute("id", pp.getConstraint().getName());
                        if (pp.getConstraint().getText() != null) {
                            Element descriptionElement = document.createElement("description");
                            descriptionElement.appendChild(document.createTextNode(pp.getConstraint().getText()));
                            pcElement.appendChild(descriptionElement);
                        }
                        if (pp.getConstraint().getClassId() != null) {
                            Element classIdElement = document.createElement("classId");
                            classIdElement.appendChild(document.createTextNode(pp.getConstraint().getClassId()));
                            pcElement.appendChild(classIdElement);
                        }
                        if (pp.getConstraint().getConstraints() != null) {
                            for (PolicyConstraintValue pcv : pp.getConstraint().getConstraints()) {
                                Element constraintElement = document.createElement("constraint");
                                constraintElement.setAttribute("id", pcv.getName());
                                Descriptor descriptor = pcv.getDescriptor();
                                if (descriptor != null) {
                                    Element descriptorElement = document.createElement("descriptor");
                                    descriptor.toDOM(document, descriptorElement);
                                    constraintElement.appendChild(descriptorElement);
                                }
                                if (pcv.getValue() != null) {
                                    Element pcvValueElement = document.createElement("value");
                                    pcvValueElement.appendChild(document.createTextNode(pcv.getValue()));
                                    constraintElement.appendChild(pcvValueElement);
                                }
                                pcElement.appendChild(constraintElement);
                            }
                        }
                        valueElement.appendChild(pcElement);
                    }
                    policysetElement.appendChild(valueElement);
                }
                policysetsElement.appendChild(policysetElement);
            }
            pdElement.appendChild(policysetsElement);
        }
        if (link != null) {
            Element linkElement = link.toDOM(document);
            pdElement.appendChild(linkElement);
        }
        return pdElement;
    }

    public static ProfileData fromDOM(Element profileDataElement) throws DOMException, Exception {

        ProfileData profileData = new ProfileData();
        String id = profileDataElement.getAttribute("id");
        profileData.setId(id);

        NodeList classIdList = profileDataElement.getElementsByTagName("classId");
        if (classIdList.getLength() > 0) {
            String value = classIdList.item(0).getTextContent();
            profileData.setClassId(value);
        }
        NodeList nameList = profileDataElement.getElementsByTagName("name");
        if (nameList.getLength() > 0) {
            String value = nameList.item(0).getTextContent();
            profileData.setName(value);
        }
        NodeList descriptionList = profileDataElement.getElementsByTagName("description");
        if (descriptionList.getLength() > 0) {
            String value = descriptionList.item(0).getTextContent();
            profileData.setDescription(value);
        }
        NodeList enabledList = profileDataElement.getElementsByTagName("enabled");
        if (enabledList.getLength() > 0) {
            String value = enabledList.item(0).getTextContent();
            profileData.setEnabled(Boolean.valueOf(value));
        }
        NodeList visibleList = profileDataElement.getElementsByTagName("visible");
        if (visibleList.getLength() > 0) {
            String value = visibleList.item(0).getTextContent();
            profileData.setVisible(Boolean.valueOf(value));
        }
        NodeList enabledByList = profileDataElement.getElementsByTagName("enabledBy");
        if (enabledByList.getLength() > 0) {
            String value = enabledByList.item(0).getTextContent();
            profileData.setEnabledBy(value);
        }
        NodeList authenticatorIdList = profileDataElement.getElementsByTagName("authenticatorId");
        if (authenticatorIdList.getLength() > 0) {
            String value = authenticatorIdList.item(0).getTextContent();
            profileData.setAuthenticatorId(value);
        }
        NodeList authzAclList = profileDataElement.getElementsByTagName("authzAcl");
        if (authzAclList.getLength() > 0) {
            String value = authzAclList.item(0).getTextContent();
            profileData.setAuthzAcl(value);
        }
        NodeList renewalList = profileDataElement.getElementsByTagName("renewal");
        if (renewalList.getLength() > 0) {
            String value = renewalList.item(0).getTextContent();
            profileData.setRenewal(Boolean.valueOf(value));
        }
        NodeList xmlOutputList = profileDataElement.getElementsByTagName("xmlOutput");
        if (xmlOutputList.getLength() > 0) {
            String value = xmlOutputList.item(0).getTextContent();
            profileData.setXMLOutput(Boolean.valueOf(value));
        }
        NodeList profileInputList = profileDataElement.getElementsByTagName("Input");
        int piCount = profileInputList.getLength();
        for (int i = 0; i < piCount; i++) {
            Element piElement = (Element) profileInputList.item(i);
            ProfileInput profileInput = ProfileInput.fromDOM(piElement);
            profileData.addProfileInput(profileInput);
        }
        NodeList profileOutputList = profileDataElement.getElementsByTagName("Output");
        int poCount = profileOutputList.getLength();
        for (int i = 0; i < poCount; i++) {
            Element poElement = (Element) profileOutputList.item(i);
            ProfileOutput profileOutput = ProfileOutput.fromDOM(poElement);
            profileData.addProfileOutput(profileOutput);
        }

        // <PolicySets>
        //     <PolicySet>
        //         <id>...</id>
        //         <value id="...">
        //             <def>...</def>
        //             <constraint>...</constraint>
        //         </value>
        //     </PolicySet>
        // </PolicySets>

        NodeList policySetList = profileDataElement.getElementsByTagName("PolicySet");
        int policySetCount = policySetList.getLength();

        for (int i = 0; i < policySetCount; i++) {
            Element policySetElement = (Element) policySetList.item(i);

            String policySetId = null;
            Vector<ProfilePolicy> policies = new Vector<>();

            // Iterate through the immediate children of <PolicySet> to find <id> and <value>.
            // Don't use getElementsByTagName() since it's recursive.
            for (Node node = policySetElement.getFirstChild(); node != null; node = node.getNextSibling()) {

                if (node.getNodeType() != Node.ELEMENT_NODE) continue;

                Element element = (Element) node;
                String tag = element.getTagName();

                if (tag.equals("id")) {
                    // found <id>
                    policySetId = element.getTextContent();
                    continue;

                } else if (!tag.equals("value")) {
                    continue;
                }

                // found <value>
                Element profilePolicyElement = element;
                ProfilePolicy profilePolicy = new ProfilePolicy();

                String policyId = profilePolicyElement.getAttribute("id");
                profilePolicy.setId(policyId);

                NodeList ppList = profilePolicyElement.getElementsByTagName("def");
                if (ppList.getLength() > 0) {
                    Element ppElement = (Element) ppList.item(0);
                    PolicyDefault pd = PolicyDefault.fromDOM(ppElement);
                    profilePolicy.setDef(pd);
                }

                NodeList constraintList = profilePolicyElement.getElementsByTagName("constraint");
                if (constraintList.getLength() > 0) {
                    Element constraintElement = (Element) constraintList.item(0);
                    PolicyConstraint pc = PolicyConstraint.fromDOM(constraintElement);
                    profilePolicy.setConstraint(pc);
                }

                policies.add(profilePolicy);
            }

            profileData.addProfilePolicySet(policySetId, policies);
        }

        NodeList LinkList = profileDataElement.getElementsByTagName("Link");
        int linkCount = LinkList.getLength();
        for (int i = 0; i < linkCount; i++) {
            Element linkElement = (Element) LinkList.item(i);
            Link link = Link.fromDOM(linkElement);
            profileData.setLink(link);
        }
        return profileData;
    }

    public String toXML() throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.newDocument();

        Element pdElement = toDOM(document);
        document.appendChild(pdElement);

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

    public static ProfileData fromXML(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(new InputSource(new StringReader(xml)));

        Element profileDataElement = document.getDocumentElement();
        return fromDOM(profileDataElement);
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