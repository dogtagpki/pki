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
package com.netscape.certsrv.cert;

import java.io.StringReader;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;

import jakarta.ws.rs.core.MultivaluedMap;
import javax.xml.XMLConstants;
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
import com.netscape.certsrv.base.RESTMessage;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.profile.ProfileAttribute;
import com.netscape.certsrv.profile.ProfileInput;
import com.netscape.certsrv.profile.ProfileOutput;
import com.netscape.certsrv.property.Descriptor;

/**
 * @author jmagne
 *
 */

@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class CertEnrollmentRequest extends RESTMessage {

    private static final String PROFILE_ID = "profileId";
    private static final String RENEWAL = "renewal";
    private static final String SERIAL_NUM = "serial_num";
    private static final String SERVERSIDE_KEYGEN_P12_PASSWD = "serverSideKeygenP12Passwd";

    @JsonProperty("ProfileID")
    protected String profileId;

    @JsonProperty("ServerSideKeygenP12Passwd")
    protected String serverSideKeygenP12Passwd;

    @JsonProperty("Renewal")
    protected boolean renewal;

    @JsonProperty("SerialNumber")
    protected CertId serialNum;   // used for one type of renewal

    @JsonProperty("RemoteHost")
    protected String remoteHost;

    @JsonProperty("RemoteAddress")
    protected String remoteAddr;

    @JsonProperty("Input")
    protected Collection<ProfileInput> inputs = new ArrayList<>();

    @JsonProperty("Output")
    protected Collection<ProfileOutput> outputs = new ArrayList<>();

    public CertEnrollmentRequest() {
    }

    public CertEnrollmentRequest(MultivaluedMap<String, String> form) {
        profileId = form.getFirst(PROFILE_ID);
        String renewalStr = form.getFirst(RENEWAL);
        serialNum = new CertId(form.getFirst(SERIAL_NUM));
        renewal = Boolean.valueOf(renewalStr);

        serverSideKeygenP12Passwd = form.getFirst(SERVERSIDE_KEYGEN_P12_PASSWD);
    }

    /**
     * @return the profileId
     */
    public String getProfileId() {
        return profileId;
    }

    /**
     * @param profileId the profileId to set
     */
    public void setProfileId(String profileId) {
        this.profileId = profileId;
    }

    public String getServerSideKeygenP12Passwd() {
        return serverSideKeygenP12Passwd;
    }

    public void setServerSideKeygenP12Passwd(String serverSideKeygenP12Passwd) {
        this.serverSideKeygenP12Passwd = serverSideKeygenP12Passwd;
    }

    /**
     * @return renewal
     */
    public boolean isRenewal() {
        return renewal;
    }

    /**
     * @param renewal the renewal to set
     */
    public void setRenewal(boolean renewal) {
        this.renewal = renewal;
    }

    public void addInput(ProfileInput input) {
        ProfileInput curInput = getInput(input.getName());
        if (curInput != null) {
            inputs.remove(curInput);
        }
        inputs.add(input);
    }

    public void deleteInput(ProfileInput input) {
        ProfileInput curInput = getInput(input.getName());
        if (curInput != null) {
            inputs.remove(curInput);
        }
    }

    public ProfileInput createInput(String name) {

        ProfileInput oldInput = getInput(name);

        if (oldInput != null)
            return oldInput;

        ProfileInput newInput = new ProfileInput();
        newInput.setName(name);

        inputs.add(newInput);

        return newInput;
    }

    // TODO: deprecate this method in 10.3
    public ProfileInput getInput(String name) {
        return getInputByName(name);
    }

    public ProfileInput getInputByName(String name) {
        for (ProfileInput input : inputs) {
            if (input.getName().equals(name))
                return input;
        }
        return null;
    }

    public ProfileInput getInputByID(String id) {
        for (ProfileInput input : inputs) {
            if (input.getId().equals(id))
                return input;
        }
        return null;
    }

    public void addOutput(ProfileOutput output) {
        ProfileOutput curOutput = getOutput(output.getName());
        if (curOutput != null) {
            outputs.remove(curOutput);
        }
        outputs.add(output);
    }

    public void deleteOutput(ProfileOutput output) {
        ProfileOutput curOutput = getOutput(output.getName());
        if (curOutput != null) {
            outputs.remove(curOutput);
        }
    }

    // TODO: deprecate this method in 10.3
    public ProfileOutput getOutput(String name) {
        return getOutputByName(name);
    }

    public ProfileOutput getOutputByName(String name) {
        for (ProfileOutput output : outputs) {
            if (output.getName().equals(name))
                return output;
        }
        return null;
    }

    public ProfileOutput getOutputByID(String id) {
        for (ProfileOutput output : outputs) {
            if (output.getId().equals(id))
                return output;
        }
        return null;
    }

    public HashMap<String, String> toParams() {
        HashMap<String, String> ret = new HashMap<>();
        ret.put("isRenewal", Boolean.valueOf(renewal).toString());
        if (profileId != null) ret.put(PROFILE_ID, profileId);
        if (serialNum != null) ret.put(SERIAL_NUM, serialNum.toHexString());
        if (remoteHost != null) ret.put("remoteHost", remoteHost);
        if (remoteAddr != null) ret.put("remoteAddr", remoteAddr);
        if (serverSideKeygenP12Passwd != null) ret.put(SERVERSIDE_KEYGEN_P12_PASSWD, serverSideKeygenP12Passwd);

        for (ProfileInput input: inputs) {
            for (ProfileAttribute attr : input.getAttributes()) {
                ret.put(attr.getName(), attr.getValue());
            }
        }

        return ret;
    }

    public CertId getSerialNum() {
        return serialNum;
    }

    public void setSerialNum(CertId serialNum) {
        this.serialNum = serialNum;
    }

    public Collection<ProfileInput> getInputs() {
        return inputs;
    }

    public void setInputs(Collection<ProfileInput> inputs) {
        this.inputs.clear();
        this.inputs.addAll(inputs);
    }

    public String getRemoteAddr() {
        return remoteAddr;
    }

    public void setRemoteAddr(String remoteAddr) {
        this.remoteAddr = remoteAddr;
    }

    public String getRemoteHost() {
        return remoteHost;
    }

    public void setRemoteHost(String remoteHost) {
        this.remoteHost = remoteHost;
    }

    public Collection<ProfileOutput> getOutputs() {
        return outputs;
    }

    public void setOutputs(Collection<ProfileOutput> outputs) {
        this.outputs.clear();
        this.outputs.addAll(outputs);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ((inputs == null) ? 0 : inputs.hashCode());
        result = prime * result + ((outputs == null) ? 0 : outputs.hashCode());
        result = prime * result + ((profileId == null) ? 0 : profileId.hashCode());
        result = prime * result + ((remoteAddr == null) ? 0 : remoteAddr.hashCode());
        result = prime * result + ((remoteHost == null) ? 0 : remoteHost.hashCode());
        result = prime * result + (renewal ? 1231 : 1237);
        result = prime * result + ((serialNum == null) ? 0 : serialNum.hashCode());

        result = prime * result + ((serverSideKeygenP12Passwd == null) ? 0 : serverSideKeygenP12Passwd.hashCode());
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
        CertEnrollmentRequest other = (CertEnrollmentRequest) obj;
        if (inputs == null) {
            if (other.inputs != null)
                return false;
        } else if (!inputs.equals(other.inputs))
            return false;
        if (outputs == null) {
            if (other.outputs != null)
                return false;
        } else if (!outputs.equals(other.outputs))
            return false;
        if (profileId == null) {
            if (other.profileId != null)
                return false;
        } else if (!profileId.equals(other.profileId))
            return false;
        if (remoteAddr == null) {
            if (other.remoteAddr != null)
                return false;
        } else if (!remoteAddr.equals(other.remoteAddr))
            return false;
        if (remoteHost == null) {
            if (other.remoteHost != null)
                return false;
        } else if (!remoteHost.equals(other.remoteHost))
            return false;
        if (renewal != other.renewal)
            return false;
        if (serialNum == null) {
            if (other.serialNum != null)
                return false;
        } else if (!serialNum.equals(other.serialNum))
            return false;
        if (serverSideKeygenP12Passwd == null) {
            if (other.serverSideKeygenP12Passwd != null)
                return false;
        } else if (!serverSideKeygenP12Passwd.equals(other.serverSideKeygenP12Passwd))
            return false;
        return true;
    }

    @Override
    public void toDOM(Document document, Element certEnrollmentRequestElement) {

        super.toDOM(document, certEnrollmentRequestElement);

        if (getProfileId() != null && !getProfileId().isEmpty()) {
            Element profileIdElement = document.createElement("ProfileID");
            profileIdElement.appendChild(document.createTextNode(getProfileId()));
            certEnrollmentRequestElement.appendChild(profileIdElement);
        }

        if (getServerSideKeygenP12Passwd() != null && !getServerSideKeygenP12Passwd().isEmpty()) {
            Element getServerSideKeygenP12PasswdElement = document.createElement("ServerSideKeygenP12Passwd");
            getServerSideKeygenP12PasswdElement.appendChild(document.createTextNode(getServerSideKeygenP12Passwd()));
            certEnrollmentRequestElement.appendChild(getServerSideKeygenP12PasswdElement);
        }

        Element renewalElement = document.createElement("Renewal");
        renewalElement.appendChild(document.createTextNode(String.valueOf(isRenewal())));
        certEnrollmentRequestElement.appendChild(renewalElement);

        if (getSerialNum() != null) {
            Element serialNumberElement = document.createElement("SerialNumber");
            serialNumberElement.appendChild(document.createTextNode(getSerialNum().toHexString()));
            certEnrollmentRequestElement.appendChild(serialNumberElement);
        }

        if (getRemoteHost() != null) {
            Element remoteHostElement = document.createElement("RemoteHost");
            remoteHostElement.appendChild(document.createTextNode(getRemoteHost()));
            certEnrollmentRequestElement.appendChild(remoteHostElement);
        }

        if (getRemoteAddr() != null) {
            Element remoteAddressElement = document.createElement("RemoteAddress");
            remoteAddressElement.appendChild(document.createTextNode(getRemoteAddr()));
            certEnrollmentRequestElement.appendChild(remoteAddressElement);
        }

        for (ProfileInput input: getInputs()) {
            certEnrollmentRequestElement.appendChild(input.toDOM(document));
        }

        for (ProfileOutput output: getOutputs()) {
            Element outputElement = document.createElement("Output");
            output.toDOM(document, outputElement);
            certEnrollmentRequestElement.appendChild(outputElement);
        }
    }

    @Override
    public Element toDOM(Document document) {
        Element certEnrollmentRequestElement = document.createElement("CertEnrollmentRequest");
        toDOM(document, certEnrollmentRequestElement);
        return certEnrollmentRequestElement;
    }

    public static void fromDOM(Element certEnrollmentRequestElement, CertEnrollmentRequest certEnrollmentRequest) {

        RESTMessage.fromDOM(certEnrollmentRequestElement, certEnrollmentRequest);

        NodeList profileIdList = certEnrollmentRequestElement.getElementsByTagName("ProfileID");
        if (profileIdList.getLength() > 0) {
            String value = profileIdList.item(0).getTextContent();
            certEnrollmentRequest.setProfileId(value);
        }

        NodeList serverSideKeygenP12PasswdList = certEnrollmentRequestElement.getElementsByTagName("ServerSideKeygenP12Passwd");
        if (serverSideKeygenP12PasswdList.getLength() > 0) {
            String value = serverSideKeygenP12PasswdList.item(0).getTextContent();
            certEnrollmentRequest.setServerSideKeygenP12Passwd(value);
        }

        NodeList renewalList = certEnrollmentRequestElement.getElementsByTagName("Renewal");
        if (renewalList.getLength() > 0) {
            String value = renewalList.item(0).getTextContent();
            certEnrollmentRequest.setRenewal(Boolean.valueOf(value));
        }

        NodeList serialNumberList = certEnrollmentRequestElement.getElementsByTagName("SerialNumber");
        if (serialNumberList.getLength() > 0) {
            String value = serialNumberList.item(0).getTextContent();
            certEnrollmentRequest.setSerialNum(new CertId(value));
        }

        NodeList remoteHostList = certEnrollmentRequestElement.getElementsByTagName("RemoteHost");
        if (remoteHostList.getLength() > 0) {
            String value = remoteHostList.item(0).getTextContent();
            certEnrollmentRequest.setRemoteHost(value);
        }

        NodeList remoteHostAddressList = certEnrollmentRequestElement.getElementsByTagName("RemoteAddress");
        if (remoteHostAddressList.getLength() > 0) {
            String value = remoteHostAddressList.item(0).getTextContent();
            certEnrollmentRequest.setRemoteAddr(value);
        }

        NodeList inputList = certEnrollmentRequestElement.getElementsByTagName("Input");
        for (int i = 0; i < inputList.getLength(); i++) {
            Element inputElement = (Element) inputList.item(i);
            ProfileInput profileInput = new ProfileInput();

            NodeList nameList = inputElement.getElementsByTagName("Name");
            if (nameList.getLength() > 0) {
                String name = nameList.item(0).getTextContent();
                profileInput.setName(name);
            }

            NodeList attributeList = inputElement.getElementsByTagName("Attribute");
            for (int o = 0; o < attributeList.getLength(); o++) {
                Element attributeElement = (Element) attributeList.item(o);
                ProfileAttribute profileAttribute = new ProfileAttribute();

                String attributeId = attributeElement.getAttribute("name");
                profileAttribute.setName(attributeId);

                NodeList attributeNameList = attributeElement.getElementsByTagName("Name");
                if (attributeNameList.getLength() > 0) {
                    String value = attributeNameList.item(0).getTextContent();
                    profileAttribute.setValue(value);
                }

                NodeList valueList = attributeElement.getElementsByTagName("Value");
                if (valueList.getLength() > 0) {
                    String value = valueList.item(0).getTextContent();
                    profileAttribute.setValue(value);
                }

                NodeList descriptorList = attributeElement.getElementsByTagName("Descriptor");
                if (descriptorList.getLength() > 0) {
                    Element descriptorElement = (Element) descriptorList.item(0);
                    Descriptor descriptor = Descriptor.fromDOM(descriptorElement);
                    profileAttribute.setDescriptor(descriptor);
                }

                profileInput.addAttribute(profileAttribute);
            }
            certEnrollmentRequest.addInput(profileInput);
        }

        NodeList outputList = certEnrollmentRequestElement.getElementsByTagName("Output");
        for (int i = 0; i < outputList.getLength(); i++) {
            Element outputElement = (Element) outputList.item(i);
            ProfileOutput output = ProfileOutput.fromDOM(outputElement);
            certEnrollmentRequest.addOutput(output);
        }
    }

    public static CertEnrollmentRequest fromDOM(Element element) {
        CertEnrollmentRequest certEnrollmentRequest = new CertEnrollmentRequest();
        fromDOM(element, certEnrollmentRequest);
        return certEnrollmentRequest;
    }

    @Override
    public String toXML() throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.newDocument();

        Element element = toDOM(document);
        document.appendChild(element);

        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
        Transformer transformer = transformerFactory.newTransformer();
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");

        DOMSource domSource = new DOMSource(document);
        StringWriter sw = new StringWriter();
        StreamResult streamResult = new StreamResult(sw);
        transformer.transform(domSource, streamResult);
        return sw.toString();
    }

    public static CertEnrollmentRequest fromXML(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(new InputSource(new StringReader(xml)));

        Element profileElement = document.getDocumentElement();
        return fromDOM(profileElement);
    }

}
