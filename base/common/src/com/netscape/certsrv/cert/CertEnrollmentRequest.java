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

import javax.ws.rs.core.MultivaluedMap;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import com.netscape.certsrv.profile.ProfileAttribute;
import com.netscape.certsrv.profile.ProfileInput;
import com.netscape.certsrv.profile.ProfileOutput;

/**
 * @author jmagne
 *
 */

@XmlRootElement(name = "CertEnrollmentRequest")
@XmlAccessorType(XmlAccessType.FIELD)
public class CertEnrollmentRequest {

    private static final String PROFILE_ID = "profileId";
    private static final String RENEWAL = "renewal";
    private static final String SERIAL_NUM = "serial_num";

    @XmlElement(name="ProfileID")
    protected String profileId;

    @XmlElement(name="Renewal")
    protected boolean renewal;

    @XmlElement(name="SerialNumber")
    protected String serialNum;   // used for one type of renewal

    @XmlElement(name="RemoteHost")
    protected String remoteHost;

    @XmlElement(name="RemoteAddress")
    protected String remoteAddr;

    @XmlElement(name = "Input")
    protected Collection<ProfileInput> inputs = new ArrayList<ProfileInput>();

    @XmlElement(name = "Output")
    protected Collection<ProfileOutput> outputs = new ArrayList<ProfileOutput>();

    public CertEnrollmentRequest() {
        // required for jaxb
    }

    public CertEnrollmentRequest(MultivaluedMap<String, String> form) {
        profileId = form.getFirst(PROFILE_ID);
        String renewalStr = form.getFirst(RENEWAL);
        serialNum = form.getFirst(SERIAL_NUM);
        renewal = new Boolean(renewalStr);
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

    public ProfileInput getInput(String name) {
        for (ProfileInput input : inputs) {
            if (input.getName().equals(name))
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

    public ProfileOutput getOutput(String name) {
        for (ProfileOutput output : outputs) {
            if (output.getName().equals(name))
                return output;
        }
        return null;
    }

    public HashMap<String, String> toParams() {
        HashMap<String, String> ret = new HashMap<String, String>();
        ret.put("isRenewal", Boolean.valueOf(renewal).toString());
        if (profileId != null) ret.put(PROFILE_ID, profileId);
        if (serialNum != null) ret.put(SERIAL_NUM, serialNum);
        if (remoteHost != null) ret.put("remoteHost", remoteHost);
        if (remoteAddr != null) ret.put("remoteAddr", remoteAddr);

        for (ProfileInput input: inputs) {
            for (ProfileAttribute attr : input.getAttributes()) {
                ret.put(attr.getName(), attr.getValue());
            }
        }

        return ret;
    }

    public String getSerialNum() {
        return serialNum;
    }

    public void setSerialNum(String serialNum) {
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

    public static CertEnrollmentRequest fromXML(String string) throws JAXBException {
        JAXBContext context = JAXBContext.newInstance(CertEnrollmentRequest.class);
        Unmarshaller unmarshaller = context.createUnmarshaller();
        return (CertEnrollmentRequest) unmarshaller.unmarshal(new StringReader(string));
    }

    public String toXML() throws JAXBException {
        JAXBContext context = JAXBContext.newInstance(CertEnrollmentRequest.class);
        Marshaller marshaller = context.createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
        StringWriter sw = new StringWriter();
        marshaller.marshal(this, sw);
        return sw.toString();
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((inputs == null) ? 0 : inputs.hashCode());
        result = prime * result + ((outputs == null) ? 0 : outputs.hashCode());
        result = prime * result + ((profileId == null) ? 0 : profileId.hashCode());
        result = prime * result + ((remoteAddr == null) ? 0 : remoteAddr.hashCode());
        result = prime * result + ((remoteHost == null) ? 0 : remoteHost.hashCode());
        result = prime * result + (renewal ? 1231 : 1237);
        result = prime * result + ((serialNum == null) ? 0 : serialNum.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
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
        return true;
    }

    public static void main(String args[]) throws Exception {
        CertEnrollmentRequest before = new CertEnrollmentRequest();
        before.setProfileId("caUserCert");
        before.setRenewal(false);

        //Simulate a "caUserCert" Profile enrollment

        ProfileInput certReq = before.createInput("KeyGenInput");
        certReq.addAttribute(new ProfileAttribute("cert_request_type", "crmf", null));
        certReq.addAttribute(new ProfileAttribute(
                "cert_request",
                "MIIBozCCAZ8wggEFAgQBMQp8MIHHgAECpQ4wDDEKMAgGA1UEAxMBeKaBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA2NgaPHp0jiohcP4M+ufrJOZEqH8GV+liu5JLbT8nWpkfhC+8EUBqT6g+n3qroSxIcNVGNdcsBEqs1utvpItzyslAbpdyat3WwQep1dWMzo6RHrPDuIoxNA0Yka1n3qEX4U//08cLQtUv2bYglYgN/hOCNQemLV6vZWAv0n7zelkCAwEAAakQMA4GA1UdDwEB/wQEAwIF4DAzMBUGCSsGAQUFBwUBAQwIcmVnVG9rZW4wGgYJKwYBBQUHBQECDA1hdXRoZW50aWNhdG9yoYGTMA0GCSqGSIb3DQEBBQUAA4GBAJ1VOQcaSEhdHa94s8kifVbSZ2WZeYE5//qxL6wVlEst20vq4ybj13CetnbN3+WT49Zkwp7Fg+6lALKgSk47suTg3EbbQDm+8yOrC0nc/q4PTRoHl0alMmUxIhirYc1t3xoCMqJewmjX1bNP8lpVIZAYFZo4eZCpZaiSkM5BeHhz",
                null));

        ProfileInput subjectName = before.createInput("SubjectNameInput");
        subjectName.addAttribute(new ProfileAttribute("sn_uid", "jmagne", null));
        subjectName.addAttribute(new ProfileAttribute("sn_e", "jmagne@redhat.com", null));
        subjectName.addAttribute(new ProfileAttribute("sn_c", "US", null));
        subjectName.addAttribute(new ProfileAttribute("sn_ou", "Development", null));
        subjectName.addAttribute(new ProfileAttribute("sn_ou1", "IPA", null));
        subjectName.addAttribute(new ProfileAttribute("sn_ou2", "Dogtag", null));
        subjectName.addAttribute(new ProfileAttribute("sn_ou3", "CA", null));
        subjectName.addAttribute(new ProfileAttribute("sn_cn", "Common", null));
        subjectName.addAttribute(new ProfileAttribute("sn_o", "RedHat", null));

        ProfileInput submitter = before.createInput("SubmitterInfoInput");
        submitter.addAttribute(new ProfileAttribute("requestor_name", "admin", null));
        submitter.addAttribute(new ProfileAttribute("requestor_email", "admin@redhat.com", null));
        submitter.addAttribute(new ProfileAttribute("requestor_phone", "650-555-5555", null));

        String xml = before.toXML();
        System.out.println(xml);

        CertEnrollmentRequest after = CertEnrollmentRequest.fromXML(xml);
        System.out.println(after.toXML());

        System.out.println(before.equals(after));
    }
}
