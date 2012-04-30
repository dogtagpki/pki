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
package com.netscape.cms.servlet.request.model;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import javax.ws.rs.core.MultivaluedMap;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import com.netscape.cms.servlet.profile.model.ProfileInput;

/**
 * @author jmagne
 *
 */

@XmlRootElement(name = "EnrollmentRequest")
@XmlAccessorType(XmlAccessType.FIELD)
public class EnrollmentRequestData {

    private static final String PROFILE_ID = "profileId";
    private static final String RENEWAL = "renewal";

    @XmlElement
    protected String profileId;

    @XmlElement
    protected boolean isRenewal;

    @XmlElement(name = "Input")
    protected List<ProfileInput> inputs = new ArrayList<ProfileInput>();

    public EnrollmentRequestData() {
    }

    public EnrollmentRequestData(MultivaluedMap<String, String> form) {
        profileId = form.getFirst(PROFILE_ID);
        String renewalStr = form.getFirst(RENEWAL);

        isRenewal = new Boolean(renewalStr);

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

    public boolean getIsRenewal() {
        return isRenewal;
    }

    public ProfileInput addInput(String name) {

        ProfileInput oldInput = getInput(name);

        if (oldInput != null)
            return oldInput;

        ProfileInput newInput = new ProfileInput();
        newInput.setInputId(name);

        inputs.add(newInput);

        return newInput;
    }

    public ProfileInput getInput(String name) {

        ProfileInput input = null;

        Iterator<ProfileInput> it = inputs.iterator();

        ProfileInput curInput = null;
        while (it.hasNext())

        {
            curInput = it.next();

            if (curInput != null && curInput.getInputId().equals(name))
                break;
        }

        return input;
    }

    /**
     * @param renewal the renewal to set
     */
    public void setIsRenewal(boolean isRenewal) {
        this.isRenewal = isRenewal;
    }

    public static void main(String args[]) throws Exception {
        EnrollmentRequestData data = new EnrollmentRequestData();
        data.setProfileId("caUserCert");
        data.setIsRenewal(false);

        //Simulate a "caUserCert" Profile enrollment

        ProfileInput certReq = data.addInput("KeyGenInput");
        certReq.setInputAttr("cert_request_type", "crmf");
        certReq.setInputAttr(
                "cert_request",
                "MIIBozCCAZ8wggEFAgQBMQp8MIHHgAECpQ4wDDEKMAgGA1UEAxMBeKaBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA2NgaPHp0jiohcP4M+ufrJOZEqH8GV+liu5JLbT8nWpkfhC+8EUBqT6g+n3qroSxIcNVGNdcsBEqs1utvpItzyslAbpdyat3WwQep1dWMzo6RHrPDuIoxNA0Yka1n3qEX4U//08cLQtUv2bYglYgN/hOCNQemLV6vZWAv0n7zelkCAwEAAakQMA4GA1UdDwEB/wQEAwIF4DAzMBUGCSsGAQUFBwUBAQwIcmVnVG9rZW4wGgYJKwYBBQUHBQECDA1hdXRoZW50aWNhdG9yoYGTMA0GCSqGSIb3DQEBBQUAA4GBAJ1VOQcaSEhdHa94s8kifVbSZ2WZeYE5//qxL6wVlEst20vq4ybj13CetnbN3+WT49Zkwp7Fg+6lALKgSk47suTg3EbbQDm+8yOrC0nc/q4PTRoHl0alMmUxIhirYc1t3xoCMqJewmjX1bNP8lpVIZAYFZo4eZCpZaiSkM5BeHhz");

        ProfileInput subjectName = data.addInput("SubjectNameInput");
        subjectName.setInputAttr("sn_uid", "jmagne");
        subjectName.setInputAttr("sn_e", "jmagne@redhat.com");
        subjectName.setInputAttr("sn_c", "US");
        subjectName.setInputAttr("sn_ou", "Development");
        subjectName.setInputAttr("sn_ou1", "IPA");
        subjectName.setInputAttr("sn_ou2", "Dogtag");
        subjectName.setInputAttr("sn_ou3", "CA");
        subjectName.setInputAttr("sn_cn", "Common");
        subjectName.setInputAttr("sn_o", "RedHat");

        ProfileInput submitter = data.addInput("SubmitterInfoInput");
        submitter.setInputAttr("requestor_name", "admin");
        submitter.setInputAttr("requestor_email", "admin@redhat.com");
        submitter.setInputAttr("requestor_phone", "650-555-5555");

        try {
            JAXBContext context = JAXBContext.newInstance(EnrollmentRequestData.class);
            Marshaller marshaller = context.createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

            ByteArrayOutputStream stream = new ByteArrayOutputStream();

            marshaller.marshal(data, stream);

            System.out.println("Originally marshalled enrollment object. \n");

            System.out.println(stream.toString());

            //Try to unmarshall

            Unmarshaller unmarshaller = context.createUnmarshaller();

            ByteArrayInputStream bais = new ByteArrayInputStream(stream.toByteArray());
            Object unmarshalled = unmarshaller.unmarshal(bais);

            //Try re-marshalling, unmarshalled object to compare

            stream.reset();

            marshaller.marshal(unmarshalled, stream);

            System.out.println("Remarshalled unmarshalled enrollment object. \n");

            System.out.println(stream.toString());

        } catch (JAXBException e) {
            System.out.println(e.toString());
        }
    }

}
