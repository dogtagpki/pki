package com.netscape.certsrv.cert;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.profile.ProfileAttribute;
import com.netscape.certsrv.profile.ProfileInput;
import com.netscape.certsrv.profile.ProfileOutput;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.util.JSONSerializer;

public class CertReviewResponseTest {

    private static CertReviewResponse before = new CertReviewResponse();
    private static ProfileInput certReq = before.createInput("KeyGenInput");
    private static ProfileInput subjectName = before.createInput("SubjectNameInput");
    private static ProfileInput submitter = before.createInput("SubmitterInfoInput");

    @BeforeAll
    public static void setUpBefore() {
        before.setNonce("nonce");
        before.setRequestId(new RequestId(0x5));
        before.setRequestType("requestType");
        before.setRequestStatus("requestStatus");
        before.setRequestOwner("requestOwner");
        before.setRequestCreationTime("requestCreationTime");
        before.setRequestModificationTime("requestModificationTime");
        before.setRequestNotes("requestNotes");
        before.setProfileApprovedBy("me");
        before.setProfileSetId("profileSetId");
        before.setProfileIsVisible("yes");
        before.setProfileName("name");
        before.setProfileDescription("desc");
        before.setProfileRemoteHost("remoteHost");
        before.setProfileRemoteAddr("farAway");

        // Setup inherited fields
        before.setProfileId("caUserCert");
        before.setRenewal(true);

        certReq.addAttribute(new ProfileAttribute("cert_request_type", "crmf", null));
        certReq.addAttribute(new ProfileAttribute(
                "cert_request",
                "MIIBozCCAZ8wggEFAgQBMQp8MIHHgAECpQ4wDDEKMAgGA1UEAxMBeKaBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA2NgaPHp0jiohcP4M+ufrJOZEqH8GV+liu5JLbT8nWpkfhC+8EUBqT6g+n3qroSxIcNVGNdcsBEqs1utvpItzyslAbpdyat3WwQep1dWMzo6RHrPDuIoxNA0Yka1n3qEX4U//08cLQtUv2bYglYgN/hOCNQemLV6vZWAv0n7zelkCAwEAAakQMA4GA1UdDwEB/wQEAwIF4DAzMBUGCSsGAQUFBwUBAQwIcmVnVG9rZW4wGgYJKwYBBQUHBQECDA1hdXRoZW50aWNhdG9yoYGTMA0GCSqGSIb3DQEBBQUAA4GBAJ1VOQcaSEhdHa94s8kifVbSZ2WZeYE5//qxL6wVlEst20vq4ybj13CetnbN3+WT49Zkwp7Fg+6lALKgSk47suTg3EbbQDm+8yOrC0nc/q4PTRoHl0alMmUxIhirYc1t3xoCMqJewmjX1bNP8lpVIZAYFZo4eZCpZaiSkM5BeHhz",
                null));

        subjectName.addAttribute(new ProfileAttribute("sn_uid", "name", null));
        subjectName.addAttribute(new ProfileAttribute("sn_e", "name@example.com", null));
        subjectName.addAttribute(new ProfileAttribute("sn_c", "US", null));
        subjectName.addAttribute(new ProfileAttribute("sn_ou", "Development", null));
        subjectName.addAttribute(new ProfileAttribute("sn_ou1", "IPA", null));
        subjectName.addAttribute(new ProfileAttribute("sn_ou2", "Dogtag", null));
        subjectName.addAttribute(new ProfileAttribute("sn_ou3", "CA", null));
        subjectName.addAttribute(new ProfileAttribute("sn_cn", "Common", null));
        subjectName.addAttribute(new ProfileAttribute("sn_o", "RedHat", null));

        submitter.addAttribute(new ProfileAttribute("requestor_name", "admin", null));
        submitter.addAttribute(new ProfileAttribute("requestor_email", "admin@example.com", null));
        submitter.addAttribute(new ProfileAttribute("requestor_phone", "650-555-5555", null));

        before.addOutput(new ProfileOutput("id_123", "test output", "cre_123"));

        before.setRemoteHost("unit_test_host");
        before.setRemoteAddr("unit_test_addr");

        before.setAttribute("uid", "testuser");
        before.setAttribute("pwd", "password");
        before.setServerSideKeygenP12Passwd("secret");
        before.setSerialNum(new CertId(123));
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        CertReviewResponse afterJSON = JSONSerializer.fromJSON(json, CertReviewResponse.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
