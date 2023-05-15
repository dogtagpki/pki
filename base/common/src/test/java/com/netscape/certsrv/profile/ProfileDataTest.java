package com.netscape.certsrv.profile;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.List;
import java.util.Vector;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.util.JSONSerializer;

public class ProfileDataTest {

    private static ProfileData before = new ProfileData();
    private static List<ProfileInput> inputs = new ArrayList<>();
    private static ProfileInput profileInput = new ProfileInput("i1", "SubjectNameInput", null);
    private static ProfileOutput profileOutput = new ProfileOutput();
    private static ProfilePolicy pp = new ProfilePolicy();
    private static PolicyDefault pd = new PolicyDefault();
    private static ProfileParameter pp1 = new ProfileParameter();
    private static ProfileParameter pp2 = new ProfileParameter();
    private static List<ProfileParameter> params = new ArrayList<>();
    private static ProfileAttribute pa1 = new ProfileAttribute();
    private static ProfileAttribute pa2 = new ProfileAttribute();
    private static List<ProfileAttribute> attributes = new ArrayList<>();
    private static Descriptor descriptor = new Descriptor(
            IDescriptor.CHOICE,
            "true,false,-",
            "-",
            "CMS_PROFILE_CRITICAL");
    private static PolicyConstraint pc = new PolicyConstraint();
    private static PolicyConstraintValue pcv1 = new PolicyConstraintValue();
    private static PolicyConstraintValue pcv2 = new PolicyConstraintValue();
    private static List<PolicyConstraintValue> constraints = new ArrayList<>();
    private static Vector<ProfilePolicy> policySet = new Vector<>();

    @BeforeAll
    public static void setUpBefore() {
        before.setClassId("com.netscape.cms.profile.common.CAEnrollProfile");
        before.setDescription("This certificate profile is for enrolling user certificates.");
        before.setEnabled(true);
        before.setEnabledBy("admin");
        before.setId("caUserCertEnrollImpl");
        before.setInputs(inputs);
        before.setName("Manual User Dual-Use Certificate Enrollment");
        before.setRenewal(false);
        before.setVisible(true);
        before.setXMLOutput(false);
        before.setAuthzAcl("foo");
        before.setAuthenticatorId("bar");

        // Setup ProfileInput
        profileInput.addAttribute(new ProfileAttribute("sn_uid", "user", descriptor));
        profileInput.addConfigAttribute(new ProfileAttribute("sn_abc", "configattr", descriptor));
        profileInput.addAttribute(new ProfileAttribute("sn_e", "user@example.com", null));
        profileInput.addAttribute(new ProfileAttribute("sn_c", "US", null));
        profileInput.addAttribute(new ProfileAttribute("sn_ou", "Development", null));
        profileInput.addAttribute(new ProfileAttribute("sn_ou1", "IPA", null));
        profileInput.addAttribute(new ProfileAttribute("sn_ou2", "Dogtag", null));
        profileInput.addAttribute(new ProfileAttribute("sn_ou3", "CA", null));
        profileInput.addAttribute(new ProfileAttribute("sn_cn", "Common", null));
        profileInput.addAttribute(new ProfileAttribute("sn_o", "RedHat", null));
        before.addProfileInput(profileInput);

        // Setup ProfileInput
        profileOutput.addAttribute(new ProfileAttribute("sn_uid", "user", null));
        profileOutput.addAttribute(new ProfileAttribute("sn_e", "user@example.com", null));
        profileOutput.addAttribute(new ProfileAttribute("sn_c", "US", null));
        profileOutput.addAttribute(new ProfileAttribute("sn_ou", "Development", null));
        profileOutput.addAttribute(new ProfileAttribute("sn_ou1", "IPA", null));
        profileOutput.addAttribute(new ProfileAttribute("sn_ou2", "Dogtag", null));
        profileOutput.addAttribute(new ProfileAttribute("sn_ou3", "CA", null));
        profileOutput.addAttribute(new ProfileAttribute("sn_cn", "Common", null));
        profileOutput.addAttribute(new ProfileAttribute("sn_o", "RedHat", null));
        profileOutput.setName("foo");
        profileOutput.setClassId("bar");
        profileOutput.setId("lorem");
        profileOutput.setText("ipsum");
        before.addProfileOutput(profileOutput);

        // Setup ProfilePolicy
        pc.setClassId("pc foo");
        pcv1.setDescriptor(descriptor);
        pcv1.setName("pcv foo1");
        pcv1.setValue("pcv bar1");
        constraints.add(pcv1);
        pcv2.setDescriptor(descriptor);
        pcv2.setName("pcv foo2");
        pcv2.setValue("pcv bar2");
        constraints.add(pcv2);
        pc.setConstraints(constraints);
        pc.setName("pc bar");
        pc.setText("pc lorem ipsum");
        pp.setConstraint(pc);

        pa1.setDescriptor(descriptor);
        pa1.setName("spam1");
        pa1.setValue("ham1");
        attributes.add(pa1);
        pa2.setDescriptor(descriptor);
        pa2.setName("spam2");
        pa2.setValue("ham2");
        attributes.add(pa2);
        pd.setAttributes(attributes);

        pd.setClassId("pd foo");
        pd.setName("pd bar");

        pp1.setName("pp foo1");
        pp1.setValue("pp bar1");
        params.add(pp1);
        pp2.setName("pp foo2");
        pp2.setValue("pp bar2");
        params.add(pp2);
        pd.setParams(params);

        pd.setText("pd lorem");
        pp.setDef(pd);
        pp.setId("foo");
        policySet.add(pp);
        before.addProfilePolicySet("ppSet", policySet);
    }

    @Test
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        System.out.println("XML (before): " + xml);

        ProfileData afterXML = ProfileData.fromXML(xml);
        System.out.println("XML (after): " + afterXML.toXML());

        // Assert
        assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        ProfileData afterJSON = JSONSerializer.fromJSON(json, ProfileData.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
