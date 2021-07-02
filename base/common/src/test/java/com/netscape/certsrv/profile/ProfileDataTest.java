package com.netscape.certsrv.profile;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class ProfileDataTest {

    private static ProfileData before = new ProfileData();
    private static List<ProfileInput> inputs = new ArrayList<>();
    private static ProfileInput input = new ProfileInput();

    @BeforeClass
    public static void setUpBefore() {
        input.setClassId("foo");
        input.setName("bar");
        input.setText("lorem");

        inputs.add(input);

        before.setClassId("com.netscape.cms.profile.common.CAEnrollProfile");
        before.setDescription("This certificate profile is for enrolling user certificates.");
        before.setEnabled(true);
        before.setEnabledBy("admin");
        before.setId("caUserCertEnrollImpl");
        before.setInputs(inputs);
        before.setName("Manual User Dual-Use Certificate Enrollment");
        before.setOutputs(new ArrayList<>());
        before.setPolicySets(new HashMap<>());
        before.setRenewal(false);
        before.setVisible(true);
        before.setXMLOutput(false);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        ProfileData afterJSON = JSONSerializer.fromJSON(json, ProfileData.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
