package com.netscape.certsrv.profile;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class ProfileInputTest {

    private static ProfileInput before = new ProfileInput("i1", "SubjectNameInput", null);

    @Before
    public void setUpBefore() {
        before.addAttribute(new ProfileAttribute("sn_uid", "user", null));
        before.addAttribute(new ProfileAttribute("sn_e", "user@example.com", null));
        before.addAttribute(new ProfileAttribute("sn_c", "US", null));
        before.addAttribute(new ProfileAttribute("sn_ou", "Development", null));
        before.addAttribute(new ProfileAttribute("sn_ou1", "IPA", null));
        before.addAttribute(new ProfileAttribute("sn_ou2", "Dogtag", null));
        before.addAttribute(new ProfileAttribute("sn_ou3", "CA", null));
        before.addAttribute(new ProfileAttribute("sn_cn", "Common", null));
        before.addAttribute(new ProfileAttribute("sn_o", "RedHat", null));
    }

    @Test
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        System.out.println("XML (before): " + xml);

        ProfileInput afterXML = ProfileInput.fromXML(xml);
        System.out.println("XML (after): " + afterXML.toXML());

        // Assert
        Assert.assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        ProfileInput afterJSON = ProfileInput.fromJSON(json);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
