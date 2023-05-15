package com.netscape.certsrv.profile;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class ProfileOutputTest {

    private static ProfileOutput before = new ProfileOutput();

    @BeforeAll
    public static void setUpBefore() {
        before.addAttribute(new ProfileAttribute("sn_uid", "user", null));
        before.addAttribute(new ProfileAttribute("sn_e", "user@example.com", null));
        before.addAttribute(new ProfileAttribute("sn_c", "US", null));
        before.addAttribute(new ProfileAttribute("sn_ou", "Development", null));
        before.addAttribute(new ProfileAttribute("sn_ou1", "IPA", null));
        before.addAttribute(new ProfileAttribute("sn_ou2", "Dogtag", null));
        before.addAttribute(new ProfileAttribute("sn_ou3", "CA", null));
        before.addAttribute(new ProfileAttribute("sn_cn", "Common", null));
        before.addAttribute(new ProfileAttribute("sn_o", "RedHat", null));
        before.setName("foo");
        before.setClassId("bar");
        before.setId("lorem");
        before.setText("ipsum");
    }

    @Test
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        System.out.println("XML (before): " + xml);

        ProfileOutput afterXML = ProfileOutput.fromXML(xml);
        System.out.println("XML (after): " + afterXML.toXML());

        // Assert
        assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        ProfileOutput afterJSON = JSONSerializer.fromJSON(json, ProfileOutput.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
