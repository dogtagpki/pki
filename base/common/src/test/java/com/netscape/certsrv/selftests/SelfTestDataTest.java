package com.netscape.certsrv.selftests;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class SelfTestDataTest {

    private static SelfTestData before = new SelfTestData();

    @Before
    public void setUpBefore() {
        before.setID("selftest1");
        before.setEnabledOnDemand(true);
        before.setCriticalOnDemand(false);
    }

    @Test
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        System.out.println("XML (before): " + xml);

        SelfTestData afterXML = SelfTestData.fromXML(xml);
        System.out.println("XML (after): " + afterXML.toXML());

        // Assert
        Assert.assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        SelfTestData afterJSON = SelfTestData.fromJSON(json);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
