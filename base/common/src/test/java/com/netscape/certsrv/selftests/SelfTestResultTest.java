package com.netscape.certsrv.selftests;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class SelfTestResultTest {

    private static SelfTestResult before = new SelfTestResult();

    @Before
    public void setUpBefore() {
        before.setID("selftest1");
        before.setStatus("PASSED");
        before.setOutput(null);
    }

    @Test
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        System.out.println("XML (before): " + xml);

        SelfTestResult afterXML = SelfTestResult.fromXML(xml);
        System.out.println("XML (after): " + afterXML.toXML());

        // Assert
        Assert.assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        SelfTestResult afterJSON = SelfTestResult.fromJSON(json);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
