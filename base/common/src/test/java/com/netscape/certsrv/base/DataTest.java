package com.netscape.certsrv.base;

import javax.ws.rs.core.Response;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.base.PKIException.Data;

public class DataTest {

    private static Data before = new PKIException("test").getData();

    @Before
    public void setUpBefore() {
        before.className = PKIException.class.getName();
        before.code = Response.Status.INTERNAL_SERVER_ERROR.getStatusCode();
        before.message = "An error has occured";
        before.setAttribute("attr1", "value1");
        before.setAttribute("attr2", "value2");
    }

    @Test
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        System.out.println("XML (before): " + xml);

        Data afterXML = Data.fromXML(xml);
        System.out.println("XML (after): " + afterXML.toXML());

        // Assert
        Assert.assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        Data afterJSON = Data.fromJSON(json);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
