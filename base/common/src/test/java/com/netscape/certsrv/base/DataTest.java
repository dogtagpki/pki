package com.netscape.certsrv.base;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.PKIException.Data;
import com.netscape.certsrv.util.JSONSerializer;

public class DataTest {

    public static Logger logger = LoggerFactory.getLogger(DataTest.class);

    private static Data before = new PKIException("test").getData();

    @BeforeAll
    public static void setUpBefore() {
        before.className = PKIException.class.getName();
        before.code = HttpStatus.SC_INTERNAL_SERVER_ERROR;
        before.message = "An error has occured";
        before.setAttribute("attr1", "value1");
        before.setAttribute("attr2", "value2");
    }

    @Test
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        logger.debug("XML (before): " + xml);

        Data afterXML = Data.fromXML(xml);
        logger.debug("XML (after): " + afterXML.toXML());

        // Assert
        assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        logger.debug("JSON (before): " + json);

        Data afterJSON = JSONSerializer.fromJSON(json, Data.class);
        logger.debug("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
