package com.netscape.certsrv.tps.cert;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Date;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.util.JSONSerializer;

public class TPSCertDataTest {

    public static Logger logger = LoggerFactory.getLogger(TPSCertDataTest.class);

    private static TPSCertData before = new TPSCertData();

    @BeforeAll
    public static void setUpBefore() {
        before.setID("cert1");
        before.setSerialNumber("16");
        before.setSubject("cn=someone");
        before.setTokenID("TOKEN1234");
        before.setKeyType("something");
        before.setStatus("active");
        before.setUserID("user1");
        before.setCreateTime(new Date());
        before.setModifyTime(new Date());
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        logger.debug("JSON (before): " + json);

        TPSCertData afterJSON = JSONSerializer.fromJSON(json, TPSCertData.class);
        logger.debug("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
