package com.netscape.certsrv.cert;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.certsrv.util.JSONSerializer;

public class CertRequestInfoTest {

    public static Logger logger = LoggerFactory.getLogger(CertRequestInfoTest.class);

    private static CertRequestInfo before = new CertRequestInfo();

    @BeforeAll
    public static void setUpBefore() {
        before.setRequestID(new RequestId("0x1"));
        before.setRequestType("enrollment");
        before.setRequestStatus(RequestStatus.COMPLETE);
        before.setCertRequestType("pkcs10");
        before.setCertId(new CertId("5"));
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        logger.debug("JSON (before): " + json);

        CertRequestInfo afterJSON = JSONSerializer.fromJSON(json, CertRequestInfo.class);
        logger.debug("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
