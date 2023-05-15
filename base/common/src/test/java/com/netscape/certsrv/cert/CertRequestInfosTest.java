package com.netscape.certsrv.cert;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.certsrv.util.JSONSerializer;

public class CertRequestInfosTest {

    private static CertRequestInfo request = new CertRequestInfo();
    private static CertRequestInfos before = new CertRequestInfos();

    @BeforeAll
    public static void setUpBefore() {
        request.setRequestID(new RequestId("0x1"));
        request.setRequestType("enrollment");
        request.setRequestStatus(RequestStatus.COMPLETE);
        request.setCertRequestType("pkcs10");

        before.addEntry(request);
        before.setTotal(1);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        CertRequestInfos afterJSON = JSONSerializer.fromJSON(json, CertRequestInfos.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
