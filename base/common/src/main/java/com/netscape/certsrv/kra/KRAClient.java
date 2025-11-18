package com.netscape.certsrv.kra;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;

public class KRAClient extends SubsystemClient {

    public KRAClient(PKIClient client) throws Exception {
        super(client, "kra");
    }
}
