package com.netscape.certsrv.kra;

import org.dogtagpki.common.KRAInfoClient;
import org.dogtagpki.kra.KRASystemCertClient;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;
import com.netscape.certsrv.key.KeyClient;

public class KRAClient extends SubsystemClient {

    public KRAClient(PKIClient client) throws Exception {
        super(client, "kra");
        init();
    }

    public void init() throws Exception {

        addClient(new KeyClient(client, name));
        addClient(new KRASystemCertClient(client, name));
        addClient(new KRAInfoClient(client, name));
    }
}
