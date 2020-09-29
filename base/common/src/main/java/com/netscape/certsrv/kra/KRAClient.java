package com.netscape.certsrv.kra;

import org.dogtagpki.common.KRAInfoClient;
import org.dogtagpki.kra.KRASystemCertClient;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;
import com.netscape.certsrv.group.GroupClient;
import com.netscape.certsrv.key.KeyClient;
import com.netscape.certsrv.selftests.SelfTestClient;
import com.netscape.certsrv.user.UserClient;

public class KRAClient extends SubsystemClient {

    public KRAClient(PKIClient client) throws Exception {
        super(client, "kra");
        init();
    }

    public void init() throws Exception {

        addClient(new GroupClient(this));
        addClient(new KeyClient(client, name));
        addClient(new SelfTestClient(client, name));
        addClient(new KRASystemCertClient(client, name));
        addClient(new UserClient(this));
        addClient(new KRAInfoClient(client, name));
    }
}
