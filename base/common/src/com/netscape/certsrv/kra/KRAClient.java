package com.netscape.certsrv.kra;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;
import com.netscape.certsrv.group.GroupClient;
import com.netscape.certsrv.key.KeyClient;
import com.netscape.certsrv.selftests.SelfTestClient;
import com.netscape.certsrv.system.SystemCertClient;
import com.netscape.certsrv.user.UserClient;

public class KRAClient extends SubsystemClient {

    public KRAClient(PKIClient client) throws Exception {
        super(client, "kra");
        init();
    }

    public void init() throws Exception {

        addClient(new GroupClient(client, name));
        addClient(new KeyClient(client, name));
        addClient(new SelfTestClient(client, name));
        addClient(new SystemCertClient(client, name));
        addClient(new UserClient(client, name));
    }
}
