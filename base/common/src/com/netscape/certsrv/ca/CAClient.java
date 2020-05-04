//--- BEGIN COPYRIGHT BLOCK ---
//This program is free software; you can redistribute it and/or modify
//it under the terms of the GNU General Public License as published by
//the Free Software Foundation; version 2 of the License.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License along
//with this program; if not, write to the Free Software Foundation, Inc.,
//51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
//(C) 2012 Red Hat, Inc.
//All rights reserved.
//--- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.ca;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;

import org.mozilla.jss.netscape.security.pkcs.PKCS7;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.authority.AuthorityClient;
import com.netscape.certsrv.client.ClientConfig;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;
import com.netscape.certsrv.group.GroupClient;
import com.netscape.certsrv.profile.ProfileClient;
import com.netscape.certsrv.selftests.SelfTestClient;
import com.netscape.certsrv.system.FeatureClient;
import com.netscape.certsrv.user.UserClient;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.xml.XMLObject;

public class CAClient extends SubsystemClient {

    public final static Logger logger = LoggerFactory.getLogger(CAClient.class);

    public CAClient(PKIClient client) throws URISyntaxException {
        super(client, "ca");
        init();
    }

    public void init() throws URISyntaxException {
        addClient(new AuthorityClient(client, name));
        addClient(new CACertClient(client, name));
        addClient(new FeatureClient(client, name));
        addClient(new GroupClient(client, name));
        addClient(new ProfileClient(client, name));
        addClient(new SelfTestClient(client, name));
        addClient(new UserClient(client, name));
    }

    public PKCS7 getCertChain() throws Exception {

        ClientConfig config = client.getConfig();
        URL serverURL = config.getServerURL();
        logger.info("Getting certificate chain from " + serverURL);

        String c = client.get("/ca/admin/ca/getCertChain");
        logger.debug("Response: " + c);

        if (c == null) {
            throw new IOException("Unable to get certificate chain from " + serverURL);
        }

        ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());
        XMLObject parser = new XMLObject(bis);
        String chain = parser.getValue("ChainBase64");

        if (chain == null || chain.length() <= 0) {
            throw new IOException("Missing certificate chain");
        }

        byte[] bytes = CryptoUtil.base64Decode(CryptoUtil.normalizeCertStr(chain));

        return new PKCS7(bytes);
    }
}
