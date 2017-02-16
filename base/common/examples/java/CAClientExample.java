// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2017 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

import java.io.File;
import java.net.InetAddress;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.util.Password;

import com.netscape.certsrv.account.AccountInfo;
import com.netscape.certsrv.ca.CAClient;
import com.netscape.certsrv.client.ClientConfig;
import com.netscape.certsrv.client.PKIClient;

/**
 * First, create an NSS database:
 * $ pki -c Secret.123 client-init
 *
 * Then import CA admin certificate and key from PKCS #12 file:
 * $ pki -c Secret.123 client-cert-import --pkcs12 &lt;file&gt; --pkcs12-password &lt;password&gt;
 *
 * To compile the program:
 * $ javac -cp "/usr/lib/java/jss4.jar:../../lib/*" CAClientExample.java
 *
 * To run the program:
 * $ java -cp "../../lib/*:." CAClientExample
 */
public class CAClientExample {

    public static void main(String args[]) throws Exception {

        String home = System.getProperty("user.home");

        String nssDatabasePath = home + File.separator + ".dogtag" + File.separator + "nssdb";
        String nssDatabasePassword = "Secret.123";

        String protocol = "https";
        String hostname = InetAddress.getLocalHost().getHostName();
        int port = 8443;

        String nickname = "caadmin";

        CryptoManager.initialize(nssDatabasePath);

        CryptoManager manager = CryptoManager.getInstance();
        CryptoToken token = manager.getInternalKeyStorageToken();
        Password password = new Password(nssDatabasePassword.toCharArray());
        token.login(password);

        ClientConfig config = new ClientConfig();
        config.setServerURL(protocol, hostname, port);
        config.setCertNickname(nickname);

        PKIClient client = new PKIClient(config);
        CAClient caClient = new CAClient(client);

        AccountInfo accountInfo = caClient.login();

        System.out.println("User ID: " + accountInfo.getID());
        System.out.println("Full name: " + accountInfo.getFullName());
        System.out.println();
        System.out.println("Roles:");

        for (String role : accountInfo.getRoles()) {
            System.out.println(" - " + role);
        }

        caClient.logout();
    }
}
