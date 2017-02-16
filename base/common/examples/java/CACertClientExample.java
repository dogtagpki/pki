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

import java.net.InetAddress;

import com.netscape.certsrv.ca.CAClient;
import com.netscape.certsrv.cert.CertClient;
import com.netscape.certsrv.cert.CertData;
import com.netscape.certsrv.cert.CertDataInfo;
import com.netscape.certsrv.cert.CertDataInfos;
import com.netscape.certsrv.cert.CertSearchRequest;
import com.netscape.certsrv.client.ClientConfig;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.dbs.certdb.CertId;

/**
 * To compile the program:
 * $ javac -cp "../../lib/*" CACertClientExample.java
 *
 * To run the program:
 * $ java -cp "../../lib/*:." CACertClientExample
 */
public class CACertClientExample {

    public static void main(String args[]) throws Exception {

        String protocol = "http";
        String hostname = InetAddress.getLocalHost().getHostName();
        int port = 8080;

        ClientConfig config = new ClientConfig();
        config.setServerURL(protocol, hostname, port);

        PKIClient client = new PKIClient(config);
        CAClient caClient = new CAClient(client);
        CertClient certClient = new CertClient(caClient);

        CertDataInfos infos = certClient.listCerts(null, null, null, null, null);

        System.out.println("Total: " + infos.getTotal());
        System.out.println();
        System.out.println("Certificates:");

        for (CertDataInfo info : infos.getEntries()) {
            System.out.println("- Serial: " + info.getID());
            System.out.println("  Subject: " + info.getSubjectDN());
        }

        System.out.println();
        System.out.println("CA Certificate:");

        CertSearchRequest request = new CertSearchRequest();
        request.setCommonName("commonName");

        infos = certClient.findCerts(request, null, null);
        CertId id = infos.getEntries().iterator().next().getID();

        CertData data = certClient.getCert(id);
        System.out.println(data.getEncoded());
    }
}
