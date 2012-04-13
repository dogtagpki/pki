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
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.servlet.csadmin;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.Enumeration;
import org.apache.http.client.HttpClient;
import org.apache.http.conn.scheme.LayeredSchemeSocketFactory;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeSocketFactory;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.params.HttpParams;
import org.jboss.resteasy.client.ClientExecutor;
import org.jboss.resteasy.client.ProxyFactory;
import org.jboss.resteasy.client.core.executors.ApacheHttpClient4Executor;
import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.mozilla.jss.ssl.SSLCertificateApprovalCallback;
import org.mozilla.jss.ssl.SSLSocket;

import com.netscape.cms.servlet.csadmin.model.ConfigurationData;
import com.netscape.cms.servlet.csadmin.model.ConfigurationResponseData;
import com.netscape.cms.servlet.csadmin.model.InstallToken;
import com.netscape.cms.servlet.csadmin.model.InstallTokenRequest;


/**
 * @author alee
 *
 */
public class ConfigurationRESTClient {
    private class ServerCertApprovalCB implements SSLCertificateApprovalCallback {

        public boolean approve(org.mozilla.jss.crypto.X509Certificate servercert,
                SSLCertificateApprovalCallback.ValidityStatus status) {

            //For now lets just accept the server cert. This is a test tool, being
            // pointed at a well known instance.


            if (servercert != null) {
                System.out.println("Peer cert details: " +
                        "\n     subject: " + servercert.getSubjectDN().toString() +
                        "\n     issuer:  " + servercert.getIssuerDN().toString() +
                        "\n     serial:  " + servercert.getSerialNumber().toString()
                        );
            }

            SSLCertificateApprovalCallback.ValidityItem item;
            Enumeration<?> errors = status.getReasons();
            int i = 0;
            while (errors.hasMoreElements()) {
                i++;
                item = (SSLCertificateApprovalCallback.ValidityItem) errors.nextElement();
                System.out.println("item " + i +
                        " reason=" + item.getReason() +
                        " depth=" + item.getDepth());

                int reason = item.getReason();

                if (reason ==
                        SSLCertificateApprovalCallback.ValidityStatus.UNTRUSTED_ISSUER ||
                        reason == SSLCertificateApprovalCallback.ValidityStatus.BAD_CERT_DOMAIN) {

                    //Allow these two since we haven't necessarily installed the CA cert for trust
                    // and we are choosing "localhost" as the host for this client.

                    return true;

                }
            }

            //For other errors return false
            return false;
        }
    }
    
    private class JSSProtocolSocketFactory implements SchemeSocketFactory, LayeredSchemeSocketFactory {
        @Override
        public Socket createSocket(HttpParams params)
                throws IOException {
            return null;
        }

        @Override
        public Socket connectSocket(Socket sock, InetSocketAddress remoteAddress,
                InetSocketAddress localAddress, HttpParams params)
                throws IOException, UnknownHostException {
            Socket socket;
            String hostName = null;
            int port = 0;
            if (remoteAddress != null) {
                hostName = remoteAddress.getHostName();
                port = remoteAddress.getPort();

            }

            int localPort = 0;
            InetAddress localAddr = null;
            if (localAddress != null) {
                localPort = localAddress.getPort();
                localAddr = localAddress.getAddress();
            }

            if (sock == null) {
                socket = new SSLSocket(InetAddress.getByName(hostName), port, localAddr, localPort,
                        new ServerCertApprovalCB(), null);

            } else {
                socket = new SSLSocket(sock, hostName, new ServerCertApprovalCB(), null);
            }

            return socket;
        }

        @Override
        public boolean isSecure(Socket sock) {
            //We only use this factory in the case of SSL Connections
            return true;
        }

        @Override
        public Socket createLayeredSocket(Socket arg0, String arg1, int arg2, boolean arg3) throws IOException,
                UnknownHostException {
            //This method implementation is required to get SSL working.
            return null;
        }
    }

    private String clientCertNickname;
    private SystemConfigurationResource configClient;

    public ConfigurationRESTClient(String baseUri, String clientCertNick) throws URISyntaxException {

        // For SSL we are assuming the caller has already intialized JSS and has
        // a valid CryptoManager and CryptoToken
        // optional clientCertNickname is provided for use if required.


        URI uri = new URI(baseUri);
        
        String protocol = uri.getScheme();
        int port = uri.getPort();
 
        clientCertNickname = null;
        HttpClient httpclient = new DefaultHttpClient();
        if(protocol != null && protocol.equals("https")) {
            if (clientCertNick != null) {
                clientCertNickname = clientCertNick;
            }
 
            Scheme scheme = new Scheme("https",port, new JSSProtocolSocketFactory());
           
            // Register for port 443 our SSLSocketFactory to the ConnectionManager
            httpclient.getConnectionManager().getSchemeRegistry().register(scheme);
           
        }
       
       
        ClientExecutor executor = new ApacheHttpClient4Executor(httpclient);
        
        ResteasyProviderFactory providerFactory = ResteasyProviderFactory.getInstance();
        providerFactory.addClientErrorInterceptor(new ConfigurationErrorInterceptor());
        configClient = ProxyFactory.create(SystemConfigurationResource.class, uri, executor, providerFactory);
    }
    
    public ConfigurationResponseData configure(ConfigurationData data) {
        ConfigurationResponseData response = configClient.configure(data);
        return response;
    }

    public InstallToken getInstallToken(InstallTokenRequest data) {
        InstallToken token = configClient.getInstallToken(data);
        return token;
    }

}
