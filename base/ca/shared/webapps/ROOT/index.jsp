<!-- --- BEGIN COPYRIGHT BLOCK ---
     This program is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published by
     the Free Software Foundation; version 2 of the License.

     This program is distributed in the hope that it will be useful,
     but WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
     GNU General Public License for more details.

     You should have received a copy of the GNU General Public License along
     with this program; if not, write to the Free Software Foundation, Inc.,
     51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

     Copyright (C) 2010 Red Hat, Inc.
     All rights reserved.
     --- END COPYRIGHT BLOCK --- -->
<%
    // establish acceptable schemes
    final String HTTP_SCHEME = "http";
    final String HTTPS_SCHEME = "https";

    // establish known ports
    final int EE_HTTP_PORT = [PKI_UNSECURE_PORT];
    final int AGENT_HTTPS_PORT = [PKI_AGENT_SECURE_PORT];
    final int EE_HTTPS_PORT = [PKI_EE_SECURE_PORT];
    final int ADMIN_HTTPS_PORT = [PKI_ADMIN_SECURE_PORT];

    // establish known paths
    final String ADMIN_PATH = "/[PKI_SUBSYSTEM_TYPE]/services";
    final String AGENT_PATH = "/[PKI_SUBSYSTEM_TYPE]/agent/[PKI_SUBSYSTEM_TYPE]";
    final String EE_PATH = "/[PKI_SUBSYSTEM_TYPE]/ee/[PKI_SUBSYSTEM_TYPE]";
    final String ERROR_PATH = "/[PKI_SUBSYSTEM_TYPE]/404.html";

    // retrieve scheme from request
    String scheme = request.getScheme();

    // retrieve client hostname on which the request was sent
    String client_hostname = request.getServerName();

    // retrieve client port number on which the request was sent
    int client_port = request.getServerPort();

    // retrieve server hostname on which the request was received
    String server_hostname = request.getLocalName();

    // retrieve server port number on which the request was received
    int server_port = request.getLocalPort();

    // uncomment the following lines to write to 'catalina.out'
    //System.out.println( "scheme = '" + scheme + "'" );
    //System.out.println( "client hostname = '" + client_hostname + "'" );
    //System.out.println( "client port = '" + client_port + "'" );
    //System.out.println( "server hostname = '" + server_hostname + "'" );
    //System.out.println( "server port = '" + server_port + "'" );

    // compose the appropriate URL
    String URL = "";

    if( scheme.equals( HTTP_SCHEME ) ) {
        if( server_port == EE_HTTP_PORT ) {
            URL = scheme + "://" + client_hostname + ":" + client_port + EE_PATH;
        } else {
            // unknown HTTP server port:  should never get here
            URL = scheme + "://" + client_hostname + ":" + client_port + ERROR_PATH;

            // uncomment the following line to write to 'catalina.out'
            //System.out.println( "Unknown HTTP server port:  '" + server_port + "'" );
        }
    } else if( scheme.equals( HTTPS_SCHEME ) ) {
        if( server_port == AGENT_HTTPS_PORT ) {
            URL = scheme + "://" + client_hostname + ":" + client_port + AGENT_PATH;
        } else if( server_port == EE_HTTPS_PORT ) {
            URL = scheme + "://" + client_hostname + ":" + client_port + EE_PATH;
        } else if( server_port == ADMIN_HTTPS_PORT ) {
            URL = scheme + "://" + client_hostname + ":" + client_port + ADMIN_PATH;
        } else {
            // unknown HTTPS server port:  should never get here
            URL = scheme + "://" + client_hostname + ":" + client_port + ERROR_PATH;

            // uncomment the following line to write to 'catalina.out'
            //System.out.println( "Unknown HTTPS server port:  '" + server_port + "'" );
        }
    } else {
        // unacceptable scheme:  should never get here
        URL = scheme + "://" + client_hostname + ":" + client_port + ERROR_PATH;

        // uncomment the following line to write to 'catalina.out'
        //System.out.println( "Unacceptable scheme:  '" + scheme + "'" );
    }

    // respond (back to browser) with the appropriate redirected URL
    response.sendRedirect( URL );
%>
