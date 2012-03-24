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
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package netscape.net;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.net.Socket;
import java.net.UnknownHostException;

/**
 * This is the base class for network clients.
 * 
 * @version 1.21, 08/07/97
 * @author Jonathan Payne
 */
public class NetworkClient {
    /** Socket for communicating with server. */
    protected Socket serverSocket = null;

    /** Stream for printing to the server. */
    public PrintStream serverOutput;

    /** Buffered stream for reading replies from server. */
    public InputStream serverInput;

    /** Open a connection to the server. */
    public void openServer(String server, int port)
            throws IOException, UnknownHostException {
        if (serverSocket != null)
            closeServer();
        serverSocket = doConnect(server, port);
        serverOutput = new PrintStream(new BufferedOutputStream(serverSocket.getOutputStream()),
                       true);
        serverInput = new BufferedInputStream(serverSocket.getInputStream());
    }

    /**
     * Return a socket connected to the server, with any
     * appropriate options pre-established
     */
    protected Socket doConnect(String server, int port)
            throws IOException, UnknownHostException {
        return new Socket(server, port);
    }

    /** Close an open connection to the server. */
    public void closeServer() throws IOException {
        if (!serverIsOpen()) {
            return;
        }
        serverSocket.close();
        serverSocket = null;
        serverInput = null;
        serverOutput = null;
    }

    /** Return server connection status */
    public boolean serverIsOpen() {
        return serverSocket != null;
    }

    /** Create connection with host <i>host</i> on port <i>port</i> */
    public NetworkClient(String host, int port) throws IOException {
        openServer(host, port);
    }

    public NetworkClient() {
    }
}
