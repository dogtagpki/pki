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
package com.netscape.cmsutil.radius;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Properties;

/**
 * This class implements RFC2865 - Remote Authentication Dial In
 * User Service (RADIUS), June 2000.
 */
public class RadiusConn {
    public static int MAX_RETRIES = 10;
    public static int OFFICAL_PORT = 1812;
    public static int DEFAULT_PORT = 1645;
    public static int DEFAULT_TIMEOUT = 5;

    public static String OPTION_DEBUG = "OPTION_DEBUG";

    @SuppressWarnings("unused")
    private Properties _options;
    private boolean _traceOn = true;
    private String _host[] = new String[2];
    private int _port[] = new int[2];
    private int _selected = 0;
    private String _secret = null;
    private DatagramSocket _socket = null;
    private short _id = (short) System.currentTimeMillis();
    private int _maxRetries = MAX_RETRIES;
    private SecureRandom _rand = null;

    public RadiusConn(String host1, String host2, int port, String secret,
            int timeout) throws SocketException {
        this(host1, port, host2, port, secret, timeout, null, null);
    }

    public RadiusConn(String host, int port, String secret, byte seed[],
            Properties options)
            throws SocketException {
        this(host, port, host, port, secret, DEFAULT_TIMEOUT, seed, options);
    }

    public RadiusConn(String host1, int port1, String host2, int port2,
            String secret, int timeout, byte seed[], Properties options)
            throws SocketException {
        _host[0] = host1;
        _port[0] = port1;
        _host[1] = host2;
        _port[1] = port2;
        _selected = 0;
        _secret = secret;
        _options = options;
        _socket = new DatagramSocket();
        _socket.setSoTimeout(timeout * 1000);
        if (seed == null) {
            _rand = new SecureRandom();
        } else {
            _rand = new SecureRandom(seed);
        }
    }

    public void disconnect() throws IOException {
        _socket.disconnect();
    }

    public void authenticate(String name, String password)
            throws IOException, NoSuchAlgorithmException,
            RejectException, ChallengeException {
        int retries = 0;
        Packet res = null;

        do {
            AccessRequest req = createAccessRequest();

            req.addAttribute(new UserNameAttribute(name));
            req.addAttribute(new UserPasswordAttribute(req.getAuthenticator(),
                    _secret, password));
            req.addAttribute(new NASIPAddressAttribute(InetAddress.getLocalHost()));
            req.addAttribute(new NASPortAttribute(_socket.getLocalPort()));

            send(req, _host[_selected], _port[_selected]);
            try {
                retries++;
                res = receive();
                if (res instanceof AccessReject) {
                    throw new RejectException((AccessReject) res);
                } else if (res instanceof AccessChallenge) {
                    throw new ChallengeException((AccessChallenge) res);
                }
            } catch (InterruptedIOException e) {
                if (retries >= _maxRetries) {
                    // switch server if maxRetries reaches limit
                    retries = 0;
                    if (_selected == 0) {
                        _selected = 1;
                    } else {
                        _selected = 0;
                    }
                    // throw e;
                }

            }
        } while (res == null);
    }

    public void replyChallenge(String password, ChallengeException ce)
            throws IOException, NoSuchAlgorithmException,
            RejectException, ChallengeException {
        replyChallenge(null, password, ce);
    }

    public void replyChallenge(String name, String password,
            ChallengeException ce)
            throws IOException, NoSuchAlgorithmException,
            RejectException, ChallengeException {
        StateAttribute state = (StateAttribute)
                ce.getAttributeSet().getAttributeByType(Attribute.STATE);

        if (state == null)
            throw new IOException("State not found in challenge");
        AccessRequest req = createAccessRequest();

        req.addAttribute(state); // needed in challenge
        if (name != null) {
            req.addAttribute(new UserNameAttribute(name));
        }
        req.addAttribute(new UserPasswordAttribute(req.getAuthenticator(),
                _secret, password));
        req.addAttribute(new NASIPAddressAttribute(InetAddress.getLocalHost()));
        req.addAttribute(new NASPortAttribute(_socket.getLocalPort()));

        send(req, _host[_selected], _port[_selected]);
        Packet res = receive();

        if (res instanceof AccessReject) {
            throw new RejectException((AccessReject) res);
        } else if (res instanceof AccessChallenge) {
            throw new ChallengeException((AccessChallenge) res);
        }
    }

    public void replyChallenge(String name, String password, String state)
            throws IOException, NoSuchAlgorithmException,
            RejectException, ChallengeException {
        if (state == null)
            throw new IOException("State not found in challenge");
        AccessRequest req = createAccessRequest();

        req.addAttribute(new StateAttribute(state)); // needed in challenge
        req.addAttribute(new UserNameAttribute(name));
        req.addAttribute(new UserPasswordAttribute(req.getAuthenticator(),
                _secret, password));
        req.addAttribute(new NASIPAddressAttribute(InetAddress.getLocalHost()));
        req.addAttribute(new NASPortAttribute(_socket.getLocalPort()));

        send(req, _host[_selected], _port[_selected]);
        Packet res = receive();

        if (res instanceof AccessReject) {
            throw new RejectException((AccessReject) res);
        } else if (res instanceof AccessChallenge) {
            throw new ChallengeException((AccessChallenge) res);
        }
    }

    private short getIdentifier() {
        return _id++;
    }

    private void send(NASPacket packet, String host, int port)
            throws IOException {
        DatagramPacket dp = new DatagramPacket(new byte[4096], 4096);

        dp.setPort(port);
        dp.setAddress(InetAddress.getByName(host));
        byte data[] = packet.getData();

        dp.setLength(data.length);
        dp.setData(data);
        _socket.send(dp);
        if (_traceOn)
            trace("Sent " + packet);
    }

    private ServerPacket receive()
            throws IOException {
        DatagramPacket dp = new DatagramPacket(new byte[4096], 4096);

        _socket.receive(dp);
        byte data[] = dp.getData();
        ServerPacket p = PacketFactory.createServerPacket(data);

        if (_traceOn)
            trace("Received " + p + " size=" + p.getAttributeSet().size());
        return p;
    }

    private AccessRequest createAccessRequest() throws NoSuchAlgorithmException {
        RequestAuthenticator ra = new RequestAuthenticator(_rand, _secret);
        AccessRequest req = new AccessRequest(getIdentifier(), ra);

        return req;
    }

    private void trace(String msg) {
        System.out.println("TRACE: " + msg);
        System.out.flush();
    }
}
