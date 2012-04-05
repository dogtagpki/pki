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
package netscape.security.x509;

import java.io.IOException;
import java.util.StringTokenizer;

import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;

/**
 * This class implements the IPAddressName as required by the GeneralNames
 * ASN.1 object.
 *
 * @see GeneralName
 * @see GeneralNameInterface
 * @see GeneralNames
 *
 * @version 1.2
 *
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 */
public class IPAddressName implements GeneralNameInterface {
    /**
     *
     */
    private static final long serialVersionUID = -4240184399679453666L;
    private byte[] address;

    /**
     * Create the IPAddressName object from the passed encoded Der value.
     *
     * @param derValue the encoded DER IPAddressName.
     * @exception IOException on error.
     */
    public IPAddressName(DerValue derValue) throws IOException {
        address = derValue.getOctetString();
    }

    /**
     * Create the IPAddressName object with the specified name.
     *
     * @param name the IPAddressName.
     */
    public IPAddressName(byte[] address) {
        this.address = address;
    }

    protected static final char IPv4_LEN = 4;
    protected static final char IPv6_LEN = 16;
    protected static final IPAddr IPv4 = new IPv4Addr();
    protected static final IPAddr IPv6 = new IPv6Addr();

    /**
     * Create the IPAddressName object with a string representing the
     * ip address and a string representing the netmask, with encoding
     * having ip address encoding followed by the netmask encoding.
     * This form is needed for name constraints extension.
     *
     * @param s the ip address in the format: n.n.n.n or x:x:x:x:x:x:x:x (RFC 1884)
     * @param netmask the netmask address in the format: n.n.n.n or x:x:x:x:x:x:x:x (RFC 1884)
     */
    public IPAddressName(String s, String netmask) {
        // Based on PKIX RFC2459. IPAddress has
        // 8 bytes (instead of 4 bytes) in the
        // context of NameConstraints
        IPAddr ipAddr = null;
        if (s.indexOf(':') != -1) {
            ipAddr = IPv6;
            address = new byte[IPv6_LEN * 2];
        } else {
            ipAddr = IPv4;
            address = new byte[IPv4_LEN * 2];
        }
        StringTokenizer st = new StringTokenizer(s, ",");
        int numFilled = ipAddr.getIPAddr(st.nextToken(), address, 0);
        if (st.hasMoreTokens()) {
            ipAddr.getIPAddr(st.nextToken(), address, numFilled);
        } else {
            for (int i = numFilled; i < address.length; i++)
                address[i] = (byte) 0xff;
        }
    }

    /**
     * Create the IPAddressName object with a string representing the
     * ip address.
     *
     * @param s the ip address in the format: n.n.n.n or x:x:x:x:x:x:x:x
     */
    public IPAddressName(String s) {
        IPAddr ipAddr = null;
        if (s.indexOf(':') != -1) {
            ipAddr = IPv6;
            address = new byte[IPv6_LEN];
        } else {
            ipAddr = IPv4;
            address = new byte[IPv4_LEN];
        }
        ipAddr.getIPAddr(s, address, 0);
    }

    /**
     * Return the type of the GeneralName.
     */
    public int getType() {
        return (GeneralNameInterface.NAME_IP);
    }

    /**
     * Encode the IPAddress name into the DerOutputStream.
     *
     * @param out the DER stream to encode the IPAddressName to.
     * @exception IOException on encoding errors.
     */
    public void encode(DerOutputStream out) throws IOException {
        out.putOctetString(address);
    }

    /**
     * Return a printable string of IPaddress
     */
    public String toString() {
        if (address.length == 4) {
            return ("IPAddress: " + (address[0] & 0xff) + "."
                    + (address[1] & 0xff) + "."
                    + (address[2] & 0xff) + "." + (address[3] & 0xff));
        } else {
            String r = "IPAddress: " + Integer.toHexString(address[0] & 0xff);
            String hexString = Integer.toHexString(address[1] & 0xff);
            if (hexString.length() == 1) {
                r = r + "0" + hexString;
            } else {
                r += hexString;
            }
            for (int i = 2; i < address.length;) {
                r += ":" + Integer.toHexString(address[i] & 0xff);
                hexString = Integer.toHexString(address[i + 1] & 0xff);
                if (hexString.length() == 1) {
                    r = r + "0" + hexString;
                } else {
                    r += hexString;
                }
                i += 2;
            }
            return r;
        }
    }
}

interface IPAddr {
    public int getIPAddr(String s, byte[] address, int start);

    public int getLength();
}

class IPv4Addr implements IPAddr {
    protected static final int IPv4_LEN = 4;

    /**
     * Gets an IP v4 address in the form n.n.n.n.
     */
    public int getIPAddr(String s, byte[] address, int start) {
        StringTokenizer st = new StringTokenizer(s, ".");
        int nt = st.countTokens();
        if (nt != IPv4_LEN)
            throw new InvalidIPAddressException(s);
        try {
            int end = start + nt;
            for (int i = start; i < end; i++) {
                Integer j = new Integer(st.nextToken());
                address[i] = (byte) j.intValue();
            }
        } catch (NumberFormatException e) {
            throw new InvalidIPAddressException(s);
        }
        return nt;
    }

    public int getLength() {
        return IPv4_LEN;
    }
}

class IPv6Addr implements IPAddr {
    /**
     * Gets an IP address in the forms as defined in RFC1884:<br>
     * <ul>
     * <li>x:x:x:x:x:x:x:x
     * <li>...::xxx (using :: shorthand)
     * <li>...:n.n.n.n (with n.n.n.n at the end)
     * </ul>
     */
    public int getIPAddr(String s, byte[] address, int start) {
        int lastcolon = -2;
        int end = start + 16;
        int idx = start;
        for (int i = start; i < address.length; i++)
            address[i] = 0;
        if (s.indexOf('.') != -1) { // has n.n.n.n at the end
            lastcolon = s.lastIndexOf(':');
            if (lastcolon == -1)
                throw new InvalidIPAddressException(s);
            end -= 4;
            IPAddressName.IPv4.getIPAddr(
                    s.substring(lastcolon + 1), address, end);
        }
        try {
            String s1 = s;
            if (lastcolon != -2)
                s1 = s.substring(0, lastcolon + 1);
            int lastDoubleColon = s1.indexOf("::");
            String l = s1, r = null;
            StringTokenizer lt = null, rt = null;
            if (lastDoubleColon != -1) {
                l = s1.substring(0, lastDoubleColon);
                r = s1.substring(lastDoubleColon + 2);
                if (l.length() == 0)
                    l = null;
                if (r.length() == 0)
                    r = null;
            }
            int at = 0;
            if (l != null) {
                lt = new StringTokenizer(l, ":", false);
                at += lt.countTokens();
            }
            if (r != null) {
                rt = new StringTokenizer(r, ":", false);
                at += rt.countTokens();
            }
            if (at > 8 ||
                    (lastcolon != -2 && (at > 6 || (lastDoubleColon == -1 && at != 6))))
                throw new InvalidIPAddressException(s);
            if (l != null) {
                while (lt.hasMoreTokens()) {
                    String tok = lt.nextToken();
                    int j = Integer.parseInt(tok, 16);
                    address[idx++] = (byte) ((j >> 8) & 0xFF);
                    address[idx++] = (byte) (j & 0xFF);
                }
            }
            if (r != null) {
                idx = end - (rt.countTokens() * 2);
                while (rt.hasMoreTokens()) {
                    String tok = rt.nextToken();
                    int j = Integer.parseInt(tok, 16);
                    address[idx++] = (byte) ((j >> 8) & 0xFF);
                    address[idx++] = (byte) (j & 0xFF);
                }
            }
        } catch (NumberFormatException e) {
            throw new InvalidIPAddressException(s);
        }
        return 16;
    }

    public int getLength() {
        return 16;
    }
}
