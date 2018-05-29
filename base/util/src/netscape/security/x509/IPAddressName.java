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
import java.nio.ByteBuffer;
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
        address = initAddress(true, s);
        if (address.length == IPv4_LEN * 2)
            fillIPv4Address(netmask, address, address.length / 2);
        else
            fillIPv6Address(netmask, address, address.length / 2);
    }

    /**
     * IP address with CIDR netmask
     *
     * @param s a single IPv4 or IPv6 address
     * @param mask a CIDR netmask
     */
    public IPAddressName(String s, CIDRNetmask mask) {
        address = initAddress(true, s);
        mask.write(ByteBuffer.wrap(
                    address, address.length / 2, address.length / 2));
    }

    /**
     * Create the IPAddressName object with a string representing the
     * ip address.
     *
     * @param s the ip address in the format: n.n.n.n or x:x:x:x:x:x:x:x
     */
    public IPAddressName(String s) {
        initAddress(false, s);
    }

    /**
     * Initialise and return a byte[] and write the IP address into it.
     * If withNetmask == true, the byte[] will be double the size,
     * with the latter half uninitialised.
     *
     * @return byte[] of length 4 or 16 if withNetmask == false,
     *         or length 8 or 32 if withNetmask == true.
     */
    private static byte[] initAddress(boolean withNetmask, String s) {
        if (s.indexOf(':') != -1) {
            byte[] address = new byte[IPv6_LEN * (withNetmask ? 2 : 1)];
            fillIPv6Address(s, address, 0);
            return address;
        } else {
            byte[] address = new byte[IPv4_LEN * (withNetmask ? 2 : 1)];
            fillIPv4Address(s, address, 0);
            return address;
        }
    }

    /**
     * Return the type of the GeneralName.
     */
    public int getType() {
        return (GeneralNameInterface.NAME_IP);
    }

    @Override
    public boolean validSingle() {
        return address.length == IPv4_LEN || address.length == IPv6_LEN;
    }

    @Override
    public boolean validSubtree() {
        return address.length == 2*IPv4_LEN || address.length == 2*IPv6_LEN;
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
        StringBuilder r = new StringBuilder("IPAddress: ");
        ByteBuffer buf = ByteBuffer.wrap(address);
        if (address.length == IPv4_LEN) {
            writeIPv4(r, buf);
        } else if (address.length == IPv4_LEN * 2) {
            writeIPv4(r, buf);
            r.append(",");
            writeIPv4(r, buf);
        } else if (address.length == IPv6_LEN) {
            writeIPv6(r, buf);
        } else if (address.length == IPv6_LEN * 2) {
            writeIPv6(r, buf);
            r.append(",");
            writeIPv6(r, buf);
        } else {
            // shouldn't be possible
            r.append("0.0.0.0");
        }
        return r.toString();
    }

    private static void writeIPv4(StringBuilder r, ByteBuffer buf) {
        for (int i = 0; i < 4; i++) {
            if (i > 0) r.append(".");
            r.append(buf.get() & 0xff);
        }
    }

    private static void writeIPv6(StringBuilder r, ByteBuffer buf) {
        for (int i = 0; i < 8; i++) {
            if (i > 0) r.append(":");
            r.append(Integer.toHexString(read16BitInt(buf)));
        }
    }

    /**
     * Read big-endian 16-bit int from buffer (advancing cursor)
     */
    private static int read16BitInt(ByteBuffer buf) {
        return ((buf.get() & 0xff) << 8) + (buf.get() & 0xff);
    }

    /**
     * Gets an IP v4 address in the form n.n.n.n.
     */
    public static int fillIPv4Address(String s, byte[] address, int start) {
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

    /**
     * Gets an IP address in the forms as defined in RFC1884:<br>
     * <ul>
     * <li>x:x:x:x:x:x:x:x
     * <li>...::xxx (using :: shorthand)
     * <li>...:n.n.n.n (with n.n.n.n at the end)
     * </ul>
     */
    public static int fillIPv6Address(String s, byte[] address, int start) {
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
            fillIPv4Address(s.substring(lastcolon + 1), address, end);
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
}
