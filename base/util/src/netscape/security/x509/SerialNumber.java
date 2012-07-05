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
import java.io.InputStream;
import java.io.Serializable;
import java.math.BigInteger;

import netscape.security.util.BigInt;
import netscape.security.util.DerInputStream;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;

/**
 * This class defines the SerialNumber class used by certificates.
 *
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 * @version 1.5
 */
public class SerialNumber implements Serializable {

    private static final long serialVersionUID = 1600956411497203535L;
    private BigInt serialNum;

    // Construct the class from the DerValue
    private void construct(DerValue derVal) throws IOException {
        serialNum = derVal.getInteger();
        if (derVal.data.available() != 0) {
            throw new IOException("Excess SerialNumber data");
        }
    }

    /**
     * The default constructor for this class using BigInteger.
     *
     * @param num the BigInteger number used to create the serial number.
     */
    public SerialNumber(BigInteger num) {
        serialNum = new BigInt(num);
    }

    public SerialNumber(BigInt num) {
        serialNum = num;
    }

    /**
     * The default constructor for this class using int.
     *
     * @param num the BigInteger number used to create the serial number.
     */
    public SerialNumber(int num) {
        serialNum = new BigInt(num);
    }

    /**
     * Create the object, decoding the values from the passed DER stream.
     *
     * @param in the DerInputStream to read the SerialNumber from.
     * @exception IOException on decoding errors.
     */
    public SerialNumber(DerInputStream in) throws IOException {
        DerValue derVal = in.getDerValue();
        construct(derVal);
    }

    /**
     * Create the object, decoding the values from the passed DerValue.
     *
     * @param val the DerValue to read the SerialNumber from.
     * @exception IOException on decoding errors.
     */
    public SerialNumber(DerValue val) throws IOException {
        construct(val);
    }

    /**
     * Create the object, decoding the values from the passed stream.
     *
     * @param in the InputStream to read the SerialNumber from.
     * @exception IOException on decoding errors.
     */
    public SerialNumber(InputStream in) throws IOException {
        DerValue derVal = new DerValue(in);
        construct(derVal);
    }

    /**
     * Return the SerialNumber as user readable string.
     */
    public String toString() {
        return ("SerialNumber: [" + serialNum.toString() + "]");
    }

    /**
     * Encode the SerialNumber in DER form to the stream.
     *
     * @param out the DerOutputStream to marshal the contents to.
     * @exception IOException on errors.
     */
    public void encode(DerOutputStream out) throws IOException {
        out.putInteger(serialNum);
    }

    /**
     * Return the serial number.
     */
    public BigInt getNumber() {
        return (serialNum);
    }
}
