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
// (C) 2013 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.dogtagpki.tps.apdu;

import org.dogtagpki.tps.main.TPSBuffer;
import org.dogtagpki.tps.main.Util;
import org.mozilla.jss.pkcs11.PK11SymKey;

import com.netscape.certsrv.base.EBaseException;

public abstract class APDU {

    public static int DEFAULT_APDU_SIZE = 32;

    public enum Type {
        APDU_UNDEFINED,
        APDU_CREATE_OBJECT,
        APDU_EXTERNAL_AUTHENTICATE,
        APDU_INITIALIZE_UPDATE,
        APDU_LIFECYCLE,
        APDU_READ_BUFFER,
        APDU_SET_PIN,
        APDU_UNBLOCK_PIN,
        APDU_WRITE_OBJECT,
        APDU_GENERATE_KEY,
        APDU_PUT_KEY,
        APDU_SELECT,
        APDU_GET_VERSION,
        APDU_DELETE_FILE,
        APDU_INSTALL_APPLET,
        APDU_FORMAT_MUSCLE_APPLET,
        APDU_LOAD_FILE,
        APDU_INSTALL_LOAD,
        APDU_GET_STATUS,
        APDU_LIST_PINS,
        APDU_CREATE_PIN,
        APDU_GET_DATA,
        APDU_READ_OBJECT,
        APDU_LIST_OBJECTS,
        APDU_IMPORT_KEY,
        APDU_IMPORT_KEY_ENC,
        APDU_SET_ISSUERINFO,
        APDU_GET_ISSUERINFO,
        APDU_GENERATE_KEY_ECC,
        APDU_GET_LIFECYCLE
    }

    protected byte cla;
    protected byte ins;
    protected byte p1;
    protected byte p2;

    protected TPSBuffer data = null;
    protected TPSBuffer plainText = null;
    protected TPSBuffer mac = null;
    protected TPSBuffer trailer = null;

    public APDU() {
        data = new TPSBuffer();
    }

    public APDU(APDU otherAPDU) {
        data = new TPSBuffer(otherAPDU.getData());
    }

    void setCLA(byte theCla) {
        cla = theCla;
    }

    void setINS(byte theIns) {
        ins = theIns;
    }

    void setP1(byte theP1) {
        p1 = theP1;
    }

    void setP2(byte theP2) {
        p2 = theP2;
    }

    void setData(TPSBuffer theData) {
        data = new TPSBuffer(theData);

    }

    public void setMAC(TPSBuffer theMac) {
        mac = theMac;
    }

    public void setTrailer(TPSBuffer theTrailer) {
        trailer = theTrailer;
    }

    /**
     * Retrieves APDU's encoding.
     * The encoding of APDU is as follows:
     *
     * CLA 1 byte
     * INS 1 byte
     * P1 1 byte
     * P2 1 byte
     * <Data Size> 1 byte
     * <Data> <Data Size> byte(s)
     * 0 1 byte
     *
     * @param data the result buffer which will contain the actual data
     *            including the APDU header, data, and pre-calculated mac.
     */

    public TPSBuffer getEncoding() {

        TPSBuffer encoding = new TPSBuffer();

        encoding.add(cla);
        encoding.add(ins);
        encoding.add(p1);
        encoding.add(p2);

        int m_mac_size = 0;

        if (mac != null) {
            m_mac_size = mac.size();
        }

        encoding.add((byte) (data.size() + m_mac_size));

        encoding.add(data);

        if (m_mac_size > 0) {
            encoding.add(mac);
        }

        if (trailer != null) {
            encoding.add(trailer);
        }

        return encoding;
    }

    public TPSBuffer getDataToMAC() {
        TPSBuffer mac = new TPSBuffer();

        mac.add(cla);
        mac.add(ins);
        mac.add(p1);
        mac.add(p2);
        mac.add((byte) (data.size() + 8));
        mac.add(data);

        return mac;
    }

    public void secureMessage(PK11SymKey encKey, byte protocol) throws EBaseException {

        if (encKey == null) {
            throw new EBaseException("APDU.secureData: No input encrytion session key!");
        }

        int padNeeded = 0;

        TPSBuffer dataToEnc = null;
        TPSBuffer padding = null;
        TPSBuffer dataEncrypted = null;

        dataToEnc = new TPSBuffer();

        if(protocol == (byte) 1) {
            dataToEnc.add((byte) data.size());
        }

        dataToEnc.add(data);

        int dataSize = dataToEnc.size();
        int rem = dataSize % 8;

        if (rem == 0) {

            if (protocol == (byte) 1) {
                padNeeded = 0;
            }
            else if (protocol == (byte) 2) {
                padNeeded = 8;
            }
        } else if (dataSize < 8) {
            padNeeded = 8 - dataSize;
        } else {
            padNeeded = 8 - rem;
        }

        if (padNeeded > 0) {
            dataToEnc.add((byte) 0x80);
            padNeeded--;

            if (padNeeded > 0) {
                padding = new TPSBuffer(padNeeded);
                dataToEnc.add(padding);
            }
        }

        dataEncrypted = Util.encryptData(dataToEnc, encKey);

        data.set(dataEncrypted);
    }

    public void secureMessageSCP02(PK11SymKey encKey) throws EBaseException {

        if (encKey == null) {
            throw new EBaseException("APDU.secureDataSCP02: Invalid input data!");
        }

        secureMessage(encKey,(byte) 2);

    }

    public Type getType() {
        return Type.APDU_UNDEFINED;
    }

    public TPSBuffer getData() {
        return data;
    }

    public TPSBuffer getMAC() {
        return mac;
    }

    public byte getCLA() {
        return cla;

    }

    public byte getINS() {
        return ins;
    }

    public byte getP1() {
        return p1;
    }

    public byte getP2() {
        return p2;
    }

    public void dump() {

        int claInt = cla & 0xff;
        int insInt = ins & 0xff;
        int p1Int = p1 & 0xff;
        int p2Int = p2 & 0xff;

        System.out.println("APDU: ");
        System.out.println("CLA: " + Util.intToHex(claInt));
        System.out.println("INS: " + Util.intToHex(insInt));
        System.out.println("P1: " + Util.intToHex(p1Int));
        System.out.println("P2: " + Util.intToHex(p2Int));

        data.dump();
    }

};
