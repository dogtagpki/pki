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
package org.dogtagpki.server.tps.apdu;

import org.dogtagpki.server.tps.main.TPSBuffer;

public abstract class APDU {

    public static int DEFAULT_APDU_SIZE = 32;

    public enum APDU_Type {
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
        APDU_GENERATE_KEY_ECC
    }

    public APDU() {
        m_data = new TPSBuffer();
    }

    public APDU(APDU otherAPDU) {
        m_data = new TPSBuffer(otherAPDU.GetData());
    }

    void SetCLA(byte cla) {
        m_cla = cla;
    }

    void SetINS(byte ins) {
        m_ins = ins;
    }

    void SetP1(byte p1) {
        m_p1 = p1;
    }

    void SetP2(byte p2) {
        m_p2 = p2;
    }

    void SetData(TPSBuffer data) {
        m_data = new TPSBuffer(data);

    }

    public void SetMAC(TPSBuffer mac) {
        m_mac = mac;
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

    public TPSBuffer GetEncoding() {

        TPSBuffer data = new TPSBuffer();

        data.add(m_cla);
        data.add(m_ins);
        data.add(m_p1);
        data.add(m_p2);

        int m_mac_size = 0;

        if (m_mac != null) {
            m_mac_size = m_mac.size();
        }

        data.add((byte) (m_data.size() + m_mac_size));

        data.add(m_data);

        if (m_mac_size > 0) {
            data.add(m_mac);
        }

        return data;
    }

    public void GetDataToMAC(TPSBuffer data) {

    }

    /* PRStatus SecureMessage(PK11SymKey *encSessionKey); */

    public APDU_Type GetType() {
        return APDU_Type.APDU_UNDEFINED;
    }

    public TPSBuffer GetData() {
        return m_data;
    }

    public TPSBuffer GetMAC() {
        return m_mac;
    }

    public byte GetCLA() {
        return m_cla;

    }

    public byte GetINS() {
        return m_ins;
    }

    public byte GetP1() {
        return m_p1;
    }

    public byte GetP2() {
        return m_p2;
    }

    public void dump() {

        System.out.println("APDU: ");
        System.out.println("CLA: " + m_cla);
        System.out.println("INS: " + m_ins);
        System.out.println("P1: " + m_p1);
        System.out.println("P2: " + m_p2);

        m_data.dump();
    }

    protected byte m_cla;
    protected byte m_ins;
    protected byte m_p1;
    protected byte m_p2;

    protected TPSBuffer m_data = null;
    protected TPSBuffer m_plainText = null;
    protected TPSBuffer m_mac = null;

};
