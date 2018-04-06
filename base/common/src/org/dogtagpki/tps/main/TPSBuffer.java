// --- BEGIN COPYRIGHT BLOCK ---
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation;
// version 2.1 of the License.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor,
// Boston, MA  02110-1301  USA
//
// Copyright (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package org.dogtagpki.tps.main;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

public class TPSBuffer {

    private byte[] buf;

    // int res;

    /**
     * Creates an empty Buffer.
     */
    public TPSBuffer() {
        buf = new byte[0];
    }

    public TPSBuffer(String str) {

        if (str != null) {
            buf = Util.str2ByteArray(str);
        } else {
            buf = new byte[0];
        }
    }

    /**
     * Creates a Buffer of length 'len', with each byte initialized to 'b'.
     */
    public TPSBuffer(int len, byte b) {
        buf = new byte[len];
        Arrays.fill(buf, b);
    }

    /**
     * Creates a buffer from only one byte
     * @param b
     */
    public TPSBuffer(byte b) {
        buf = new byte[1];
        buf[0] = b;
    }

    /**
     * Creates a Buffer of length 'len', initialized to zeroes.
     */
    public TPSBuffer(int len) {
        buf = new byte[len];
        Arrays.fill(buf, (byte) 0);
        len = 0;

    }

    /**
     * Creates a Buffer of length 'len', initialized from 'buf'. 'buf' must
     * contain at least 'len' bytes.
     */
    public TPSBuffer(byte[] inBuf) {

        if (inBuf == null) {
            buf = new byte[0];
        }

        buf = new byte[inBuf.length];
        System.arraycopy(inBuf, 0, buf, 0, inBuf.length);
    }

    public TPSBuffer(TPSBuffer cpy) {

        if (cpy == null) {
            buf = new byte[0];
            return;
        }

        byte[] srcBytes = cpy.toBytesArray();

        int srcLen = srcBytes.length;

        buf = new byte[srcLen];

        System.arraycopy(srcBytes, 0, buf, 0, srcLen);

    }

    public byte at(int i) {
        if (i < 0 || i >= size()) {
            return 0x0;
        }

        return buf[i];
    }

    public void setAt(int i, byte value) {
        if (i < 0 || i >= size())
            return;

        buf[i] = value;
    }

    /**
     * Returns true if the two buffers are the same length and contain
     * the same byte at each offset.
     */
    public boolean equals(TPSBuffer cmp) {

        byte[] cmpBytes = cmp.toBytesArray();

        if (cmpBytes == null)
            return false;

        return Arrays.equals(buf, cmpBytes);

    }

    public void prepend(TPSBuffer prepend) {
        if(prepend == null)
            return;

        byte [] preBytes = prepend.toBytesArray();
        prependBytes(preBytes);
    }
    public void add(TPSBuffer addend) {

        if (addend == null)
            return;

        byte[] addBytes = addend.toBytesArray();
        addBytes(addBytes);
    }

    public void set(TPSBuffer newContents) {
        if (newContents == null)
            return;

        buf = newContents.toBytesArray();
    }

    public void set(byte [] newContents) {
        if (newContents == null)
            return;
        buf = newContents;
    }

    /**
     * Append operators.
     */

    public void add(byte b) {
        byte[] addBytes = new byte[1];
        addBytes[0] = b;

        addBytes(addBytes);
    }

    public void prependBytes(byte [] preBytes) {
        if (preBytes == null)
            return;

        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        bytes.write(preBytes, 0, preBytes.length);
        bytes.write(buf, 0, buf.length);

        buf = bytes.toByteArray();
    }

    public void addBytes(byte[] addBytes) {
        if (addBytes == null)
            return;

        ByteArrayOutputStream bytes = new ByteArrayOutputStream();

        bytes.write(buf, 0, buf.length);
        bytes.write(addBytes, 0, addBytes.length);

        buf = bytes.toByteArray();

    }

    public byte[] toBytesArray() {
        return buf;
    }

    /**
     * The length of buffer. The actual amount of space allocated may be
     * higher--see capacity().
     */
    public int size() {
        return buf.length;
    }

    /**
     * Sets all bytes in the buffer to 0.
     */
    public void zeroize() {
        Arrays.fill(buf, (byte) 0);

    }

    /**
     * Changes the length of the Buffer. If 'newLen' is shorter than the
     * current length, the Buffer is truncated. If 'newLen' is longer, the
     * new bytes are initialized to 0. If 'newLen' is the same as size(),
     * this is a no-op.
     */
    public void resize(int newLen) {
        byte[] tmp = new byte[buf.length];

        System.arraycopy(buf, 0, tmp, 0, buf.length);

        buf = new byte[newLen];
        System.arraycopy(tmp, 0, buf, 0, tmp.length);
    }

    /**
     * Returns a new Buffer that is a substring of this Buffer, starting
     * from offset 'start' and continuing for 'len' bytes. This Buffer
     * must have size() >= (start + len).
     */
    public TPSBuffer substr(int start, int theLen) {

        if (start < 0 || theLen <= 0 || ((start + theLen) > buf.length)) {
            return null;
        }

        byte[] tmp = new byte[theLen];

        System.arraycopy(buf, start, tmp, 0, theLen);

        TPSBuffer ret = new TPSBuffer(tmp);

        return ret;
    }

    /**
     * Get the SubString from start to the end
     * @param start
     */
    public TPSBuffer substr(int start) {
        return substr(start,buf.length -2);
    }

    /**
     * dump()s this Buffer to stdout.
     */
    public void dump() {
        String newLine = System.getProperty("line.separator");
        System.out.println(newLine + "Buffer Contents: " + newLine);
        for (int i = 0; i < buf.length; i++) {
            int val = buf[i] & 0xff;
            System.out.print(Util.intToHex(val) + " ");
            if (((i % 8) == 7)) {
                System.out.print(newLine);
            }
        }
        System.out.print(newLine);

    }

    public String toHexString() {
        final String HEX_DIGITS = "0123456789ABCDEF";

        StringBuffer result = new StringBuffer(buf.length * 2);

        for (int i = 0; i < buf.length; i++)
        {
            char c = (char) buf[i];

            result.append(HEX_DIGITS.charAt((c & 0xF0) >> 4));
            result.append(HEX_DIGITS.charAt(c & 0x0F));
            result.append("%");
        }

        return result.toString();
    }

    /*
     * toHexString - this version returns hex string without the'%'
     * @return the hex representation of the buffer
     */
    public String toHexStringPlain() {
        final String HEX_DIGITS = "0123456789ABCDEF";

        StringBuffer result = new StringBuffer(buf.length * 2);

        for (int i = 0; i < buf.length; i++)
        {
            char c = (char) buf[i];

            result.append(HEX_DIGITS.charAt((c & 0xF0) >> 4));
            result.append(HEX_DIGITS.charAt(c & 0x0F));
        }

        return result.toString();
    }

    public int getIntFrom1Byte(int offset) {

        if (offset < 0 || offset >= (this.size())) {
            return 0;
        }

        int result = (this.at(offset) & 0xff);

        return result;
    }

    public int getIntFrom2Bytes(int offset) {

        if (offset < 0 || offset >= (this.size() - 1)) {
            return 0;
        }

        int i1 = (this.at(offset) & 0xff) << 8;
        int i2 = this.at(offset + 1) & 0xff;

        return i1 + i2;
    }

    public void addLong4Bytes(long value) {

        this.add((byte) ((value >> 24) & 0xff));

        this.add((byte) ((value >> 16) & 0xff));
        this.add((byte) ((value >> 8) & 0xff));
        this.add((byte) (value & 0xff));
    }

    public void addInt2Bytes(int value) {
        this.add((byte) ((value >> 8) & 0xff));
        this.add((byte) (value & 0xff));
    }

    public long getLongFrom4Bytes(int offset) {

        if (offset < 0 || offset >= (this.size() - 3)) {
            return 0;
        }

        long l1 = (long) (this.at(offset + 0) & 0xff) << 24;

        long l2 = (long) (this.at(offset + 1) & 0xff) << 16;
        long l3 = (long) (this.at(offset + 2) & 0xff) << 8;
        long l4 = this.at(offset + 3) & 0xff;

        return l1 + l2 + l3 + l4;
    }

    public void reset() {
        buf = new byte[0];
    }

    public static void main(String[] args) {

        byte[] first = { 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a };
        byte[] second = { 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a };
        byte[] third = { 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a };

        TPSBuffer b1 = new TPSBuffer(first);

        TPSBuffer b2 = new TPSBuffer(second);

        System.out.println("Buffer b1");
        b1.dump();

        System.out.println("Buffer b2");
        b2.dump();

        b1.addBytes(second);

        System.out.println("Buffer b1 + byte array: ");
        b1.dump();

        b1.add(b2);

        System.out.println("Buffer b1 with b2 added to it: ");
        b1.dump();

        TPSBuffer b3 = new TPSBuffer(third);

        System.out.println("Buffer b3: ");
        b3.dump();

        TPSBuffer b4 = b3.substr(1, 4);

        System.out.println("Substr of Buffer b3 from 1 length 4: ");

        b4.dump();

        TPSBuffer b5 = new TPSBuffer(b4);

        System.out.println("Buffer b5 instantiated from Buffer b4");

        b5.dump();

        TPSBuffer b6 = new TPSBuffer("A0000000030000");
        b6.dump();

        TPSBuffer empty = new TPSBuffer();

        int emptySize = empty.size();
        System.out.println("empty buffer size: " + emptySize);

    }

}
