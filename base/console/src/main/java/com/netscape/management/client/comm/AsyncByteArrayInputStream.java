/** BEGIN COPYRIGHT BLOCK
 * Copyright (C) 2001 Sun Microsystems, Inc.  Used by permission.
 * Copyright (C) 2005 Red Hat, Inc.
 * All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation version
 * 2.1 of the License.
 *                                                                                 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *                                                                                 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * END COPYRIGHT BLOCK **/
package com.netscape.management.client.comm;

import java.io.InputStream;
import java.io.IOException;
import com.netscape.management.client.util.IProgressListener;

/**
 * The AsyncByteArrayInputStream is an implementation of a mutable
 * ByteArrayInputStream; while a consumer is reading bytes off the
 * beginning of the buffer, a producer can be writing bytes to the
 * end of the buffer. The notion of EOF is controlled by a producer,
 * so that a consumer may block in reading bytes until the producer
 * writes bytes, or indicates an EOF condition. This class is used
 * as the internal buffer for communications traffic.
 *
 * @author  <a href=mailto:dt@netscape.com>David Tompkins</a>
 * @version 0.3, 10/2/97
 */
public class AsyncByteArrayInputStream extends InputStream {
    protected byte buf[]; // data buffer
    protected int cnt; // The index one greater than the last valid character in the buffer
    protected int pos = 0; // the index of the next character to be read from the buffer
    protected int mark = 0; // reset mark position (default = 0)
    protected boolean eof = true; // has the buffer been fully populated?
    protected IProgressListener progressListener = null; // listener for progess updates

    /**
     * Creates a new async byte array input stream, with an initial buffer
     * capacity of 32 bytes. The buffer will increase its size accordingly
     * during write() calls, until the eof condition is set.
     *
     */
    public AsyncByteArrayInputStream() {
        this(32, null);
    }

    /**
      * Creates a new async byte array input stream, with an initial buffer
      * capacity of size bytes. The buffer will increase its size accordingly
      * during write() calls, until the eof condition is set.
      *
      * @param size the initial size
      */
    public AsyncByteArrayInputStream(int size,
            IProgressListener progressListener) {
        this.buf = new byte[size];
        this.progressListener = progressListener;
        this.cnt = 0;
        this.eof = false;
    }

    /**
      * Creates a new async byte array input stream that reads data from the
      * specified byte array. The byte array is not copied, and eof is assumed.
      *
      * @param buf the input buffer.
      */
    public AsyncByteArrayInputStream(byte buf[]) {
        this.buf = buf;
        this.cnt = buf.length;
    }

    /**
      * Creates a new async byte array input stream that reads data from the
      * specified byte array. Up to <code>length</code> characters are to
      * be read from the byte array, starting at the indicated offset.
      * <p>
      * The byte array is not copied, and eof is assumed.
      *
      * @param buf    the input buffer.
      * @param offset the offset in the buffer of the first byte to read.
      * @param length the maximum number of bytes to read from the buffer.
      */
    public AsyncByteArrayInputStream(byte buf[], int offset, int length) {
        this.buf = buf;
        this.pos = offset;
        this.cnt = Math.min(offset + length, buf.length);
    }

    /**
      * Reads the next byte of data from this input stream. The value
      * byte is returned as an <code>int</code> in the range
      * <code>0</code> to <code>255</code>. If no byte is available
      * because the end of the stream has been reached, the value
      * <code>-1</code> is returned.
      * <p>
      * If the buffer has not yet been fully populated, this method may block
      * until more data arrives, or eof is detected.
      *
      * @return  the next byte of data, or <code>-1</code> if the end of the
      *          stream has been reached.
      */
    public synchronized int read() {
        for (;;) {
            if (pos < cnt)
                return (buf[pos++] & 0xff);

            if (eof)
                return (-1);

            try {
                wait();
            } catch (InterruptedException e) { }
        }
    }

    /**
      * Reads up to <code>len</code> bytes of data into an array of bytes
      * from this input stream. If the buffer has not yet been fully populated,
      * this method may block until more data arrives, or eof is detected.
      *
      * @param   b     the buffer into which the data is read.
      * @param   off   the start offset of the data.
      * @param   len   the maximum number of bytes read.
      * @return  the total number of bytes read into the buffer, or
      *          <code>-1</code> if there is no more data because the end of
      *          the stream has been reached.
      */
    public synchronized int read(byte b[], int off, int len) {
        for (;;) {
            if (pos >= cnt) {
                if (eof)
                    return -1;
            } else {
                if (pos + len > cnt)
                    len = cnt - pos;

                if (len > 0) {
                    System.arraycopy(buf, pos, b, off, len);
                    pos += len;
                    return len;
                }
            }

            try {
                wait();
            } catch (InterruptedException e) { }
        }
    }

    /**
      * Skips <code>n</code> bytes of input from this input stream. Fewer
      * bytes might be skipped if the end of the current buffer contents
      * is reached.
      *
      * @param   n   the number of bytes to be skipped.
      * @returns  the actual number of bytes skipped.
      */
    public synchronized long skip(long n) {
        if (pos + n > cnt)
            n = cnt - pos;

        if (n < 0)
            return 0;

        pos += n;
        return n;
    }

    /**
      * Returns the number of bytes that can be read from this input
      * stream without blocking.
      *
      * @returns  the number of bytes that can be read from the input stream
      *          without blocking.
      */
    public synchronized int available() {
        return cnt - pos;
    }
    public synchronized int size() {
        return cnt;
    }
    public synchronized void reset() {
        pos = mark;
    }
    public synchronized void mark(int markpos) {
        mark = pos;
    }
    public boolean markSupported() {
        return true;
    }

    /**
      * Will return when data is available, or eof has been set.
      *
      * @returns the number of bytes available, or -1 on EOF.
      */
    public synchronized int waitForData() {
        for (;;) {
            if (eof)
                return -1;

            int n;

            if ((n = available()) > 0)
                return n;

            try {
                wait();
            } catch (InterruptedException e) { }
        }
    }

    protected synchronized void checkCapacity(int size) {
        int newcount = cnt + size;

        if (newcount > buf.length) {
            byte newbuf[] = new byte[Math.max(buf.length << 1, newcount)];
            System.arraycopy(buf, 0, newbuf, 0, cnt);
            buf = newbuf;
        }
    }

    /**
      * Writes the specified byte to the end of the buffer, and notifies any
      * objects blocking on read().
      *
      * @param b the byte to be written.
      * @returns true on success, false if eof already set.
      */
    public synchronized boolean write(int b) {
        if (eof)
            return false;

        checkCapacity(1);

        buf[cnt++] = (byte) b;

        notifyAll();
        return true;
    }

    /**
      * Writes <code>len</code> bytes from the specified byte array
      * starting at offset <code>off</code> to the end of the buffer, and notifies any
      * objects blocking on read().
      *
      * @param b   the data.
      * @param off the start offset in the data.
      * @param len the number of bytes to write.
      * @returns true on success, false if eof already set.
      */
    public synchronized boolean write(byte b[], int off, int len) {
        if (eof)
            return false;

        checkCapacity(len);

        System.arraycopy(b, off, buf, cnt, len);
        cnt += len;

        notifyAll();
        return true;
    }

    /**
      * Writes <code>len</code> bytes from the specified InputStream
      * to the end of the buffer, and notifies any objects blocking on read().
      *
      * @param is the InputStream.
      * @param len the number of bytes to write.
      * @returns true on success, false if eof already set.
      */
    public synchronized boolean write(InputStream is, int len)
        throws IOException {
        if (eof)
            return false;

        checkCapacity(len);

        int len0 = len;

        while (len > 0) {
            int readlen = is.read(buf, cnt, len);
            len -= readlen;
            cnt += readlen;
            if (progressListener != null) {
                progressListener.progressUpdate(null, len0, cnt);
            }
        }

        notifyAll();
        return true;
    }

    /**
      * Sets the EOF condition on this async byte array input stream, which precludes
      * further write()'s to the buffer.
      *
      */
    public synchronized void setEOF() {
        eof = true;
        notifyAll();
    }

    /**
      * Returns the EOF condition of this async byte array stream.
      */
    public synchronized boolean getEOF() {
        return eof;
    }

    /**
      * Returns a String representation of the buffer contents.
      */
    public synchronized String toString() {
        return new String(buf, 0, cnt);
    }

    public byte[] getBuf() {
        return buf;
    }
}
