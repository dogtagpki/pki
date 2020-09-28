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
package org.dogtagpki.tps;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;

import org.dogtagpki.tps.msg.TPSMessage;

/**
 * @author Endi S. Dewata <edewata@redhat.com>
 */
public class TPSConnection {

    public static final int MAX_MESSAGE_SIZE_DEFAULT = 9999;
    private static int maxMessageSize = MAX_MESSAGE_SIZE_DEFAULT;

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(TPSConnection.class);

    public InputStream in;
    public PrintStream out;
    public boolean chunked;

    public TPSConnection(InputStream in, OutputStream out) {
        this(in, out, false);
    }

    public TPSConnection(InputStream in, OutputStream out, boolean chunked) {
        this.in = in;
        this.out = new PrintStream(out);
        this.chunked = chunked;
    }

    public TPSMessage read() throws IOException {
        logger.debug("TPSConnection read()");

        StringBuilder sb = new StringBuilder();
        int b;

        // Determine # of digits in maxMessageSize so we can limit the number of
        // read()s to the number of digits.
        int maxMessageSizeNumDigits = 1;
        for(int i = maxMessageSize; i != 0; i /= 10)
            maxMessageSizeNumDigits++;

        // Check first two bytes from InputStream (s=).
        // The first char can be anything.
        if((b = in.read()) < 0)
            throw new IOException("Unexpected end of stream");
        else
            sb.append((char)b);

        // The second char must be '='.
        if((b = in.read()) != (int)'=')
            throw new IOException("Unexpected end of stream");
        else
            sb.append((char)b);

        // read the first parameter (not including the "s=")
        while ((b = in.read()) >= 0 && maxMessageSizeNumDigits-- > 0) {
            char c = (char) b;
            if (c == '&')
                break;
            sb.append(c);
        }

        if (b < 0)
            throw new IOException("Unexpected end of stream");
        if (b != (int)'&')
            throw new IOException("Received message size is too large.");

        // parse message size
        String nvp = sb.toString();
        String[] s = nvp.split("=");
        int size = Integer.parseInt(s[1]);

        // Validate message size
        if(size > maxMessageSize)
            throw new IOException("Received message size is too large.");

        sb.append('&');

        // read the rest of message
        for (int i = 0; i < size; i++) {

            b = in.read();
            if (b < 0)
                throw new IOException("Unexpected end of stream");

            char c = (char) b;
            sb.append(c);
        }

        if (size <= 38) // for pdu_data size is 2 and only contains status
            logger.debug("TPSConnection.read: Reading:  " + sb);
        else
            logger.debug("TPSConnection.read: Reading...");

        // parse the entire message
        return TPSMessage.createMessage(sb.toString());
    }

    public void write(TPSMessage message) throws IOException {
        String s = message.encode();

        // don't print the pdu_data
        int idx =  s.lastIndexOf("pdu_data=");

        int debug = 0;
        String toDebug = null;
        if (idx == -1 || debug == 1)
            logger.debug("TPSConnection.write: Writing: " + s);
        else {
            toDebug = s.substring(0, idx-1);
            logger.debug("TPSConnection.write: Writing: " + toDebug + "pdu_data=<do not print>");
        }
        // send message
        out.print(s);

        // We don't have to send any specific chunk format here
        // The output stream detects chunked encoding and sends
        // the correct output to the other end.


        out.flush();
    }

    /**
     * Getter for static variable maxMessageSize.
     * @return maxMessageSize
     */
    public static int getMaxMessageSize() {
        return maxMessageSize;
    }

    /**
     * Setter for static variable maxMessageSize. This variable places a limit on the value
     * (and thus, length) of the first parameter of an incoming stream of data. For example,
     * incoming data conforms to the following format: "s=(message length here)&".
     * TPSConnection will read one character (typically 's', but can be any char), and will
     * expect the second character to be an '='. The following characters until the '&' are
     * interpreted as the messageSize. This number cannot be larger than maxMessageSize.
     * @param maxSize
     */
    public static void setMaxMessageSize(int maxSize) {
        if(maxSize > 0)
            maxMessageSize = maxSize;
        else
            logger.debug("TPSConnection: Cannot set maxMessageSize to out-of-range value: " + maxSize);
    }
}
