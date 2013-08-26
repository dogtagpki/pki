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
package com.netscape.certsrv.tps;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;

/**
 * @author Endi S. Dewata <edewata@redhat.com>
 */
public class TPSConnection {

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

        StringBuilder sb = new StringBuilder();
        int b;

        // read the first parameter
        while ((b = in.read()) >= 0) {
            char c = (char)b;
            if (c == '&') break;
            sb.append(c);
        }

        if (b < 0) throw new IOException("Unexpected end of stream");

        // parse message size
        String nvp = sb.toString();
        String[] s = nvp.split("=");
        int size = Integer.parseInt(s[1]);

        sb.append('&');

        // read the rest of message
        for (int i=0; i<size; i++) {

            b = in.read();
            if (b < 0) throw new IOException("Unexpected end of stream");

            char c = (char)b;
            sb.append(c);
        }

        // parse the entire message
        return new TPSMessage(sb.toString());
    }

    public void write(TPSMessage message) throws IOException {
        String s = message.encode();

        if (chunked) {
            // send message length + EOL
            out.print(Integer.toHexString(s.length()));
            out.print("\r\n");
        }

        // send message
        out.print(s);

        if (chunked) {
            // send EOL
            out.print("\r\n");
        }

        out.flush();
    }
}
