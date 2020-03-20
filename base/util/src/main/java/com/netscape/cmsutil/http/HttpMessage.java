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
package com.netscape.cmsutil.http;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.StringWriter;
import java.util.Enumeration;
import java.util.Hashtable;

/**
 * Basic HTTP Message, excluding message body.
 * Not optimized for performance.
 * Set fields or parse from input.
 */
public class HttpMessage {
    protected String mLine = null; // request or response line.
    protected Hashtable<String, String> mHeaders = null;
    protected String mContent = null; // arbitrary content chars assumed.

    /**
     * Instantiate a HttpResponse for write to http client.
     */
    public HttpMessage() {
        mHeaders = new Hashtable<String, String>();
    }

    /**
     * Set a header field. <br>
     * Content-length is automatically set on write.<br>
     * If value spans multiple lines must be in proper http format for
     * multiple lines.
     */
    public void setHeader(String name, String value) {
        if (mHeaders == null)
            mHeaders = new Hashtable<String, String>();
        mHeaders.put(name.toLowerCase(), value);
    }

    /**
     * get a header
     */
    public String getHeader(String name) {
        return mHeaders.get(name.toLowerCase());
    }

    /**
     * write http headers
     * does not support values of more than one line
     */
    public void writeHeaders(OutputStreamWriter writer)
            throws IOException {
        if (mHeaders != null) {
            Enumeration<String> keys = mHeaders.keys();
            String header, value;

            while (keys.hasMoreElements()) {
                header = keys.nextElement();
                value = mHeaders.get(header);
                writer.write(header + ":" + value + Http.CRLF);
            }
        }
        writer.write(Http.CRLF); // end with CRLF line.
    }

    /**
     * read http headers.
     * does not support values of more than one line or multivalue headers.
     */
    public void readHeaders(BufferedReader reader)
            throws IOException {
        mHeaders = new Hashtable<String, String>();

        int colon;
        String line, key, value;

        while (true) {
            line = reader.readLine();
            if (line == null || line.equals(""))
                break;
            colon = line.indexOf(':');
            if (colon == -1) {
                mHeaders = null;
                throw new HttpProtocolException("Bad Http header format");
            }
            key = line.substring(0, colon);
            value = line.substring(colon + 1);
            mHeaders.put(key.toLowerCase(), value.trim());
        }
    }

    public void write(OutputStreamWriter writer)
            throws IOException {
        writer.write(mLine + Http.CRLF);
        writeHeaders(writer);
        writer.flush();
        if (mContent != null) {
            writer.write(mContent);
        }
        writer.flush();
    }

    public void parse(BufferedReader reader)
            throws IOException {
        String line = reader.readLine();

        if (line == null) {
            throw new HttpEofException("End of stream reached");
        }
        if (line.equals("")) {
            throw new HttpProtocolException("Bad Http req/resp line " + line);
        }
        mLine = line;
        readHeaders(reader);

        // won't work if content length is not set.
        String lenstr = mHeaders.get("content-length");

        if (lenstr != null) {
            int len = Integer.parseInt(lenstr);
            char[] cbuf = new char[len];
            int done = reader.read(cbuf, 0, cbuf.length);
            int total = done;

            while (done >= 0 && total < len) {
                done = reader.read(cbuf, total, len - total);
                total += done;
            }

            mContent = new String(cbuf);
        } else {
            char[] cbuf = new char[8192];
            StringWriter sw = new StringWriter();
            int charsRead;
            while ((charsRead = reader.read(cbuf)) != -1) {
                sw.write(cbuf, 0, charsRead);
            }
            if (sw.getBuffer().length()>0) mContent = sw.toString();
        }
    }

    public void reset() {
        mLine = null;
        mHeaders = null;
        mContent = null;
    }

    public void setContent(String content) {
        mContent = content;
    }

    public String getContent() {
        return mContent;
    }

}
