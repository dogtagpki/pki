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
package com.netscape.cmscore.connector;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OptionalDataException;

import org.mozilla.jss.netscape.security.util.Utils;

/**
 * This represents a rquest encoder that serializes and
 * deserializes a request to a Remote Authority so that it can be sent through
 * the connector.
 */
public class HttpRequestEncoder {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(HttpRequestEncoder.class);

    /**
     * Encodes a request object.
     *
     * @param r Object to serve as the source of the message.
     * @return String containing encoded message.
     * @exception IOException Failure of the encoding operation due to IO error.
     */
    public String encode(Object r)
            throws IOException {
        String s = null;
        byte[] serial;
        ByteArrayOutputStream ba = new ByteArrayOutputStream();
        ObjectOutputStream os = new ObjectOutputStream(ba);

        os.writeObject(r);
        serial = ba.toByteArray();
        s = Utils.base64encode(serial, true);
        return s;
    }

    /**
     * Decodes a String into an object.
     *
     * @return Object which is the result of the decoded message.
     * @exception IOException Failure of the decoding operation due to IO error.
     */
    public Object decode(String s)
            throws IOException {
        Object result = null;
        byte[] serial = null;

        try {

            serial = Utils.base64decode(s);
            ByteArrayInputStream ba = new ByteArrayInputStream(serial);
            ObjectInputStream is = new ObjectInputStream(ba);

            result = is.readObject();

        } catch (ClassNotFoundException e) {
            // XXX hack: change this
            logger.error("HttpRequestEncoder: " + e.getMessage(), e);
            throw new IOException("Class Not Found " + e.getMessage());

        } catch (OptionalDataException e) {
            if (e.eof == true) {
                logger.trace("done reading input stream " + result);
            } else {
                logger.trace(e.length + " more bytes of primitive data");
            }
        }
        return result;
    }
}
