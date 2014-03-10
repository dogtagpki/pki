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
// (C) 2014 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package org.dogtagpki.server.tps.cms;

import java.io.ByteArrayInputStream;
import java.util.Hashtable;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmsutil.xml.XMLObject;

/**
 * RemoteRequestHandler is the base class for the remote authorities
 *
 * @author cfu
 */
public abstract class RemoteRequestHandler
{
    private static final String RESPONSE_SEPARATOR = "\\&";
    private static final String NAME_VALUE_EQUAL = "=";

    protected String connid;

    /**
     * parseResponse parses remote responses that take the form of '&'-separated
     * name-value pairs
     *
     * @param content The exact string content in the HTTP response
     * @return name-value pairs in a Hashtable
     */
    protected Hashtable<String, Object> parseResponse(String content)
            throws EBaseException {
        CMS.debug("RemoteRequestHandler: parseResponse(): begins:");
        if (content == null) {
            throw new EBaseException("RemoteRequestHandler: parserResponse(): no response content.");
        }
        Hashtable<String, Object> vars = new Hashtable<String, Object>();
        String[] elements = content.split(RESPONSE_SEPARATOR);
        CMS.debug("RemoteRequestHandler: parseResponse(): # of elements:" +
            elements.length);
        for (String nvs : elements) {
            String[] nv = nvs.split(NAME_VALUE_EQUAL);
            if (nv.length == 2) {
                vars.put(nv[0], nv[1]);
            } else {
                // continue to parse through
                CMS.debug("RemoteRequestHandler: parseResponse(): content contains element not conforming to <name>=<value>.");
            }
        }
        return vars;
    }

    /**
     * Get the XML parser for XML in text
     *
     * @param text XML in text
     * @return XMLObject the parser
     */
    protected XMLObject getXMLparser(String text) {
        if (text == null) {
            return null;
        } else {
            CMS.debug("RemoteRequestHandler: getXMLparser(): parsing: " + text);
        }
        try {
            ByteArrayInputStream bis =
                    new ByteArrayInputStream(text.getBytes());
            return new XMLObject(bis);
        } catch (Exception e) {
            CMS.debug("RemoteRequestHandler: getXMLparser(): failed: " + e);
            throw new RuntimeException(e);
        }
    }

}
