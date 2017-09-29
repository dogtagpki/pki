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
package com.netscape.certsrv.logging;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The log event object that carries message detail of a log event
 * that goes into the Signed Audit Event log. This log has the
 * property of being digitally signed for security considerations.
 *
 *
 * @version $Revision$, $Date$
 * @see java.text.MessageFormat
 * @see com.netscape.certsrv.logging.LogResources
 */
public class SignedAuditEvent extends LogEvent {

    private static final long serialVersionUID = 4287822756516673931L;

    protected Map<String, Object> attributes = new LinkedHashMap<>();

    public SignedAuditEvent() {
    }

    /**
     * Constructs a SignedAuditEvent message event.
     * <P>
     *
     * @param msgFormat The message string.
     */
    public SignedAuditEvent(String msgFormat) {
        super(msgFormat);
    }

    /**
     * Constructs a message with a parameter. For example,
     *
     * <PRE>
     * new SignedAuditEvent(&quot;failed to load {0}&quot;, fileName);
     * </PRE>
     * <P>
     *
     * @param msgFormat Details in message string format.
     * @param param Message string parameter.
     */
    public SignedAuditEvent(String msgFormat, String param) {
        super(msgFormat, param);
    }

    /**
     * Constructs a message from an exception. It can be used to carry
     * a signed audit exception that may contain information about
     * the context. For example,
     *
     * <PRE>
     * 		try {
     *  		...
     * 		} catch (IOExeption e) {
     * 		 	logHandler.log(new SignedAuditEvent("Encountered Signed Audit Error {0}", e);
     *      }
     * </PRE>
     * <P>
     *
     * @param msgFormat Exception details in message string format.
     * @param exception System exception.
     */
    public SignedAuditEvent(String msgFormat, Exception exception) {
        super(msgFormat, exception);
    }

    /**
     * Constructs a message from a base exception. This will use the msgFormat
     * from the exception itself.
     *
     * <PRE>
     * 		try {
     *  		...
     * 		} catch (Exception e) {
     * 		 	logHandler.log(new SignedAuditEvent(e));
     *      }
     * </PRE>
     * <P>
     *
     * @param e CMS exception.
     */
    public SignedAuditEvent(Exception e) {
        super(e);
    }

    /**
     * Constructs a message event with a list of parameters
     * that will be substituted into the message format.
     * <P>
     *
     * @param msgFormat Message string format.
     * @param params List of message format parameters.
     */
    public SignedAuditEvent(String msgFormat, Object params[]) {
        super(msgFormat, params);
    }

    public void setAttribute(String name, Object value) {
        attributes.put(name, value);
    }

    public Object getAttribute(String name) {
        return attributes.get(name);
    }

    public Map<String, Object> getAttributes() {
        return attributes;
    }

    public String getAttributeList() {

        StringBuilder sb = new StringBuilder();

        for (String name : attributes.keySet()) {
            Object value = attributes.get(name);

            sb.append("[");
            sb.append(name);
            sb.append("=");
            sb.append(value == null ? ILogger.SIGNED_AUDIT_EMPTY_VALUE : value);
            sb.append("]");
        }

        return sb.toString();
    }

    public Object[] getParameters() {

        if (mParams != null) {
            return mParams;
        }

        // convert attribute list into a single parameter
        mParams = new Object[] {
                getAttributeList()
        };

        return mParams;
    }
}
