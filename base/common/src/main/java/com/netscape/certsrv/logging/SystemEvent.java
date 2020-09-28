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

/**
 * The log event object that carries a log message.
 * This class represents System events which are CMS events
 * which need to be logged to a log file.
 *
 * @version $Revision$, $Date$
 * @see java.text.MessageFormat
 * @see com.netscape.certsrv.logging.LogResources
 */
public class SystemEvent extends LogEvent {

    private static final long serialVersionUID = 7160410535724580752L;

    public SystemEvent() {
    }

    /**
     * Constructs a SystemEvent message event.
     * <P>
     *
     * @param msgFormat The message string.
     */
    public SystemEvent(String msgFormat) {
        super(msgFormat);
    }

    /**
     * Constructs a SystemEvent message with a parameter. For example,
     *
     * <PRE>
     * new SystemEvent(&quot;failed to load {0}&quot;, fileName);
     * </PRE>
     * <P>
     *
     * @param msgFormat Details in message string format.
     * @param param Message string parameter.
     */
    public SystemEvent(String msgFormat, String param) {
        super(msgFormat, param);
    }

    /**
     * Constructs a SystemEvent message from an exception. It can be used to carry
     * a system exception that may contain information about
     * the context. For example,
     *
     * <PRE>
     * 		try {
     *  		...
     * 		} catch (IOExeption e) {
     * 		 	logHandler.log(new SystemEvent("Encountered System Error {0}", e);
     *      }
     * </PRE>
     * <P>
     *
     * @param msgFormat Exception details in message string format.
     * @param exception System exception.
     */
    public SystemEvent(String msgFormat, Exception exception) {
        super(msgFormat, exception);
    }

    /**
     * Constructs a SystemEvent message from a base exception. This will use the msgFormat
     * from the exception itself.
     *
     * <PRE>
     * 		try {
     *  		...
     * 		} catch (Exception e) {
     * 		 	logHandler.log(new SystemEvent(e));
     *      }
     * </PRE>
     * <P>
     *
     * @param e CMS exception.
     */
    public SystemEvent(Exception e) {
        super(e);
    }

    /**
     * Constructs a SystemEvent message event with a list of parameters
     * that will be substituted into the message format.
     * <P>
     *
     * @param msgFormat Message string format.
     * @param params List of message format parameters.
     */
    public SystemEvent(String msgFormat, Object params[]) {
        super(msgFormat, params);
    }
}
