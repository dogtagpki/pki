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

import java.io.Serializable;
import java.util.Locale;

/**
 * An interface which all loggable events must implement. CMS comes with a
 * limited set of ILogEvent types to implement: audit, system, and signed audit.
 * This is the base class of all the subsequent implemented types. A log event
 * represents a certain kind of log message designed for a specific purpose. For
 * instance, an audit type event represents messages having to do with auditable
 * CMS actions. The resulting message will ultimately appear into a specific log
 * file.
 * 
 * @version $Revision$, $Date$
 */
public interface ILogEvent extends Serializable {

    /**
     * Retrieves event time stamp.
     * 
     * @return Long integer of the time the event was created.
     */
    public long getTimeStamp();

    /**
     * Retrieves log source. This is an id of the subsystem responsible for
     * creating the log event.
     * 
     * @return Integer source id.
     */
    public int getSource();

    /**
     * Retrieves log level. The log level of an event represents its relative
     * importance or severity within CMS.
     * 
     * @return Integer log level value.
     */
    public int getLevel();

    /**
     * Retrieves NT specific log event type.
     * 
     * @return Integer NTEventType value.
     */
    public int getNTEventType();

    /**
     * Retrieves multiline attribute. Does this message consiste of more than
     * one line.
     * 
     * @return Boolean of multiline status.
     */
    public boolean getMultiline();

    /**
     * Retrieves log event type. Each type of event has an associated String
     * type value.
     * 
     * @return String containing the type of event.
     */
    public String getEventType();

    /**
     * Sets log event type. Each type of event has an associated String type
     * value.
     * 
     * @param eventType String containing the type of event.
     */
    public void setEventType(String eventType);

    /**
     * Returns localized message string. This method should only be called if a
     * localized string is necessary.
     * <P>
     * 
     * @return Details message.
     */
    public String toContent();

    /**
     * Returns the string based on the given locale.
     * <P>
     * 
     * @param locale locale
     * @return Details message.
     */
    public String toContent(Locale locale);
}
