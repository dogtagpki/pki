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


import java.io.IOException;
import java.util.EventListener;
import java.util.Hashtable;
import java.util.Vector;

import javax.servlet.ServletException;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.common.NameValuePairs;



/**
 * An interface represents a log event listener.
 * A ILogEventListener is registered to  a specific
 * ILogQueue to be notified of created ILogEvents.
 * the log queue will notify all its registered listeners
 * of the logged event. The listener will then proceed to
 * process the event accordingly which will result in a log
 * message existing in some file.
 *
 * @version $Revision$, $Date$
 */
public interface ILogEventListener extends EventListener {

    /**
     *  The event notification method: Logs event.
     *
     * @param event The log event to be processed.
     */
    public void log(ILogEvent event) throws ELogException;

    /**
     *  Flushes the log buffers (if any). Will result in the messages
     *  being actually written to their destination.
     */
    public void flush();

    /**
     *  Closes the log file and destroys any associated threads.
     */
    public void shutdown();

    /**
     * Get the configuration store for the log event listener.
     * @return The configuration store of this log event listener.
     */
    public IConfigStore getConfigStore();

    /**
     * Initialize this log listener
	 * @param owner The subsystem.
	 * @param config Configuration store for this log listener.
	 * @exception initialization error.
     */
    public void init(ISubsystem owner, IConfigStore config) 
        throws EBaseException;

    /**
     * Startup the instance.
     */
    public void startup()
        throws EBaseException;

    /**
     * Retrieve last "maxLine" number of system logs with log level >"level"
     * and from  source "source". If the parameter is omitted. All entries
     * are sent back.
         * @param req a Hashtable containing the required information such as
         * log entry, log level, log source, and log name.
         * @return NameValue pair list of log messages.
         * @exception ServletException For Servelet errros.
         * @exception IOException For input/output problems.
         * @exception EBaseException For other problems.
     */
    public NameValuePairs retrieveLogContent(Hashtable req) throws ServletException,
            IOException, EBaseException;

    /**
    * Retrieve list of log files.
    *
    */
    public NameValuePairs retrieveLogList(Hashtable req) throws ServletException,
            IOException, EBaseException;

    /**
     * Returns implementation name.
     * @return String name of event listener implementation.
     */
    public String getImplName();

    /**
     * Returns the description of this log event listener.
     * @return String with listener description.
     */
    public String getDescription();

    /**
    * Return list of default config parameters for this log event listener.
    * @return Vector of default parameters.
    */
    public Vector getDefaultParams();

    /**
    * Return list of instance config parameters for this log event listener.
    * @return Vector of instance parameters.
    */
    public Vector getInstanceParams();
}
