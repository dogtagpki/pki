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
import java.util.Hashtable;
import java.util.Vector;

import javax.servlet.ServletException;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.common.NameValuePairs;


/**
 * A log event listener which sends all log events to the system console/tty
 *
 * @version $Revision$, $Date$
 */
public class ConsoleLog implements ILogEventListener {

    /**
     * Log the given event.  Usually called from a log manager.
     *
     * @param	ev	log event
     */
    public void log(ILogEvent ev) {
        System.err.println(Thread.currentThread().getName() + ": " + ev);
    }

    /**
     * Flush the system output stream. 
     *
     */
    public void flush() {
        System.err.flush();
    }

	/**
	 * All operations need to be cleaned up for shutdown are done here
	 */
    public void shutdown() {
    }

	/**
	 * get the configuration store that is associated with this
	 * log listener
	 * @return the configuration store that is associated with this
	 * log listener
	 */
    public IConfigStore getConfigStore() {
        return null;
    }

    public void init(ISubsystem owner, IConfigStore config) 
        throws EBaseException {
    }

    public void startup() throws EBaseException {
    }

    /**
     * Retrieve last "maxLine" number of system log with log lever >"level"
     * and from  source "source". If the parameter is omitted. All entries
     * are sent back.
	 * @param req a Hashtable containing the required information such as
	 * log entry, log level, log source, and log name
	 * @return the content of the log that match the criteria in req
	 * @exception servletException
	 * @exception IOException
	 * @exception EBaseException
     */
    public synchronized NameValuePairs retrieveLogContent(Hashtable req) throws ServletException,
            IOException, EBaseException {
        return null;
    }

    /**
     * Retrieve log file list.
	 * <br> unimplemented
     */
    public synchronized NameValuePairs retrieveLogList(Hashtable req) throws ServletException,
            IOException, EBaseException {
        return null;
    }

    public String getImplName() {
        return "ConsoleLog";
    }

    public String getDescription() {
        return "ConsoleLog";
    }

    public Vector getDefaultParams() {
        Vector v = new Vector();

        return v;
    }

    public Vector getInstanceParams() {
        Vector v = new Vector();

        return v;
    }
}
