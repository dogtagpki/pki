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
package com.netscape.certsrv.apps;

import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Locale;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;

/**
 * This interface represents the CMS core framework. The
 * framework contains a set of services that provide
 * the foundation of a security application.
 * <p>
 * The engine implementation is loaded by CMS at startup. It is responsible for starting up all the related subsystems.
 * <p>
 *
 * @version $Revision$, $Date$
 */
public interface ICMSEngine extends ISubsystem {

    /**
     * Gets this ID .
     *
     * @return CMS engine identifier
     */
    public String getId();

    /**
     * Sets the identifier of this subsystem. Should never be called.
     * Returns error.
     *
     * @param id CMS engine identifier
     */
    public void setId(String id) throws EBaseException;

    public void reinit(String id) throws EBaseException;

    public int getCSState();

    public void setCSState(int mode);

    /**
     * Returns a server wide system time. Plugins should call
     * this method to retrieve system time.
     *
     * @return current time
     */
    public Date getCurrentDate();

    /**
     * Returns the names of all the registered subsystems.
     *
     * @return a list of string-based subsystem names
     */
    public Enumeration<String> getSubsystemNames();

    /**
     * Returns all the registered subsystems.
     *
     * @return a list of ISubsystem-based subsystems
     */
    public Enumeration<ISubsystem> getSubsystems();

    /**
     * Set whether the given subsystem is enabled.
     *
     * @param id The subsystem ID.
     * @param enabled Whether the subsystem is enabled
     */
    public void setSubsystemEnabled(String id, boolean enabled)
        throws EBaseException;

    /**
     * Retrieves the registered subsytem with the given name.
     *
     * @param name subsystem name
     * @return subsystem of the given name
     */
    public ISubsystem getSubsystem(String name);

    /**
     * Puts data of an byte array into the debug file.
     *
     * @param data byte array to be recorded in the debug file
     */
    public void debug(byte data[]);

    /**
     * Puts a message into the debug file.
     *
     * @param msg debugging message
     */
    public void debug(String msg);

    /**
     * Puts a message into the debug file.
     *
     * @param level 0-10
     * @param msg debugging message
     */
    public void debug(int level, String msg);

    /**
     * Puts an exception into the debug file.
     *
     * @param e exception
     */
    public void debug(Throwable e);

    /**
     * Checks if the debug mode is on or not.
     *
     * @return true if debug mode is on
     */
    public boolean debugOn();

    /**
     * Puts the current stack trace in the debug file.
     */
    public void debugStackTrace();

    /**
     * Retrieves the localized user message from UserMessages.properties.
     *
     * @param locale end-user locale
     * @param msgID message id defined in UserMessages.properties
     * @return localized user message
     */
    public String getUserMessage(Locale locale, String msgID);

    /**
     * Retrieves the localized user message from UserMessages.properties.
     *
     * @param locale end-user locale
     * @param msgID message id defined in UserMessages.properties
     * @param p an array of parameters
     * @return localized user message
     */
    public String getUserMessage(Locale locale, String msgID, String p[]);

    /**
     * Retrieves the localized user message from UserMessages.properties.
     *
     * @param locale end-user locale
     * @param msgID message id defined in UserMessages.properties
     * @param p1 1st parameter
     * @return localized user message
     */
    public String getUserMessage(Locale locale, String msgID, String p1);

    /**
     * Retrieves the localized user message from UserMessages.properties.
     *
     * @param locale end-user locale
     * @param msgID message id defined in UserMessages.properties
     * @param p1 1st parameter
     * @param p2 2nd parameter
     * @return localized user message
     */
    public String getUserMessage(Locale locale, String msgID, String p1, String p2);

    /**
     * Retrieves the localized user message from UserMessages.properties.
     *
     * @param locale end-user locale
     * @param msgID message id defined in UserMessages.properties
     * @param p1 1st parameter
     * @param p2 2nd parameter
     * @param p3 3rd parameter
     * @return localized user message
     */
    public String getUserMessage(Locale locale, String msgID, String p1, String p2, String p3);

    /**
     * Retrieves log message from LogMessages.properties or audit-evenst.properties.
     *
     * @param msgID message ID defined in LogMessages.properties or audit-evenst.properties
     * @param p an array of parameters
     * @return localized log message
     */
    public String getLogMessage(String msgID, Object p[]);

    /**
     * Blocks all new incoming requests.
     */
    public void disableRequests();

    /**
     * Terminates all requests that are currently in process.
     */
    public void terminateRequests();

    /**
     * Checks to ensure that all new incoming requests have been blocked.
     * This method is used for reentrancy protection.
     * <P>
     *
     * @return true or false
     */
    public boolean areRequestsDisabled();

    /**
     * Create configuration file.
     *
     * @param path configuration path
     * @return configuration store
     * @exception EBaseException failed to create file
     */
    public IConfigStore createFileConfigStore(String path) throws EBaseException;

    /**
     * Creates argument block.
     */
    public IArgBlock createArgBlock();

    /**
     * Creates argument block.
     */
    public IArgBlock createArgBlock(String realm, Hashtable<String, String> httpReq);

    /**
     * Creates argument block.
     */
    public IArgBlock createArgBlock(Hashtable<String, String> httpReq);

    public void sleepOneMinute(); // for debug only

    public boolean isExcludedLdapAttrsEnabled();

    public boolean isExcludedLdapAttr(String key);
}
