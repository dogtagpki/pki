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


import java.io.*;
import java.util.*;
import java.text.MessageFormat;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.logging.*;


/**
 * An interface that represents a logging component.  The logging
 * component is a framework that handles different types of log types,
 * each represented by an ILogEventListener, and each implements a log 
 * plugin.  CMS  comes
 * with three standard log types: "signedAudit", "system", and
 * "transaction".  Each log plugin can be instantiated into log
 * instances.  Each log instance can be individually configured and is 
 * associated with its own configuration entries in the configuration file.
 * <P>
 * 
 * @version $Revision$, $Date$
 */
public interface ILogSubsystem extends ISubsystem {

    /**
     * The ID of this component
     */
    public static final String ID = "log";

    /**
     * Retrieve plugin name (implementation name) of the log event
     * listener.  If no plug name found, an empty string is returned
     * @param log the log event listener
     * @return the log event listener's plugin name
     */ 
    public String getLogPluginName(ILogEventListener log);

    /**
     * Retrieve the log event listener by instance name
     * @param insName the log instance name in String
     * @return the log instance in ILogEventListener
     */
    public ILogEventListener getLogInstance(String insName);

    /**
     * get the list of log plugins that are available
     * @return log plugins in a Hashtable.  Each entry in the
     * Hashtable contains the name/value pair of pluginName/LogPlugin
     * @see LogPlugin
     */
    public Hashtable getLogPlugins();

    /**
     * get the list of log instances that are available
     * @return log instances in a Hashtable.  Each entry in the
     * Hashtable contains the name/value pair of instName/ILogEventListener
     * @see LogPlugin
     */
    public Hashtable getLogInsts();

    /**
     * Get the default configuration parameter names associated with a 
     * plugin.  It is used by
     * administration servlet to handle log configuration when a new
     * log instance is added.
     * @param implName The implementation name for which the
     * configuration parameters are to be configured
     * @return a Vector of default configuration paramter names
     * associated with this log plugin
     * @exception ELogException when instantiation of the plugin
     * implementation fails.
     */
    public Vector getLogDefaultParams(String implName) throws
            ELogException;

    /**
     * Get the default configuration parameter names associated with a 
     * log instance.  It is used by administration servlet to handle
     * log instance configuration.
     * @param insName The instance name for which the configuration
     * parameters are to be configured
     * @return a Vector of default configuration paramter names
     * associated with this log instance.
     */
    public Vector getLogInstanceParams(String insName)
        throws ELogException;
}
