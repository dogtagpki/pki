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
package com.netscape.cmscore.logging;

import java.util.Collection;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.TreeSet;
import java.util.Vector;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.Subsystem;
import com.netscape.certsrv.logging.ELogException;
import com.netscape.certsrv.logging.LogEventListener;
import com.netscape.certsrv.logging.LogPlugin;
import com.netscape.cms.logging.LogQueue;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ConfigStore;

/**
 * A class representing a log subsystem.
 * The logging component is a framework that handles different types of log types,
 * each represented by an LogFile, and each implements a log plugin.
 * CMS comes with three standard log types: "signedAudit", "system", and
 * "transaction". Each log plugin can be instantiated into log
 * instances. Each log instance can be individually configured and is
 * associated with its own configuration entries in the configuration file.
 *
 * @author thomask
 * @author mzhao
 */
public class LogSubsystem extends Subsystem {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(LogSubsystem.class);

    private static LogSubsystem mInstance = new LogSubsystem();
    private LoggingConfig mConfig;

    /**
     * The ID of this component
     */
    public static final String ID = "log";

    public static final String PROP_CLASS = "class";
    public static final String PROP_PLUGIN = "pluginName";

    public Hashtable<String, LogPlugin> mLogPlugins = new Hashtable<>();
    public Hashtable<String, LogEventListener> mLogInsts = new Hashtable<>();
    public Set<String> auditEvents = new TreeSet<>();

    /**
     * Constructs a log subsystem.
     */
    private LogSubsystem() {
    }

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public void setId(String id) throws EBaseException {
        throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_OPERATION"));
    }

    /**
     * Initializes the log subsystem.
     * <P>
     * @param config configuration store
     */
    @Override
    public void init(ConfigStore config) throws EBaseException {
        mConfig = (LoggingConfig) config;
        LogQueue.getInstance().init();

        // load log plugin implementation
        LoggerPluginsConfig pluginsConfig = mConfig.getLoggerPluginsConfig();
        Enumeration<String> mImpls = pluginsConfig.getSubStoreNames().elements();

        while (mImpls.hasMoreElements()) {
            String id = mImpls.nextElement();
            String pluginPath = pluginsConfig.getString(id + "." + PROP_CLASS);
            LogPlugin plugin = new LogPlugin(id, pluginPath);

            mLogPlugins.put(id, plugin);
        }
        logger.trace("loaded logger plugins");

        // load log instances
        LoggersConfig loggersConfig = mConfig.getLoggersConfig();
        Enumeration<String> instances = loggersConfig.getSubStoreNames().elements();

        while (instances.hasMoreElements()) {
            String insName = instances.nextElement();
            String implName = loggersConfig.getString(insName + "." +
                    PROP_PLUGIN);
            LogPlugin plugin =
                    mLogPlugins.get(implName);

            if (plugin == null) {
                throw new EBaseException(implName);
            }
            String className = plugin.getClassPath();
            // Instantiate and init the log listener.
            LogEventListener logInst = null;

            try {
                logInst = (LogEventListener) Class.forName(className).getDeclaredConstructor().newInstance();
                ConfigStore pConfig = loggersConfig.getSubStore(insName, ConfigStore.class);

                logInst.init(this, pConfig);
                // for view from console

            } catch (EBaseException e) {
                throw e;

            } catch (Exception e) {
                throw new EBaseException(insName + ": Unable to create " + className + ": " + e.getMessage(), e);
            }

            // add log instance to list.
            mLogInsts.put(insName, logInst);
            logger.trace("loaded log instance " + insName + " impl " + implName);
        }

        // load audit events from audit-events.properties
        ResourceBundle rb = ResourceBundle.getBundle("audit-events");
        Pattern value_pattern = Pattern.compile("^<type=(.*)>:.*");

        for (String name : rb.keySet()) {

            String value = rb.getString(name);

            Matcher value_matcher = value_pattern.matcher(value);
            if (!value_matcher.matches()) {
                continue;
            }

            String event = value_matcher.group(1);

            auditEvents.add(event.trim());
        }
    }

    public Collection<String> getAuditEvents() {
        return auditEvents;
    }

    @Override
    public void startup() throws EBaseException {
        logger.trace("entering LogSubsystem.startup()");
        Enumeration<String> enum1 = mLogInsts.keys();

        while (enum1.hasMoreElements()) {
            String instName = enum1.nextElement();

            logger.trace("about to call inst=" + instName + " in LogSubsystem.startup()");
            LogEventListener inst = mLogInsts.get(instName);

            inst.startup();
        }
    }

    /**
     * Stops this subsystem.
     * <P>
     */
    @Override
    public void shutdown() {
        LogQueue.getInstance().shutdown();
    }

    /**
     * Returns the root configuration storage of this system.
     * <P>
     *
     * @return configuration store of this subsystem
     */
    @Override
    public LoggingConfig getConfigStore() {
        return mConfig;
    }

    /**
     * Retrieves singleton: the LogSubsystem.
     */
    public static LogSubsystem getInstance() {
        return mInstance;
    }

    /**
     * Retrieve plugin name (implementation name) of the log event
     * listener. If no plug name found, an empty string is returned
     *
     * @param log the log event listener
     * @return the log event listener's plugin name
     */
    public String getLogPluginName(LogEventListener log) {
        ConfigStore cs = log.getConfigStore();
        if (cs == null) {
            return "";
        }
        try {
            return cs.getString("pluginName", "");
        } catch (EBaseException e) {
            e.printStackTrace();
            return "";
        }
    }

    /**
     * Retrieve the log event listener by instance name
     *
     * @param insName the log instance name in String
     * @return the log instance in LogEventListener
     */
    public LogEventListener getLogInstance(String insName) {
        return mLogInsts.get(insName);
    }

    /**
     * get the list of log plugins that are available
     *
     * @return log plugins in a Hashtable. Each entry in the
     *         Hashtable contains the name/value pair of pluginName/LogPlugin
     * @see LogPlugin
     */
    public Hashtable<String, LogPlugin> getLogPlugins() {
        return mLogPlugins;
    }

    /**
     * get the list of log instances that are available
     *
     * @return log instances in a Hashtable. Each entry in the
     *         Hashtable contains the name/value pair of instName/LogEventListener
     * @see LogPlugin
     */
    public Hashtable<String, LogEventListener> getLogInsts() {
        return mLogInsts;
    }

    /**
     * Get the default configuration parameter names associated with a
     * plugin. It is used by
     * administration servlet to handle log configuration when a new
     * log instance is added.
     *
     * @param implName The implementation name for which the
     *            configuration parameters are to be configured
     * @return a Vector of default configuration paramter names
     *         associated with this log plugin
     * @exception ELogException when instantiation of the plugin
     *                implementation fails.
     */
    public Vector<String> getLogDefaultParams(String implName) throws
            ELogException {
        // is this a registered implname?
        LogPlugin plugin = mLogPlugins.get(implName);

        if (plugin == null) {
            throw new ELogException(implName);
        }

        // a temporary instance
        LogEventListener LogInst = null;
        String className = plugin.getClassPath();

        try {
            LogInst = (LogEventListener) Class.forName(className).getDeclaredConstructor().newInstance();
            Vector<String> v = LogInst.getDefaultParams();

            return v;

        } catch (Exception e) {
            throw new ELogException(CMS.getUserMessage("CMS_LOG_LOAD_CLASS_FAIL", className), e);
        }
    }

    /**
     * Get the default configuration parameter names associated with a
     * log instance. It is used by administration servlet to handle
     * log instance configuration.
     *
     * @param insName The instance name for which the configuration
     *            parameters are to be configured
     * @return a Vector of default configuration paramter names
     *         associated with this log instance.
     */
    public Vector<String> getLogInstanceParams(String insName) throws
            ELogException {
        LogEventListener logInst = getLogInstance(insName);

        if (logInst == null) {
            return null;
        }
        Vector<String> v = logInst.getInstanceParams();

        return v;
    }
}
