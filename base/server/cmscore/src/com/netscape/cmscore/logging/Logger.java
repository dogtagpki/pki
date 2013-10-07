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

import java.util.Hashtable;
import java.util.Properties;

import com.netscape.certsrv.logging.ILogEvent;
import com.netscape.certsrv.logging.ILogEventFactory;
import com.netscape.certsrv.logging.ILogQueue;
import com.netscape.certsrv.logging.ILogger;

/**
 * A class represents certificate server logger
 * implementation.
 * <P>
 *
 * @author thomask
 * @author mzhao
 * @version $Revision$, $Date$
 */
public class Logger implements ILogger {

    protected static Logger mLogger = new Logger();
    protected ILogQueue mLogQueue = null;
    protected Hashtable<Integer, ILogEventFactory> mFactories = new Hashtable<Integer, ILogEventFactory>();

    /**
     * Constructs a generic logger, and registers a list
     * of resident event factories.
     */
    public Logger() {
        mLogQueue = LogSubsystem.getLogQueue();

        // register standard event factories
        register(EV_AUDIT, new AuditEventFactory());
        register(EV_SYSTEM, new SystemEventFactory());
        register(EV_SIGNED_AUDIT, new SignedAuditEventFactory());
    }

    /**
     * get default single global logger
     */
    static public Logger getLogger() {
        return mLogger;
    }

    /**
     * Retrieves the associated log queue.
     */
    public ILogQueue getLogQueue() {
        return mLogQueue;
    }

    /**
     * Registers log factory.
     *
     * @param evtClass the event class name: ILogger.EV_SYSTEM or ILogger.EV_AUDIT
     * @param f the event factory name
     */
    public void register(int evtClass, ILogEventFactory f) {
        mFactories.put(evtClass, f);
    }

    //************** default level ****************
    /**
     * Logs an event using default log level: ILogger.LL_INFO
     *
     * @param evtClass What kind of event it is: EV_AUDIT or EV_SYSTEM.
     * @param source the source of the log event
     * @param msg the one line detail message to be logged
     */
    public void log(int evtClass, int source, String msg) {
        log(evtClass, null, source, ILogger.LL_INFO, msg, null);
    }

    /**
     * Logs an event using default log level: ILogger.LL_INFO
     *
     * @param evtClass What kind of event it is: EV_AUDIT or EV_SYSTEM.
     * @param props the resource bundle used for the detailed message
     * @param source the source of the log event
     * @param msg the one line detail message to be logged
     */
    public void log(int evtClass, Properties props, int source, String msg) {
        log(evtClass, props, source, ILogger.LL_INFO, msg, null);
    }

    //************** no param ****************

    /**
     * Logs an event to the log queue.
     *
     * @param evtClass What kind of event it is: EV_AUDIT or EV_SYSTEM.
     * @param source the source of the log event
     * @param level the level of the log event
     * @param msg the one line detail message to be logged
     */
    public void log(int evtClass, int source, int level, String msg) {
        log(evtClass, null, source, level, msg, null);
    }

    /**
     * Logs an event to the log queue.
     *
     * @param evtClass What kind of event it is: EV_AUDIT or EV_SYSTEM.
     * @param props the resource bundle used for the detailed message
     * @param source the source of the log event
     * @param level the level of the log event
     * @param msg the one line detail message to be logged
     */
    public void log(int evtClass, Properties props, int source, int level, String msg) {
        log(evtClass, props, source, level, msg, null);
    }

    //********************* one param **********************

    /**
     * Logs an event to the log queue.
     *
     * @param evtClass What kind of event it is: EV_AUDIT or EV_SYSTEM.
     * @param props the resource bundle used for the detailed message
     * @param source the source of the log event
     * @param msg the one line detail message to be logged
     * @param param the parameter in the detail message
     */
    public void log(int evtClass, int source, int level, String msg, Object param) {
        log(evtClass, null, source, level, msg, param);
    }

    /**
     * Logs an event using default log level: ILogger.LL_INFO
     *
     * @param evtClass What kind of event it is: EV_AUDIT or EV_SYSTEM.
     * @param props the resource bundle used for the detailed message
     * @param source the source of the log event
     * @param msg the one line detail message to be logged
     * @param param the parameter in the detail message
     */
    public void log(int evtClass, Properties props, int source, String msg, Object param) {
        log(evtClass, props, source, ILogger.LL_INFO, msg, param);
    }

    /**
     * Logs an event to the log queue.
     *
     * @param evtClass What kind of event it is: EV_AUDIT or EV_SYSTEM.
     * @param props the resource bundle used for the detailed message
     * @param source the source of the log event
     * @param level the level of the log event
     * @param msg the one line detail message to be logged
     * @param param the parameter in the detail message
     */
    public void log(int evtClass, Properties props, int source, int level, String msg,
            Object param) {
        Object o[] = new Object[1];

        o[0] = param;
        log(evtClass, props, source, level, msg, o);
    }

    //******************* multiple param **************************

    /**
     * Logs an event to the log queue.
     *
     * @param evtClass What kind of event it is: EV_AUDIT or EV_SYSTEM.
     * @param source the source of the log event
     * @param level the level of the log event
     * @param msg the one line detail message to be logged
     * @param params the parameters in the detail message
     */
    public void log(int evtClass, int source, int level, String msg,
            Object params[]) {
        log(evtClass, null, source, level, msg, params);
    }

    //*************** the real implementation *****************
    /**
     * Logs an event to the log queue.
     *
     * @param evtClass What kind of event it is: EV_AUDIT or EV_SYSTEM.
     * @param props the resource bundle used for the detailed message
     * @param source the source of the log event
     * @param level the level of the log event
     * @param msg the one line detail message to be logged
     * @param params the parameters in the detail message
     */
    public void log(int evtClass, Properties prop, int source, int level, String msg,
            Object params[]) {
        ILogEvent iLEvent = create(evtClass, prop, source, level, msg, params, ILogger.L_SINGLELINE);
        if (iLEvent != null)
            mLogQueue.log(iLEvent);
    }

    //******************** multiline log *************************
    //************** default level ****************
    /**
     * Logs an event using default log level: ILogger.LL_INFO
     *
     * @param evtClass What kind of event it is: EV_AUDIT or EV_SYSTEM.
     * @param source the source of the log event
     * @param msg the one line detail message to be logged
     * @param multiline true if the message has more than one line, otherwise false
     */
    public void log(int evtClass, int source, String msg, boolean multiline) {
        log(evtClass, null, source, ILogger.LL_INFO, msg, null, multiline);
    }

    /**
     * Logs an event using default log level: ILogger.LL_INFO
     *
     * @param evtClass What kind of event it is: EV_AUDIT or EV_SYSTEM.
     * @param props the resource bundle used for the detailed message
     * @param source the source of the log event
     * @param msg the one line detail message to be logged
     * @param multiline true if the message has more than one line, otherwise false
     */
    public void log(int evtClass, Properties props, int source, String msg, boolean multiline) {
        log(evtClass, props, source, ILogger.LL_INFO, msg, null, multiline);
    }

    //************** no param ****************

    /**
     * Logs an event to the log queue.
     *
     * @param evtClass What kind of event it is: EV_AUDIT or EV_SYSTEM.
     * @param source the source of the log event
     * @param level the level of the log event
     * @param msg the one line detail message to be logged
     * @param multiline true if the message has more than one line, otherwise false
     */
    public void log(int evtClass, int source, int level, String msg, boolean multiline) {
        log(evtClass, null, source, level, msg, null, multiline);
    }

    /**
     * Logs an event to the log queue.
     *
     * @param evtClass What kind of event it is: EV_AUDIT or EV_SYSTEM.
     * @param props the resource bundle used for the detailed message
     * @param source the source of the log event
     * @param level the level of the log event
     * @param msg the one line detail message to be logged
     * @param multiline true if the message has more than one line, otherwise false
     */
    public void log(int evtClass, Properties props, int source, int level, String msg, boolean multiline) {
        log(evtClass, props, source, level, msg, null, multiline);
    }

    //********************* one param **********************

    /**
     * Logs an event to the log queue.
     *
     * @param evtClass What kind of event it is: EV_AUDIT or EV_SYSTEM.
     * @param props the resource bundle used for the detailed message
     * @param source the source of the log event
     * @param msg the one line detail message to be logged
     * @param param the parameter in the detail message
     * @param multiline true if the message has more than one line, otherwise false
     */
    public void log(int evtClass, int source, int level, String msg, Object param, boolean multiline) {
        log(evtClass, null, source, level, msg, param, multiline);
    }

    /**
     * Logs an event using default log level: ILogger.LL_INFO
     *
     * @param evtClass What kind of event it is: EV_AUDIT or EV_SYSTEM.
     * @param props the resource bundle used for the detailed message
     * @param source the source of the log event
     * @param msg the one line detail message to be logged
     * @param param the parameter in the detail message
     * @param multiline true if the message has more than one line, otherwise false
     */
    public void log(int evtClass, Properties props, int source, String msg, Object param, boolean multiline) {
        log(evtClass, props, source, ILogger.LL_INFO, msg, param, multiline);
    }

    /**
     * Logs an event to the log queue.
     *
     * @param evtClass What kind of event it is: EV_AUDIT or EV_SYSTEM.
     * @param props the resource bundle used for the detailed message
     * @param source the source of the log event
     * @param level the level of the log event
     * @param msg the one line detail message to be logged
     * @param param the parameter in the detail message
     * @param multiline true if the message has more than one line, otherwise false
     */
    public void log(int evtClass, Properties props, int source, int level, String msg,
            Object param, boolean multiline) {
        Object o[] = new Object[1];

        o[0] = param;
        log(evtClass, props, source, level, msg, o, multiline);
    }

    //******************* multiple param **************************

    /**
     * Logs an event to the log queue.
     *
     * @param evtClass What kind of event it is: EV_AUDIT or EV_SYSTEM.
     * @param source the source of the log event
     * @param level the level of the log event
     * @param msg the one line detail message to be logged
     * @param params the parameters in the detail message
     * @param multiline true if the message has more than one line, otherwise false
     */
    public void log(int evtClass, int source, int level, String msg,
            Object params[], boolean multiline) {
        log(evtClass, null, source, level, msg, params, multiline);
    }

    //*************** the real implementation *****************
    /**
     * Logs an event to the log queue.
     *
     * @param evtClass What kind of event it is: EV_AUDIT or EV_SYSTEM.
     * @param props the resource bundle used for the detailed message
     * @param source the source of the log event
     * @param level the level of the log event
     * @param msg the one line detail message to be logged
     * @param params the parameters in the detail message
     * @param multiline true if the message has more than one line, otherwise false
     */
    public void log(int evtClass, Properties prop, int source, int level, String msg,
            Object params[], boolean multiline) {
        ILogEvent iLEvent = create(evtClass, prop, source, level, msg, params, multiline);
        if (iLEvent != null)
            mLogQueue.log(iLEvent);
    }

    //******************** end  multiline log *************************

    /**
     * Creates generic log event. If required, we can recycle
     * events here.
     */
    //XXXXXXXXXXX prop is out dated!!!! XXXXXXXXXXXXXXX
    public ILogEvent create(int evtClass, Properties prop, int source, int level,
            String msg, Object params[], boolean multiline) {
        ILogEventFactory f = mFactories.get(evtClass);

        if (f == null)
            return null;
        return f.create(evtClass, prop, source, level, multiline, msg, params);
    }

    /**
     * Notifies logger to reuse the event. This framework
     * opens up possibility to reuse event.
     *
     * @param event a log event
     */
    public void release(ILogEvent event) {
        // do nothing for now.
    }

}
