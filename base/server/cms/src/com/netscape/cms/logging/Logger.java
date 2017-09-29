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
package com.netscape.cms.logging;

import java.util.Hashtable;

import com.netscape.certsrv.logging.ILogEvent;
import com.netscape.certsrv.logging.ILogQueue;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.LogCategory;
import com.netscape.certsrv.logging.LogEvent;
import com.netscape.certsrv.logging.LogSource;

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
    protected ILogQueue mLogQueue = LogQueue.getLogQueue();
    protected static Hashtable<LogCategory, LogFactory> mFactories = new Hashtable<LogCategory, LogFactory>();

    static {
        register(EV_AUDIT, new AuditEventFactory());
        register(EV_SYSTEM, new SystemEventFactory());
    }

    LogFactory factory;
    LogCategory category;
    LogSource source;
    int level = ILogger.LL_INFO;

    public Logger() {
    }

    public Logger(LogFactory factory, LogCategory category, LogSource source) {
        this.factory = factory;
        this.category = category;
        this.source = source;
    }

    public Logger(LogFactory factory, LogCategory category, LogSource source, int level) {
        this.factory = factory;
        this.category = category;
        this.source = source;
        this.level = level;
    }

    /**
     * get default single global logger
     */
    static public Logger getLogger() {
        return mLogger;
    }

    public static Logger getLogger(LogCategory category, LogSource source) {

        LogFactory factory = mFactories.get(category);

        if (factory == null) {
            throw new RuntimeException("Unknown logger category: " + category);
        }

        return factory.createLogger(category, source);
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
    public static void register(LogCategory evtClass, LogFactory f) {
        mFactories.put(evtClass, f);
    }

    //************** default level ****************

    public void log(String msg) {
        log(category, source, level, msg, null, ILogger.L_SINGLELINE);
    }

    public void log(LogEvent event) {
        log(category, source, level, event.getMessage(), event.getParameters(), ILogger.L_SINGLELINE);
    }

    /**
     * Logs an event using default log level.
     *
     * @param evtClass What kind of event it is: EV_AUDIT or EV_SYSTEM.
     * @param source the source of the log event
     * @param msg the one line detail message to be logged
     */
    public void log(LogCategory evtClass, LogSource source, String msg) {
        log(evtClass, source, level, msg, null, ILogger.L_SINGLELINE);
    }

    //************** no param ****************

    public void log(int level, String msg) {
        log(category, source, level, msg, null, ILogger.L_SINGLELINE);
    }

    /**
     * Logs an event to the log queue.
     *
     * @param evtClass What kind of event it is: EV_AUDIT or EV_SYSTEM.
     * @param source the source of the log event
     * @param level the level of the log event
     * @param msg the one line detail message to be logged
     */
    public void log(LogCategory evtClass, LogSource source, int level, String msg) {
        log(evtClass, source, level, msg, null, ILogger.L_SINGLELINE);
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
    public void log(LogCategory evtClass, LogSource source, int level, String msg, Object param) {
        Object o[] = new Object[1];
        o[0] = param;
        log(evtClass, source, level, msg, o, ILogger.L_SINGLELINE);
    }

    //******************* multiple param **************************

    public void log(int level, String msg, Object params[]) {
        log(category, source, level, msg, params, ILogger.L_SINGLELINE);
    }

    /**
     * Logs an event to the log queue.
     *
     * @param evtClass What kind of event it is: EV_AUDIT or EV_SYSTEM.
     * @param source the source of the log event
     * @param level the level of the log event
     * @param msg the one line detail message to be logged
     * @param params the parameters in the detail message
     */
    public void log(LogCategory evtClass, LogSource source, int level, String msg,
            Object params[]) {
        log(evtClass, source, level, msg, params, ILogger.L_SINGLELINE);
    }

    //******************** multiline log *************************
    //************** default level ****************
    /**
     * Logs an event using default log level.
     *
     * @param evtClass What kind of event it is: EV_AUDIT or EV_SYSTEM.
     * @param source the source of the log event
     * @param msg the one line detail message to be logged
     * @param multiline true if the message has more than one line, otherwise false
     */
    public void log(LogCategory evtClass, LogSource source, String msg, boolean multiline) {
        log(evtClass, source, level, msg, null, multiline);
    }

    //************** no param ****************

    public void log(int level, String msg, boolean multiline) {
        log(category, source, level, msg, null, multiline);
    }

    /**
     * Logs an event to the log queue.
     *
     * @param evtClass What kind of event it is: EV_AUDIT or EV_SYSTEM.
     * @param source the source of the log event
     * @param level the level of the log event
     * @param msg the one line detail message to be logged
     * @param multiline true if the message has more than one line, otherwise false
     */
    public void log(LogCategory evtClass, LogSource source, int level, String msg, boolean multiline) {
        log(evtClass, source, level, msg, null, multiline);
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
    public void log(LogCategory evtClass, LogSource source, int level, String msg, Object param, boolean multiline) {
        Object o[] = new Object[1];
        o[0] = param;
        log(evtClass, source, level, msg, o, multiline);
    }

    //******************* multiple param **************************

    public void log(int level, String msg, Object params[], boolean multiline) {
        log(category, source, level, msg, params, multiline);
    }

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
    public void log(LogCategory evtClass, LogSource source, int level, String msg,
            Object params[], boolean multiline) {
        ILogEvent iLEvent = create(evtClass, source, level, msg, params, multiline);
        if (iLEvent != null)
            mLogQueue.log(iLEvent);
    }

    //******************** end  multiline log *************************

    public ILogEvent create(int level, String msg, Object params[], boolean multiline) {
        return create(category, source, level, msg, params, multiline);
    }

    /**
     * Creates generic log event. If required, we can recycle
     * events here.
     */
    public ILogEvent create(LogCategory evtClass, LogSource source, int level,
            String msg, Object params[], boolean multiline) {

        LogFactory f = factory == null ? mFactories.get(evtClass) : factory;

        if (f == null) {
            throw new RuntimeException("Unknown logger category: " + evtClass);
        }

        LogEvent event = (LogEvent) f.create();
        update(event, source, level, msg, params, multiline);
        return event;
    }

    /**
     * Updates a log event.
     *
     * @param event The event to be updated.
     * @param source The subsystem who creates the log event.
     * @param level The severity of the log event.
     * @param message The detail message of the log.
     * @param params The parameters in the detail log message.
     * @param multiline The log message has more than one line or not.
     */
    public void update(LogEvent event, LogSource source, int level,
            String message, Object params[], boolean multiline) {

        event.setSource(source);
        event.setLevel(level);
        event.setMessage(message);
        event.setParameters(params);
        event.setMultiline(multiline);
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
