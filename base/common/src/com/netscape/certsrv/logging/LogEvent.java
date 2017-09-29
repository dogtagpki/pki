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
// (C) 2017 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.logging;

import java.text.MessageFormat;

import com.netscape.certsrv.base.EBaseException;

public class LogEvent implements ILogEvent {

    private static final long serialVersionUID = 1L;

    static final String INVALID_LOG_LEVEL = "log level: {0} is invalid, should be 0-6";

    Object mParams[];

    String mEventType;
    String mMessage;
    int mLevel = -1;
    int mNTEventType = -1;
    LogSource mSource;
    boolean mMultiline = false;
    long mTimeStamp = System.currentTimeMillis();

    public LogEvent() {
    }

    /**
     * Constructs a message event
     * <P>
     *
     * @param msgFormat the message string
     */
    public LogEvent(String msgFormat) {
        mMessage = msgFormat;
        mParams = null;
    }

    /**
     * Constructs a message with a parameter. For example,
     *
     * <PRE>
     * new AuditEvent(&quot;failed to load {0}&quot;, fileName);
     * </PRE>
     * <P>
     *
     * @param msgFormat details in message string format
     * @param param message string parameter
     */
    public LogEvent(String msgFormat, String param) {
        this(msgFormat);
        mParams = new String[1];
        mParams[0] = param;
    }

    /**
     * Constructs a message from an exception. It can be used to carry
     * a system exception that may contain information about
     * the context. For example,
     *
     * <PRE>
     *         try {
     *          ...
     *         } catch (IOExeption e) {
     *              logHandler.log(new AuditEvent("Encountered System Error {0}", e);
     *      }
     * </PRE>
     * <P>
     *
     * @param msgFormat exception details in message string format
     * @param exception system exception
     */
    public LogEvent(String msgFormat, Exception exception) {
        this(msgFormat);
        mParams = new Exception[1];
        mParams[0] = exception;
    }

    /**
     * Constructs a message from a base exception. This will use the msgFormat
     * from the exception itself.
     *
     * <PRE>
     *         try {
     *          ...
     *         } catch (Exception e) {
     *              logHandler.log(new AuditEvent(e));
     *      }
     * </PRE>
     * <P>
     *
     * @param e CMS exception
     */
    public LogEvent(Exception e) {
        this(e.getMessage());
        if (e instanceof EBaseException) {
            mParams = ((EBaseException) e).getParameters();
        } else {
            mParams = new Exception[1];
            mParams[0] = e;
        }
    }

    /**
     * Constructs a message event with a list of parameters
     * that will be substituted into the message format.
     * <P>
     *
     * @param msgFormat message string format
     * @param params list of message format parameters
     */
    public LogEvent(String msgFormat, Object params[]) {
        this(msgFormat);
        mParams = params;
    }

    /**
     * Returns the current message format string.
     * <P>
     *
     * @return details message
     */
    public String getMessage() {
        return mMessage;
    }

    public void setMessage(String message) {
        this.mMessage = message;
    }

    /**
     * Returns a list of parameters.
     * <P>
     *
     * @return list of message format parameters
     */
    public Object[] getParameters() {
        return mParams;
    }

    /**
     * Sets audit event's parameters.
     */
    public void setParameters(Object[] params) {
        mParams = params;
    }

    /**
     * Retrieves log source.
     *
     * @return the component source
     *         where this message event was triggered
     */
    public LogSource getSource() {
        return mSource;
    }

    /**
     * Sets log source.
     *
     * @param source the component source
     *            where this message event was triggered
     */
    public void setSource(LogSource source) {
        mSource = source;
    }

    /**
     * Retrieves log level.
     * The log level of an event represents its relative importance
     * or severity within CMS.
     *
     * @return Integer log level value.
     */
    public int getLevel() {
        return mLevel;
    }

    /**
     * Retrieves NT specific log event type.
     *
     * @return Integer NTEventType value.
     */
    public int getNTEventType() {
        return mNTEventType;
    }

    /**
     * Sets log level, NT log event type.
     * For certain log levels the NT log event type gets
     * set as well.
     *
     * @param level Integer log level value.
     */
    public void setLevel(int level) {
        mLevel = level;
        switch (level) {
        case ILogger.LL_DEBUG:
        case ILogger.LL_INFO:
            mNTEventType = ILogger.NT_INFO;
            break;

        case ILogger.LL_WARN:
            mNTEventType = ILogger.NT_WARN;
            break;

        case ILogger.LL_FAILURE:
        case ILogger.LL_MISCONF:
        case ILogger.LL_CATASTRPHE:
        case ILogger.LL_SECURITY:
            mNTEventType = ILogger.NT_ERROR;
            break;

        default:
            ConsoleError.send(new SystemEvent(INVALID_LOG_LEVEL,
                    Integer.toString(level)));
            break;
        }
    }

    /**
     * Retrieves log multiline attribute.
     *
     * @return Boolean whether or not this event is multiline.
     *         A multiline message simply consists of more than one line.
     */
    public boolean getMultiline() {
        return mMultiline;
    }

    /**
     * Sets log multiline attribute. A multiline message consists of
     * more than one line.
     *
     * @param multiline Boolean multiline value.
     */
    public void setMultiline(boolean multiline) {
        mMultiline = multiline;
    }

    /**
     * Retrieves event time stamp.
     *
     * @return Long integer of the time the event was created.
     */
    public long getTimeStamp() {
        return mTimeStamp;
    }

    /**
     * Retrieves log event type. Each type of event
     * has an associated String type value.
     *
     * @return String containing the type of event.
     */
    public String getEventType() {
        return mEventType;
    }

    /**
     * Sets log event type. Each type of event
     * has an associated String type value.
     *
     * @param eventType String containing the type of event.
     */
    public void setEventType(String eventType) {
        mEventType = eventType;
    }

    /**
     * Return string representation of log message.
     *
     * @return String containing log message.
     */
    public String toString() {
        MessageFormat detailMessage = new MessageFormat(mMessage);
        return detailMessage.format(mParams);
    }
}
