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

import java.text.MessageFormat;
import java.util.Locale;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.MessageFormatter;

/**
 * The log event object that carries message detail of a log event that goes
 * into the Signed Audit Event log. This log has the property of being digitally
 * signed for security considerations.
 * 
 * 
 * @version $Revision$, $Date$
 * @see java.text.MessageFormat
 * @see com.netscape.certsrv.logging.LogResources
 */
public class SignedAuditEvent implements IBundleLogEvent {

    /**
     *
     */
    private static final long serialVersionUID = 4287822756516673931L;

    protected Object mParams[] = null;

    private String mEventType = null;
    private String mMessage = null;
    private int mLevel = -1;
    private int mNTEventType = -1;
    private int mSource = -1;
    private boolean mMultiline = false;
    private long mTimeStamp = System.currentTimeMillis();

    private static final String INVALID_LOG_LEVEL = "log level: {0} is invalid, should be 0-6";

    /**
     * The bundle name for this event. ....not anymore...keep for now and clean
     * up later
     */
    private String mBundleName = LogResources.class.getName();

    /**
     * Constructs a SignedAuditEvent message event.
     * <P>
     * 
     * @param msgFormat The message string.
     */
    public SignedAuditEvent(String msgFormat) {
        mMessage = msgFormat;
        mParams = null;
    }

    /**
     * Constructs a message with a parameter. For example,
     * 
     * <PRE>
     * new SignedAuditEvent(&quot;failed to load {0}&quot;, fileName);
     * </PRE>
     * <P>
     * 
     * @param msgFormat Details in message string format.
     * @param param Message string parameter.
     */
    public SignedAuditEvent(String msgFormat, String param) {
        this(msgFormat);
        mParams = new String[1];
        mParams[0] = param;
    }

    /**
     * Constructs a message from an exception. It can be used to carry a signed
     * audit exception that may contain information about the context. For
     * example,
     * 
     * <PRE>
     * 		try {
     *  		...
     * 		} catch (IOExeption e) {
     * 		 	logHandler.log(new SignedAuditEvent("Encountered Signed Audit Error {0}", e);
     *      }
     * </PRE>
     * <P>
     * 
     * @param msgFormat Exception details in message string format.
     * @param exception System exception.
     */
    public SignedAuditEvent(String msgFormat, Exception exception) {
        this(msgFormat);
        mParams = new Exception[1];
        mParams[0] = exception;
    }

    /**
     * Constructs a message from a base exception. This will use the msgFormat
     * from the exception itself.
     * 
     * <PRE>
     * 		try {
     *  		...
     * 		} catch (Exception e) {
     * 		 	logHandler.log(new SignedAuditEvent(e));
     *      }
     * </PRE>
     * <P>
     * 
     * @param e CMS exception.
     */
    public SignedAuditEvent(Exception e) {
        this(e.getMessage());
        if (e instanceof EBaseException) {
            mParams = ((EBaseException) e).getParameters();
        } else {
            mParams = new Exception[1];
            mParams[0] = e;
        }
    }

    /**
     * Constructs a message event with a list of parameters that will be
     * substituted into the message format.
     * <P>
     * 
     * @param msgFormat Message string format.
     * @param params List of message format parameters.
     */
    public SignedAuditEvent(String msgFormat, Object params[]) {
        this(msgFormat);
        mParams = params;
    }

    /**
     * Returns the current message format string.
     * <P>
     * 
     * @return Details message.
     */
    public String getMessage() {
        return mMessage;
    }

    /**
     * Returns a list of parameters. These parameters can be used to assist in
     * formatting the message.
     * <P>
     * 
     * @return List of message format parameters.
     */
    public Object[] getParameters() {
        return mParams;
    }

    /**
     * Returns localized message string. This method should only be called if a
     * localized string is necessary.
     * <P>
     * 
     * @return Details message.
     */
    public String toContent() {
        return toContent(Locale.getDefault());
    }

    /**
     * Returns the string based on the given locale.
     * <P>
     * 
     * @param locale Locale.
     * @return Details message.
     */
    public String toContent(Locale locale) {
        return MessageFormatter.getLocalizedString(locale, getBundleName(),
                getMessage(), getParameters());
    }

    /**
     * Sets the resource bundle name for this class instance. This should be
     * overridden by subclasses who have their own resource bundles.
     * 
     * @param bundle String with name of resource bundle.
     */
    public void setBundleName(String bundle) {
        mBundleName = bundle;
    }

    /**
     * Retrieves bundle name.
     * 
     * @return String with name of resource bundle.
     */
    protected String getBundleName() {
        return mBundleName;
    }

    /**
     * Retrieves log source. This is an id of the subsystem responsible for
     * creating the log event.
     * 
     * @return Integer source id.
     */
    public int getSource() {
        return mSource;
    }

    /**
     * Sets log source.
     * 
     * @param source Integer id of log source.
     */
    public void setSource(int source) {
        mSource = source;
    }

    /**
     * Retrieves log level. The log level of an event represents its relative
     * importance or severity within CMS.
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
     * Sets log level, NT log event type. For certain log levels the NT log
     * event type gets set as well.
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
            ConsoleError.send(new SignedAuditEvent(INVALID_LOG_LEVEL, Integer
                    .toString(level)));
            break;
        }
    }

    /**
     * Retrieves log multiline attribute.
     * 
     * @return Boolean whether or not this event is multiline. A multiline
     *         message simply consists of more than one line.
     */
    public boolean getMultiline() {
        return mMultiline;
    }

    /**
     * Sets log multiline attribute. A multiline message consists of more than
     * one line.
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
     * Retrieves log event type. Each type of event has an associated String
     * type value.
     * 
     * @return String containing the type of event.
     */
    public String getEventType() {
        return mEventType;
    }

    /**
     * Sets log event type. Each type of event has an associated String type
     * value.
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
        if (getBundleName() == null) {
            MessageFormat detailMessage = new MessageFormat(mMessage);

            return detailMessage.format(mParams);
        } else
            return toContent();
    }
}
