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
package com.netscape.osutil;


/**
 * This class provides an interface to Windows NT event logging.
 *
 * @version $Revision: 14579 $, $Date: 2007-05-01 13:07:48 -0700 (Tue, 01 May 2007) $
 */
public class NTEventLogger {

    private byte[] handle; // Must be non-null. Should be non-empty.
    private boolean open; // true if this log is open for writing.

    // The Windows NT event ID.  The actual event ID is 1001, but we also
    // need to set bit 29 to indicate that we are not Microsoft.
    // See _Windows NT Event Logging_ (O'Reilly), page 128, for an explanation.
    public static final int EVENT_ID = 0x20000000 | 1001;

    private NTEventLogger() {
    }

    // Load native library.  This is the same library used by OsSubsystem.
    // loadLibrary() is idempotent, so don't worry about calling it multiple
    // times.
    static {
        try {
            System.loadLibrary("osutil");
        } catch (Throwable t) {
            // This is bad news, the program is doomed at this point
            t.printStackTrace();
        }
    }

    /**
     * Creates an application or system NT Event log handle.
     *
     * @param eventSourceName The name of the source application.
     *    This should be a subkey of
     *    <code>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\EventLog</code>.
     *    If the given source does not exist, NT will automatically return
     *        a handle to the application log without complaining.
     *    The reason to use a real source, rather than just using the default
     *        application log, is that the registry key of a real source
     *        tells NT where to find the message resources for formatting
     *        the strings that are sent in <code>reportEvent</code>.
     *        If the default application log is used, NT will insert a lame
     *        message: "The description for Event ID ( ... ) in Source
     *        ( ... ) could not be found. It contains the following insertion
     *        string(s):".
     * @throws Exception If an error occurs in the native NT code.  The
     *    exception message will contain more information.
     */
    public NTEventLogger(String eventSourceName) throws Exception {
        open = true;
        handle = initNTLog(eventSourceName);
    }

    /**
     * Writes a string to the log.  This is the simple way to write to the
     *  NT event log.
     *    <p>This method must not be called after the log is
     *    closed.
     * 
     * @param type The type of the event that is logged.  Pre-defined types
     *         are:
     *    <table border>
     *    <tr><th>Name</th><th>Description</th></tr>
     *    <tr><td>EVENTLOG_SUCCESS</td><td>Success</td></tr>
     *    <tr><td>EVENTLOG_ERROR_TYPE</td><td>Error</td></tr>
     *    <tr><td>EVENTLOG_WARNING_TYPE</td><td>Warning</td></tr>
     *    <tr><td>EVENTLOG_INFORMATION_TYPE</td><td>Informational</td></tr>
     *    <tr><td>EVENTLOG_AUDIT_SUCCESS</td><td>Success Audit</td></tr>
     *    <tr><td>EVENTLOG_AUDIT_FAILURE</td><td>Failure Audit</td></tr>
     *    </table>
     * @param logMessage The string that will be written to the log.
     * @exception Exception If an error occurs. The exception message will
     *        have more information.
     */
    public void
    reportEvent(int type, String logMessage) throws Exception {
        if (!open) {
            throw new IllegalArgumentException("Log has been closed");
        }

        reportEventNative(handle, (short) type, (short) 0, EVENT_ID,
            new String[] {logMessage}
        );
    }

    /**
     * Writes an NT event to the log.  See NT documentation for a description
     * of the parameters. This is the complicated way to write to the log,
     *    to be used if you want to do something tricky. Normally you'll want
     *    to call reportEvent(int, String).
     *    <p>This method must not be called after the log is
     *    closed.
     * 
     * @param type The type of the event that is logged.  Pre-defined types
     *         are:
     *    <table border>
     *    <tr><th>Name</th><th>Description</th></tr>
     *    <tr><td>EVENTLOG_SUCCESS</td><td>Success</td></tr>
     *    <tr><td>EVENTLOG_ERROR_TYPE</td><td>Error</td></tr>
     *    <tr><td>EVENTLOG_WARNING_TYPE</td><td>Warning</td></tr>
     *    <tr><td>EVENTLOG_INFORMATION_TYPE</td><td>Informational</td></tr>
     *    <tr><td>EVENTLOG_AUDIT_SUCCESS</td><td>Success Audit</td></tr>
     *    <tr><td>EVENTLOG_AUDIT_FAILURE</td><td>Failure Audit</td></tr>
     *    </table>
     * @param category An application-defined category for the event, which
     *        must be in the range 0-65535. A value of 0 indicates that there
     *        is not event category.
     * @param eventID The application-specific event index.  It must be in the
     *        range 0-65535.
     * @param strings An array of description strings to be written to the log.
     * @exception Exception If an error occurs. The exception message will
     *        have more information.
     */
    public void
    reportEvent(int type, int category, int eventID,
        String[] strings) throws Exception {
        if (!open) {
            throw new IllegalArgumentException("Log has been closed");
        }

        /* check args */
        if (category < 0 || category > 65535) {
            throw new IllegalArgumentException("category " + category +
                    " is outside the valid range");
        }

        reportEventNative(handle, (short) type, (short) category,
            eventID, strings);
    }

    private static native void
    reportEventNative(byte[] handle, short type, short category, int eventID,
        String[] strings) throws Exception;

    // Cleans up native resources when the Java object gets garbage collected
    protected void finalize() throws Throwable {
        close();
    }

    public void close() throws Exception {
        if (open) {
            shutdownNTLog(handle);
            open = false;
        }
    }
    
    // creates the NT log in native code, returns a byte array containing
    // the Windows log HANDLE.
    private static native byte[]
    initNTLog(String eventSourceName) throws Exception;

    // Closes the log pointed to by the given handle.
    private static native void
    shutdownNTLog(byte[] handle) throws Exception;

    public static void main(String args[]) {
        try {
            NTEventLogger h = new NTEventLogger("NTEventLogger test");

            h.reportEvent(EVENTLOG_SUCCESS, "This is a test");
            h.reportEvent(EVENTLOG_ERROR_TYPE,
                "SERVER MELTDOWN: Evacuate the building!!!");

        }catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static final short EVENTLOG_SUCCESS = 0;
    public static final short EVENTLOG_ERROR_TYPE = 1;
    public static final short EVENTLOG_WARNING_TYPE = 2;
    public static final short EVENTLOG_INFORMATION_TYPE = 4;
    public static final short EVENTLOG_AUDIT_SUCCESS = 8;
    public static final short EVENTLOG_AUDIT_FAILURE = 16;
}
