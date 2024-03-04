/** BEGIN COPYRIGHT BLOCK
 * Copyright (C) 2001 Sun Microsystems, Inc.  Used by permission.
 * Copyright (C) 2005 Red Hat, Inc.
 * All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation version
 * 2.1 of the License.
 *                                                                                 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *                                                                                 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * END COPYRIGHT BLOCK **/
package com.netscape.management.client.util;

import java.io.*;
import java.util.*;
import java.text.SimpleDateFormat;

/**
 * The Debug class controls the output of debugging statements. There are
 * two levels of control for the output. First, the output can be prevented
 * outright by disabling the trace flag. Second, the amount of output can
 * be regulated by the trace level. By convention, we use ten levels,
 * designated from 0 to 9. 0 implies least output and 9 implies full output.
 * By default, the trace level is set to 5 and the trace level designated
 * to debugging statements without a specific level is also 5. These
 * statements will be printed when the trace flag is enabled. To reduce the
 * amount of output, debugging statements should be specified with this
 * default level in mind. Note that all statements designated at the
 * current trace level or below will be printed.
 */
public class Debug {
    // Predefined trace types
    public static final String TYPE_GC = "memgc"; // garbage collection
    public static final String TYPE_LDAP = "ldap"; // ldap calls
    public static final String TYPE_JSS  = "jss";  // jss calls
    public static final String TYPE_HTTP = "http"; // http calls
    public static final String TYPE_RSPTIME = "rsptime"; // response time
    public static final String TYPE_NOJARS = "nojars"; // no jars - for debuggers

    //Predefined keywords used for gc trace type
    public static final String KW_CREATE = "Create   ";
    public static final String KW_FINALIZE = "FINALIZE ";

    public static boolean _fTrace = false; // flag for global tracing
    public static int _iTraceLevel = 5; // default trace level
    private static Vector _traceTypes; // A list of enabled trace types

    // Flags "enabled" for predefined trace types. Fast way to check if a
    // predefined type is enabled, rather than searching _traceTypes list
    private static boolean _fTraceGC, _fTraceLdap, _fTraceJSS, _fTraceHttp, _fTraceTime,
    	_fNoJars;

    // Flags for show entry options
    public static final int SHOW_INDEX = 1;
    public static final int SHOW_DEBUGLEVEL = 2;
    public static final int SHOW_TIMESTAMP = 4;

    // OR-ed SHOW_<name> flags
    private static int _showFlags;

    // Time Stemp format Hour(0-23):Minute:Second.Milliseconds
    public static SimpleDateFormat _timeFormat = new SimpleDateFormat("HH:mm:ss.SSS");

    // On off list for filtering trace entries with specific string pattern
    public static Vector _onFilter, _offFilter;

    // Time the application was started
    private static long _appStartTimeStamp;

    // Time stamp for the last printed debug message when SHOW_TIMESTAMP is enabled
    private static long _lastTimeStamp;

    // Index of the last trace entry when SHOW_INDEX is enabled
    private static int _iEntryIndex = 0;

    // Show caller selector
    // 0 = do not show
    // 1 = short mode in format method(File:lineNo)
    // 2 = full mode in format fullPackageName+Method(File:LineNo)
    private static int _showCaller = 0;

    // Flag whether to show call stack
    private static boolean _fPrintCallStack = false;



    /**
    * Constructor.
    */
    public Debug() {
        _fTrace = false;
        _iTraceLevel = -1;
    }

    public static boolean gcTraceEnabled() {
        return _fTraceGC;
    }
    public static boolean ldapTraceEnabled() {
        return _fTraceLdap;
    }
    public static boolean jssTraceEnabled() {
        return _fTraceJSS;
    }
    public static boolean httpTraceEnabled() {
        return _fTraceHttp;
    }
    public static boolean timeTraceEnabled() {
        return _fTraceTime;
    }
    public static boolean noJarsEnabled() {
        return _fNoJars;
    }
    public static int getShowFlags() {
        return _showFlags;
    }

    /**
     * Enables or disables debugging.
     * @param fTrace  boolean value
     */
    public static void setTrace(boolean fTrace) {
        _fTrace = fTrace;
        if (!_fTrace)
            _iTraceLevel = -1;
    }

    /**
     * Determine whether debugging is enabled or disabled.
     * @return  boolean value
     */
    public static boolean getTrace() {
        return _fTrace;
    }

    public static boolean isEnabled() {
        return _fTrace;
    }

    /**
     * Set the verbose level of the debugging output.
     * @param iTraceLevel  integer value indicating which debugging statements to display
     */
    public static void setTraceLevel(int iTraceLevel) {
        _iTraceLevel = iTraceLevel;
        if (_iTraceLevel >= 0)
            _fTrace = true;
    }

    /**
     * Retrieves the verbose level of the debugging output.
     * @return  integer value indicating which debugging statements to display
     */
    public static int getTraceLevel() {
        return _iTraceLevel;
    }

    /**
     * Set the trace mode for debugging output.
     * The input parameter has the format [<typeList>][:<flagList>]
     * List elements are comma separated.
     * If '?' is specified as the input parameter, print usage information
     *
     * @param mode a list of trace types and flags or '?'
     * @return success flag
     */
    public static boolean setTraceMode(String mode) {
        // By default enable trace at level 5
        if (mode == null) {
            _fTrace = true;
            _iTraceLevel = 5;
            return true;
        }

        String flags = null, typeList = mode;
        int sep = mode.indexOf(':');
        if (sep >= 0) {
            flags = mode.substring(sep + 1);
            typeList = mode.substring(0, sep);
            if (typeList.length() == 0) {
                _fTrace = true;
                _iTraceLevel = 5;
            }
        }

        StringTokenizer list = new StringTokenizer(typeList, ",");
        _traceTypes = new Vector();
        String traceType;
        for (int i = 0; list.hasMoreElements(); i++) {
            traceType = list.nextToken();

            if (traceType.length() == 1 && traceType.charAt(0) >= '0' &&
                    traceType.charAt(0) <= '9') {
                _fTrace = true;
                _iTraceLevel = Integer.parseInt(traceType);
            } else if (traceType.equals(TYPE_GC)) {
                _fTraceGC = true;
                _traceTypes.addElement(traceType);
            } else if (traceType.equals(TYPE_LDAP)) {
                _fTraceLdap = true;
                _traceTypes.addElement(traceType);
            } else if (traceType.equals(TYPE_JSS)) {
                _fTraceJSS = true;
                _traceTypes.addElement(traceType);
            } else if (traceType.equals(TYPE_HTTP)) {
                _fTraceHttp = true;
                _traceTypes.addElement(traceType);
            } else if (traceType.equals(TYPE_RSPTIME)) {
                _fTraceTime = true;
                _showFlags |= SHOW_TIMESTAMP;
                _traceTypes.addElement(traceType);
                if (_appStartTimeStamp > 0) {
                    System.out.println( _timeFormat.format(
                            new Date(_appStartTimeStamp)) + " JVM Loaded");
                    _lastTimeStamp = _appStartTimeStamp;
                }
            } else if (traceType.equals(TYPE_NOJARS)) {
            	_fNoJars = true;
                _traceTypes.addElement(traceType);
            } else {
                // Bad trace type
                System.err.println("Bad trace type: " + traceType);
                return false;
            }
        }

        if (_traceTypes.size() == 0) {
            _traceTypes = null;
        }

        if (flags == null)
            return true;

        list = new StringTokenizer(flags, ",");
        for (int i = 0; list.hasMoreElements(); i++) {
            String flag = list.nextToken();
            if (flag.equals("idx")) {
                _showFlags |= SHOW_INDEX;
            } else if (flag.equals("lvl")) {
                _showFlags |= SHOW_DEBUGLEVEL;
            } else if (flag.equals("ts")) {
                _showFlags |= SHOW_TIMESTAMP;
            } else if (flag.equals("cls")) {
                _showCaller = 1; // short mode
            } else if (flag.equals("clf")) {
                _showCaller = 2; // full mode

            } else if (flag.equals("cs")) {
                _fPrintCallStack = true;
            } else if (flag.equals("all")) {
                _showFlags |= 0xFF;
                _showCaller = 1; // short mode
            }
            else if (flag.startsWith("on") && flag.length() > 3) {
                StringTokenizer patternList =
                        new StringTokenizer(flag.substring(3),
                        String.valueOf(flag.charAt(2)));
                if (_onFilter == null)
                    _onFilter = new Vector();
                while (patternList.hasMoreElements()) {
                    String pattern = patternList.nextToken();
                    _onFilter.addElement(pattern);
                }
            } else if (flag.startsWith("off") && flag.length() > 4) {
                StringTokenizer patternList =
                        new StringTokenizer(flag.substring(4),
                        String.valueOf(flag.charAt(3)));
                if (_offFilter == null)
                    _offFilter = new Vector();
                while (patternList.hasMoreElements()) {
                    String pattern = patternList.nextToken();
                    _offFilter.addElement(pattern);
                }
            } else {
                System.err.println("Bad trace flag: " + flag);
                return false;
            }
        }
        return true;

    }

    public static String getUsage() {
        String usage = "\n-D option format: -D [<type1,type2,...>][:<flag1,flag2,...]";
        usage += "\nPredefined Debug Types:";
        usage += "\nn\t\tDebug level  0<=n<=9, 0 = min info, 9 = max info";
        usage += "\n"+TYPE_LDAP + "\t\tLDAP Calls";
        usage += "\n"+TYPE_JSS + "\t\tJSS Calls";
        usage += "\n"+TYPE_HTTP + "\t\tHTTP Calls";
        usage += "\n"+TYPE_GC + "\t\tGarbage Collection";
        usage += "\n"+TYPE_RSPTIME + "\t\tResponse Time";
        usage += "\n"+TYPE_NOJARS + "\t\tno jar files - for debuggers";
        usage += "\nDebug Flags:";
        usage += "\nidx\t\tEnumerate debug entries";
        usage += "\nlvl\t\tShow debug level for debug entries";
        usage += "\nts\t\tTime stamp debug entries, format Hour:Minute:Second.Milliseconds";
        usage += "\ncls\t\tShow caller short mode: (file:line)";
        usage += "\nclf\t\tShowCaller full mode: package.metod(file:line)";
        usage += "\nall\t\tShortcut for enabling idx,lvl,ts,cls";
        usage += "\ncs\t\tPrint call stack for each debug entry";
        usage += "\non<list>\tShow only entries that contain strings in the filter <list>";
        usage += "\noff<list>\tDo not show entries that contain strings in the filter <list>";
        usage += "\n\t\ton/off filter <list> list has the format";
        usage += "\n\t\t  X<string1>[X<string2>X<string3>...] ";
        usage += "\n\t\twhere X is the list entry separator character.";
        usage += "\nExamples:";
        usage += "\n\t\t-D 9:all";
        usage += "\n\t\t-D ldap,http:idx";
        usage += "\n\t\t-D \":cls,on@HttpChannel,off@send>\"";

        return usage;
    }

    /**
     * Initialize time stamp with the application start time
     * @param t0  application start time in milliseconds
     */
    public static void setApplicationStartTime(long t0) {
        _appStartTimeStamp = t0;
    }

    /**
     * Return application start time if set
     * @return  application start time
     */
    public static long getApplicationStartTime() {
        return _appStartTimeStamp;
    }

    /**
     * Returns a liste of enabled trace types
     * @return  trace type list
     */
    public static Vector getTraceTypes() {
        return _traceTypes;
    }

    /**
     * Check the trace type by name if enabled. Note that predefined
     * trace types have associated methods for checking if enabled.
     * @param type a trace type
     * @return  flag whether the trace type is enabled
     */
    public static boolean isTraceTypeEnabled(String type) {
        if (_traceTypes == null)
            return false;
        for (int i = 0; i < _traceTypes.size(); i++) {
            if (((String)_traceTypes.elementAt(i)).startsWith(type))
                return true;
        }
        return false;
    }

    /**
     * Check wheter the text is matched against the filter list
     * Used for on/off filter
     */
    private static boolean isInFilterList(Vector list, String text) {
        if (list == null)
            return false;
        for (int i = 0; i < list.size(); i++) {
            String filter = (String) list.elementAt(i);
            if (text.indexOf(filter) >= 0)
                return true;
        }
        return false;
    }

    /**
      * Create a prefix for a debug entry. Modify _iEntryIndex and
      * _lastTimeStamp accordingly
      */
    private static String getEntryPrefix(int level) {
        if ((_showFlags &
                (SHOW_INDEX | SHOW_DEBUGLEVEL | SHOW_TIMESTAMP)) == 0)
            return "";

        _iEntryIndex++;
        String prefix = "";

        if ((_showFlags & (SHOW_INDEX | SHOW_TIMESTAMP)) ==
                (SHOW_INDEX | SHOW_TIMESTAMP)) {
            prefix = _iEntryIndex + " ";
        } else if ((_showFlags & SHOW_INDEX) != 0) {
            prefix += _iEntryIndex;
        }
        if ((_showFlags & SHOW_TIMESTAMP) != 0) {
            long t0 = System.currentTimeMillis();
            prefix += _timeFormat.format(new Date(t0));
            if (_lastTimeStamp != 0) {
                // Add delta time
                prefix += " (" + (t0 - _lastTimeStamp) / 1000. + ")";
            }
            _lastTimeStamp = t0;
        }
        if ((_showFlags & SHOW_DEBUGLEVEL) != 0) {
            if (level >= 0)
                prefix += " L"+level;
        }
        return prefix + " ";
    }

    /**
     * Debug statement specifying what trace type to println.
     * @param type  trace type
     * @param s      debug statement
     */
    public static void println(String type, String s) {
        if (_traceTypes != null && isTraceTypeEnabled(type)) {
            if (_showCaller > 0) {
                s = getCaller(_showCaller == 1) + " " + s;
            }
            if (_showFlags != 0) {
                System.err.println(getEntryPrefix(-1) + s);
            } else {
                System.err.println(s);
            }
            if (_fPrintCallStack) {
                Thread.currentThread();
                Thread.dumpStack();
            }
        }
    }

    /**
     * Debug statement specifying what trace type to print.
     * @param level  trace level
     * @param s      debug statement
     */
    public static void print(String type, String s) {
        if (_traceTypes != null && isTraceTypeEnabled(type)) {
            if (_showCaller > 0) {
                s = getCaller(_showCaller == 1) + " " + s;
            }
            if (_showFlags != 0) {
                System.err.print(getEntryPrefix(-1) + s);
            } else {
                System.err.print(s);
            }
            if (_fPrintCallStack) {
                Thread.currentThread();
                Thread.dumpStack();
            }
        }
    }

    /**
     * Default debug statement indicates trace level of 5.
     * @param s  debug statement
     */
    public static void println(String s) {
        println(5, s);
    }

    /**
     * Default debug statement indicates trace level of 5.
     * @param s  debug statement
     */
    public static void print(String s) {
        print(5, s);
    }

    /**
     * Debug statement specifying at which level to print.
     * @param level  trace level
     * @param s      debug statement
     */
    public static void println(int level, String s) {
        if (_fTrace && _iTraceLevel >= level) {
            if (_showCaller > 0) {
                s = getCaller(_showCaller == 1) + " " + s;
            }

            if (_offFilter != null && isInFilterList(_offFilter, s)) {
                return; // disabled
            }
            if (_onFilter != null && !isInFilterList(_onFilter, s)) {
                return; // disabled
            }

            if (_showFlags != 0) {
                System.err.println(getEntryPrefix(level) + s);
            } else {
                // Don't show password even in the debug print
                // supported patterns
                // ...ConsoleInfo(fqdn, port, adminDN, password, suffix) ...
                // ... username=cn=Directory Manager password=password
                // CHANGE PWD TO new_password
                // ...change-sie-password?new_password)
                // ...change-sie-password?new_password
                // ...change-sie-password?new_password 0
                // ...new credentials are <cn=Directory Manager> <password>
                // ... {type='userPassword', values='new_password'} for ...
                // ... {type='nsslapd-rootpw', values='new_password'}} to ...
                // ... {type='userpassword', values='password'} ...
                StringBuilder debugStr = new StringBuilder(s);
                if (s.contains("ConsoleInfo(")) {
                    // ...ConsoleInfo(fqdn, port, adminDN|cn=directory manager, password, suffix) ...
                    int start = debugStr.indexOf("ConsoleInfo(");
                    start = debugStr.indexOf(",", ++start);
                    start = debugStr.indexOf(",", ++start);
                    start = debugStr.indexOf(",", ++start);
                    int end = debugStr.indexOf(",", ++start);
                    if ((start > 0) && (end > 0)) {
                        debugStr.replace(start + 1, end, "***password***");
                    }
                } else if (s.contains("password=")) {
                    // ... username=cn=Directory Manager password=password
                    int start = debugStr.indexOf("password=");
                    start += 9;
                    int end = debugStr.length();
                    if ((start > 0) && (end > 0)) {
                        debugStr.replace(start, end, "***password***");
                    }
                } else if (s.contains("CHANGE PWD TO")) {
                    // CHANGE PWD TO new_password
                    int start = debugStr.indexOf("TO");
                    start = debugStr.indexOf(" ", ++start);
                    int end = debugStr.length();
                    if ((start > 0) && (end > 0)) {
                        debugStr.replace(++start, end, "***password***");
                    }
                } else if (s.contains("change-sie-password?")) {
                    // ...change-sie-password?new_password)
                    // ...change-sie-password?new_password 0
                    // ...change-sie-password?new_password
                    int start = debugStr.indexOf("change-sie-password?");
                    start += 20;
                    int end = debugStr.indexOf(")", start);
                    if ((start > 0) && (end > 0)) {
                        debugStr.replace(start, end, "***password***");
                    } else {
                        end = debugStr.indexOf("0", start);
                        if ((start > 0) && (end > 0)) {
                            end -= 1;
                            debugStr.replace(start, end, "***password***");
                        } else {
                            end = debugStr.length();
                            if (start > 0) {
                                debugStr.replace(start, end, "***password***");
                            }
                        }
                    }
                } else if (s.contains("new credentials are <")) {
                    // ...new credentials are <cn=Directory Manager> <password>
                    int start = debugStr.indexOf("new credentials are <");
                    start += 21;
                    start = debugStr.indexOf("<", ++start);
                    int end = debugStr.indexOf(">", ++start);
                    if ((start > 0) && (end > 0)) {
                        debugStr.replace(start, end, "***password***");
                    }
                } else if (s.contains("type='userpassword',") ||
                           s.contains("type='userPassword',")) {
                    // ... {type='userPassword', values='new_password'} for ...
                    // ... {type='userpassword', values='password'} ...
                    int start = debugStr.indexOf("type='user");
                    start += 20;
                    start = debugStr.indexOf("'", start);
                    int end = debugStr.indexOf("'", ++start);
                    if ((start > 0) && (end > 0)) {
                        debugStr.replace(start, end, "***password***");
                    }
                } else if (s.contains("type='nsslapd-rootpw',")) {
                    // ... {type='nsslapd-rootpw', values='new_password'}} to ...
                    int start = debugStr.indexOf("type='nsslapd-rootpw',");
                    start += 22;
                    start = debugStr.indexOf("'", start);
                    int end = debugStr.indexOf("'", ++start);
                    if ((start > 0) && (end > 0)) {
                        debugStr.replace(start, end, "***password***");
                    }
                }
                System.err.println(debugStr);
            }

            if (_fPrintCallStack) {
                Thread.currentThread();
                Thread.dumpStack();
            }
        }
    }

    /**
     * Debug statement specifying at which level to print.
     * @param level  trace level
     * @param s      debug statement
     */
    public static void print(int level, String s) {
        if (_fTrace && _iTraceLevel >= level) {
            if (_showCaller > 0) {
                s = getCaller(_showCaller == 1) + " " + s;
            }

            if (_offFilter != null && isInFilterList(_offFilter, s)) {
                return; // disabled
            }
            if (_onFilter != null && !isInFilterList(_onFilter, s)) {
                return; // disabled
            }

            if (_showFlags != 0) {
                System.err.print(getEntryPrefix(level) + s);
            } else {
                System.err.print(s);
            }
            if (_fPrintCallStack) {
                Thread.currentThread();
                Thread.dumpStack();
            }
        }
    }

    /**
     * Default debug statement indicates trace level of 5.
     * @param s  debug statement
     */
    public static void println(int s) {
        println(5, "" + s);
    }

    /**
     * Default debug statement indicates trace level of 5.
     * @param s  debug statement
     */
    public static void print(int s) {
        print(5, "" + s);
    }

    /**
     * Debug statement specifying at which level to print.
     * @param level  trace level
     * @param s      debug statement
     */
    public static void println(int level, int s) {
        println(level, "" + s);
    }

    /**
     * Debug statement specifying at which level to print.
     * @param level  trace level
     * @param s      debug statement
     */
    public static void print(int level, int s) {
        print(level, "" + s);
    }

    /**
      * Return the short class name, no package names
      * @param name full class name
      * @return just the class name, no package names
      */
    public static String getShortClassName(String name) {
        int lastDot = name.lastIndexOf('.');
        return (lastDot >= 0) ? name.substring(lastDot + 1) : name;
    }

    /**
     * Debug statement for hashtable.
     * @param tag  identifying information
     * @param tbl  the hashtable to print
     */
    public static void printHashtable(String tag, Hashtable tbl) {
        if (tag != null && tag.length() != 0) {
            println(" ======== " + tag + " ========");
        }
        for (Enumeration e = tbl.keys(); e.hasMoreElements();) {
            String key = (String) e.nextElement();
            println(key + "=" + tbl.get(key));
        }
    }

    /**
      * Show the Debug method caller
     */
    private static String getCaller(boolean shortMode) {
        ByteArrayOutputStream outBuf = new ByteArrayOutputStream();
        new Exception().printStackTrace(new PrintStream(outBuf));
        DataInputStream inBuf = new DataInputStream(
                new ByteArrayInputStream(outBuf.toByteArray()));

        try {
            String line;
            int lineCount = 0;
            int frameCount = 0;
            while ((line = inBuf.readLine()) != null) {
                lineCount++;
                if (lineCount == 1)
                    continue;
                if (line.indexOf("client.util.Debug") >= 0 ||
                        line.indexOf("client/util/Debug") >= 0)
                    continue;
                if (shortMode) {
                    //return line.substring(line.lastIndexOf('.', line.lastIndexOf('(')) +1);
                    return line.substring(line.lastIndexOf('('));
                } else {
                    return line.trim().substring(3);
                }
            }
        } catch (Exception e) {}
        return "";
    }
}
