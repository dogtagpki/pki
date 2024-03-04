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
package com.netscape.management.client.cmd;


import java.util.Hashtable;
import java.util.Vector;


/**
 * CommandLineParser provides functions similar to the UNIX getopt. This
 * class requires an array of control strings to parse the command line.
 * The control string must have the following format:
 * <p>
 * <code>-option[:]</code>
 * <p>
 * Example control strings include:
 * <ul>
 * <li><code>-help:</code>
 * <li><code>-version</code>
 * <li><code>-verbose:</code>
 * </ul>
 * <p>
 * The '-' is required to denote that the argument is an option tag. It is
 * followed by the name of the option. The optional ':' indicates whether
 * the option requires another parameter. Each individual program is
 * responsible for deciding whether it is an error for an option ending
 * with : to not have a parameter. All control strings must be lower case.
 * <p>
 * Enhancements over the Java GetOpt class includes:
 * <ul>
 * <li>handle space separated parameters if enclosed in matching quotes
 * <li>handle backslash character as the shell escape charater
 * <li>handle descriptive option tags as well as single character tags.
 * </ul>
 *
 * @version  %I%, %G%
 * @author   Terence Kwan
 * @author   Peter Lee
 * @see      GetOpt
 */

public class CommandLineParser extends Object {

    protected static final String KEY_VALUE = "1";
    protected static final String REQUIRES_PARAMETER_INDICATOR = ":";
    protected static final String EMPTY_STRING = "";

    protected Vector _unmatchedParameters;
    protected Hashtable _options;
    protected Hashtable _optionParameters;


    /**
     * Class constructor which parses the specified arguments using the
     * specified control strings. The options are distinguishable by the
     * leading '-'. Options specified in <code>args</code> are compared
     * against the valid options provided in <code>controls</code>. Since
     * options do not have to be fully qualified, a best match comparison
     * is performed using <code>getOptionIndex</code>. If duplicate options
     * are found or the specified option does not exist, an error message
     * is displayed and the program is exited.
     * <p>
     * If the specified option is valid, the complete option is retrieved
     * from <code>controls</code> and stored to indicate that the option
     * has been specified. If the option ends with ':', the next argument
     * is read as the parameter for the option. It is NOT an error if the
     * parameter is not specified. The code using this class should determine
     * for itself whether the parameter is required. This allows optional
     * parameters to be specified. If the parameter exists, it is stored as
     * to indicate that the option and parameter pair has been specified.
     * <p>
     * The parameters starting with \, ', and " are handled as special cases.
     * The leading \ character is ignored as a shell escape character. The
     * leading ' and " characters indicate that there may be 0 or more
     * additional arguments that must be looked at to determine the end of
     * the parameter. Mismatched ' or " characters result in an error
     * message and program exit.
     *
     * @param controls  an array of strings used to parse <code>args</code>
     * @param args      an array of strings to be parsed
     * @return          CommandLineParser object with parsed arguments
     */
    public CommandLineParser(String[] controls, String[] args) {
        _options = new Hashtable();
        _optionParameters = new Hashtable();
        _unmatchedParameters = new Vector();

        int optionIndex;
        String option;
        String optionKey;
        String parameter;
        for (int i = 0; i < args.length; i++) {
            option = args[i];
            if (option.charAt(0) == '-') {
                optionIndex = getOptionIndex(controls, option);
                if (optionIndex == -1) {
                    System.err.println(
                            "ERROR CommandLineParser: unknown or ambiguous option: " +
                            args[i]);
                    System.exit(-1);
                }

                optionKey = controls[optionIndex];
                _options.put(optionKey, KEY_VALUE); // generic value to indicate that option was provided.
                if (optionKey.endsWith(REQUIRES_PARAMETER_INDICATOR)) {
                    // Read the next argument as the parameter for the option.
                    // Note the need for optional parameter. Don't flag error
                    // here. Let the user of this class deal with that.
                    i++;

                    // Make sure we are not at the end of the arg list.
                    if (i < args.length) {
                        parameter = args[i];
                        if (parameter.charAt(0) == '-') {
                            // Next argument is another option.
                            // Reset for next iteration.
                            i--;
                        } else {
                            // Handle quotes and back slashes
                            if (parameter.charAt(0) == '"') {
                                if (i < args.length) {
                                    if (parameter.endsWith("\"")) {
                                        parameter = parameter.substring(1,
                                                parameter.length() - 1);
                                    } else {
                                        parameter = parameter.substring(1);
                                        String nextParam;
                                        if (i + 1 < args.length) {
                                            do {
                                                i++;
                                                nextParam = args[i];
                                                if (nextParam.endsWith("\"")) {
                                                    parameter = parameter +
                                                            " " + nextParam.substring(
                                                            0, nextParam.length()
                                                            - 1);
                                                } else {
                                                    parameter = parameter +
                                                            " " + nextParam;
                                                }
                                            } while ( (nextParam.endsWith(
                                                    "\"") == false) &&
                                                    (i < args.length))
                                                ;
                                        }
                                    }
                                }
                                if (i == args.length) {
                                    System.err.println("ERROR CommandLineParser: unmatched \"");
                                    System.exit(-1);
                                }
                            } else if (parameter.charAt(0) == '\'') {
                                if (i < args.length) {
                                    if (parameter.endsWith("'")) {
                                        parameter = parameter.substring(1,
                                                parameter.length() - 1);
                                    } else {
                                        parameter = parameter.substring(1);
                                        String nextParam;
                                        if (i + 1 < args.length) {
                                            do {
                                                i++;
                                                nextParam = args[i];
                                                if (nextParam.endsWith("'")) {
                                                    parameter = parameter +
                                                            " " + nextParam.substring(
                                                            0, nextParam.length()
                                                            - 1);
                                                } else {
                                                    parameter = parameter +
                                                            " " + nextParam;
                                                }
                                            } while ( (nextParam.endsWith(
                                                    "'") == false) &&
                                                    (i < args.length))
                                                ;
                                        }
                                    }
                                }
                                if (i == args.length) {
                                    System.err.println("ERROR CommandLineParser: unmatched '");
                                    System.exit(-1);
                                }
                            } else if (parameter.charAt(0) == '\\') {
                                if (parameter.length() > 1) {
                                    parameter = parameter.substring(1);
                                } else {
                                    parameter = EMPTY_STRING;
                                }
                            }
                            _optionParameters.put(optionKey, parameter);
                        }
                    }
                }
            } else {
                // Parameter with no matching option.
                // Handle quotes and back slashes
                if (option.charAt(0) == '"') {
                    if (i < args.length) {
                        if (option.endsWith("\"")) {
                            option = option.substring(1,
                                    option.length() - 1);
                        } else {
                            option = option.substring(1);
                            String nextParam;
                            if (i + 1 < args.length) {
                                do {
                                    i++;
                                    nextParam = args[i];
                                    if (nextParam.endsWith("\"")) {
                                        option = option + " " +
                                                nextParam.substring(0,
                                                nextParam.length() - 1);
                                    } else {
                                        option = option + " " + nextParam;
                                    }
                                } while ( (nextParam.endsWith("\"") ==
                                        false) && (i < args.length))
                                    ;
                            }
                        }
                    }
                    if (i == args.length) {
                        System.err.println("ERROR CommandLineParser: unmatched \"");
                        System.exit(-1);
                    }
                } else if (option.charAt(0) == '\'') {
                    if (i < args.length) {
                        if (option.endsWith("'")) {
                            option = option.substring(1,
                                    option.length() - 1);
                        } else {
                            option = option.substring(1);
                            String nextParam;
                            if (i + 1 < args.length) {
                                do {
                                    i++;
                                    nextParam = args[i];
                                    if (nextParam.endsWith("'")) {
                                        option = option + " " +
                                                nextParam.substring(0,
                                                nextParam.length() - 1);
                                    } else {
                                        option = option + " " + nextParam;
                                    }
                                } while ( (nextParam.endsWith("'") ==
                                        false) && (i < args.length))
                                    ;
                            }
                        }
                    }
                    if (i == args.length) {
                        System.err.println("ERROR CommandLineParser: unmatched '");
                        System.exit(-1);
                    }
                } else if (option.charAt(0) == '\\') {
                    if (option.length() > 1) {
                        option = option.substring(1);
                    } else {
                        option = EMPTY_STRING;
                    }
                }
                _unmatchedParameters.addElement(option);
            }
        }
    }


    /**
      * Retrieves the index of the specified option in the controls string
      * array. The search is for best match meaning that the control string
      * has to only start with the specifed option. This may result in
      * duplicates, in which case -1 is returned to indicate the ambiguous
      * option.
      *
      * @param controls  an array of strings to compare for <code>option</code>
      * @param option    the string to look up in <code>controls</code>
      * @return          an integer indicating the index of the option;
      *                  -1 if not found or if duplicates found
      */
    protected int getOptionIndex(String[] controls, String option) {
        int count = 0;
        int index = -1;
        String optionLowerCase = option.toLowerCase();

        for (int i = 0; i < controls.length; i++) {
            if (controls[i].startsWith(optionLowerCase)) {
                count++;
                index = i;
            }
        }

        if (count == 0 || count > 1) {
            return -1;
        }

        return index;
    }


    /**
      * Looks up whether an option has been specified.
      *
      * @param key  the string indicating the option to be checked
      * @return     <code>true</code> if the option is present;
      *             <code>false</code> otherwise
      */
    public boolean hasOption(String key) {
        if (_options.get(key) == KEY_VALUE) {
            return true;
        }
        return false;
    }


    /**
      * Retrieves the parameter for the specified option.
      *
      * @param key  the string indicating the option whose parameter is desired
      * @return     the string parameter for the option; <code>null</code> if
      *             the parameter or the option was not specified
      */
    public String getOptionParam(String key) {
        return (String)_optionParameters.get(key);
    }


    /**
      * Gets all unmatched parameters. Unmatched parameters refer to those
      * parameters that do not have a matching option.
      *
      * @return  an array of strings of unmatched parameters
      */
    public String[] getUnmatchedParameters() {
        if (_unmatchedParameters.size() == 0) {
            return null;
        }

        String[] ups = new String[_unmatchedParameters.size()];
        _unmatchedParameters.copyInto(ups);
        return ups;
    }
}
