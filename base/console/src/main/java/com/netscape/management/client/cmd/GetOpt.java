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


import java.util.*;


/**
 * GetOpt provides functions similar to the UNIX getopt. The programmer
 * needs to specify a control string for parsing the command line. An
 * example control string is "s:phy:", which indicates that the command
 * will take options "s", "p", "h" and "y". Furthermore, options "s" and "y"
 * may have an additional argument, as indicated by the ":" after the option
 * character. Whether the argument is required for a particular option is up
 * to the programmer to decide.
 * <p>
 * Changed 01/30/1998 by phlee.
 * Only the UNIX style of specifying an option ('-') will be supported. NT
 * style which uses '/' conflicts with the ability to specify full path
 * names in UNIX.
 *
 * @version  %I%, %G%
 * @author   Terence Kwan
 * @author   Peter Lee
 * @see      CommandLineParser
 */

public class GetOpt extends Object {

    /**
     * Internal variables
     */
    private String _control;
    private Vector _option;
    private Vector _parameterList;
    private Hashtable _optionHashTable;
    private Hashtable _optionParamHashTable;



    /**
     * Constructs an object which gets options.
     *
     * @param controlString  string which specifies all possible options
     * @param args           an arry of strings representing the arguments
     *                       to be parsed
     * @return               GetOpt object with parsed arguments
     */
    public GetOpt(String controlString, String args[]) {

        _option = new Vector();
        _control = controlString;
        _optionHashTable = new Hashtable();
        _optionParamHashTable = new Hashtable();
        _parameterList = new Vector();

        for (int i = 0; i < args.length; i++) {
            String option = args[i];
            if (option.length() > 0) {
                if (option.charAt(0) == '-') {
                    // Support only UNIX style options.
                    if (option.length() == 2) {
                        // Check for valid option.
                        int optionIndex =
                                _control.indexOf(option.charAt(1));
                        if (optionIndex == (-1)) {
                            System.err.println("Unknown option: " +
                                    option.charAt(1));
                        } else {
                            char optionChar[] = new char[1];
                            optionChar[0] = option.charAt(1);
                            String optionKey = new String(optionChar);
                            _optionHashTable.put(optionKey, "1"); // generic value.
                            if (_control.length() > (optionIndex + 1)) {
                                if (_control.charAt(optionIndex + 1) ==
                                        ':') {
                                    i++;
                                    // Check that the option was provided with a parameter!
                                    if (i < args.length) { // End of arg list?
                                        if (args[i].charAt(0) != '-') {
                                            _optionParamHashTable.put(
                                                    optionKey, args[i]);
                                        } else {
                                            // Next argument is for a different option.
                                            // Reset for next iteration.
                                            i--;
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        // Currently supports only single characters to specify the
                        // desired option. However, allow users to specify complete
                        // option name, such as "-help". Only the first character
                        // of the option will be parsed, i.e. "h" for "-help".
                    }
                } else {
                    // Parameter with no matching option.
                    _parameterList.addElement(args[i]);
                }
            }
        }
    }



    /**
      * Looks up whether an option has been specified.
      *
      * @param c  the character representing the option to be checked
      * @return   <code>true</code> if the option is present;
      *           <code>false</code> otherwise
      */
    public boolean hasOption(char c) {

        char optionChar[] = new char[1];
        optionChar[0] = c;
        String key = new String(optionChar);
        if (_optionHashTable.get(key) == "1") {
            return true;
        }
        return false;
    }



    /**
      * Retrieves the parameter for the specified option.
      *
      * @param c  the character representing the option whose parameter is desired
      * @return   the string parameter for the option; <code>null</code> if
      *           the parameter or the option was not specified
      */
    public String getOptionParam(char c) {

        char optionChar[] = new char[1];
        optionChar[0] = c;
        String key = new String(optionChar);
        return (String)_optionParamHashTable.get(key);
    }



    /**
      * Gets all unmatched parameters. Unmatched parameters refer to those
      * parameters that do not have a matching option.
      *
      * @return  a vector of strings of unmatched parameters
      */
    public Vector getParameters() {

        return _parameterList;
    }
}
