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
import java.net.URL;
import java.util.Properties;
import com.netscape.management.nmclf.*;


/**
 * Provides functionality to invoking a browser using
 * a specified URL.  For NT, the invokation of the
 * browser is dependant on a utility called
 * viewurl.exe, which is expected to be in
 * "../bin/base" relative to the current working directory.
 *
 * @author atulb
 */
public class Browser {

    public static final int OS_WINNT = 1;
    public static final int OS_UNIX = 2;
    public static final int NEW_WINDOW = 3;
    public static final int EXISTING_WINDOW = 4;

    private ResourceSet _resource = new ResourceSet("com.netscape.management.client.util.default");

    //assumes the point of execution to be <ServerRoot>/java
    protected static final String DEFAULT_NT_BROWSER = "../bin/base/viewurl.exe";
    protected static final String FALLBACK_NT_BROWSER = "rundll32 url.dll,FileProtocolHandler";
    protected static final String DEFAULT_UNIX_BROWSER = "firefox";
    protected static final String FALLBACK_UNIX_BROWSER = "mozilla";
    protected String window_name = null;
    String executable;
    String osName;

    /**
     *  constructor
     */
    public Browser() {
        init();
    }

    /**
      * constructor
      *
      * @param window  name of the window
      */
    public Browser(String window) {
        window_name = window;
        init();
    }

    /**
      * Initializes the object. Sets browser depending upon the OS.
      */
    private void init() {
        Properties p = System.getProperties();
        osName = new String(p.getProperty("os.name"));
        Debug.println("Browser: osName is " + osName);
        if (osName.startsWith("Windows")) {
            File viewurl = new File(DEFAULT_NT_BROWSER);
            if (!viewurl.exists()) {
                Debug.println(0,
                        "Browser: Did not find " +
                        DEFAULT_NT_BROWSER + " using instead rundll32 url.dll");
                executable = new String(FALLBACK_NT_BROWSER);
            } else {
                executable = new String(DEFAULT_NT_BROWSER);
            }
        } else {
	    /* Check path for default browser */
            if (!checkBrowser(DEFAULT_UNIX_BROWSER)) {
                Debug.println(0, "Browser: Did not find " + DEFAULT_UNIX_BROWSER);
                Debug.println(0, "Browser: Falling back to " + FALLBACK_UNIX_BROWSER);
                executable = new String(FALLBACK_UNIX_BROWSER);
            } else {
                executable = new String(DEFAULT_UNIX_BROWSER);
            }
        }
    }

    /**
      * Sets the browser to be the one path where path is the complete path
      * name of the browser or a relative name relative to <serverRoot>/java.
      *
      * @param path  the full path for the browser executable
      */
    public void setBrowser(String path) {
        executable = path;
    }

    /**
      * Checks the path to see if the browser exists.  Returns
      * true of false.
      *
      * @param executable  the name of the browser executable
      */
    public boolean checkBrowser(String executable) {
        Runtime command = Runtime.getRuntime();

        Debug.println("Attempting to get path\n");
        try {
            /* Get path from env command */
            Process proc = command.exec("env");
            DataInputStream stdout = new DataInputStream(proc.getInputStream());

            try {
                proc.waitFor();
            } catch (InterruptedException e) {
                Debug.println(0, "Exception -> "+e);
                Debug.println("Browser: checkBrowser() returning false");
                return false;
            }

            Debug.println("exit value="+ proc.exitValue());

            if (stdout != null) {
                String line = null;
                String [] paths = null;

                while ((line = stdout.readLine()) != null) {
                    /* Look for PATH environment variable */
                    if (line.startsWith("PATH=") || line.startsWith("Path=")) {
                        paths = line.substring(5).split(":");
                        break;
                    }
                }
                stdout.close();

                /* Check for browser in each path element */
                if (paths != null) {
                    for (int i = 0; i < paths.length; i++) {
                        File my_browser = new File(paths[i] + "/" + executable);
                        if (my_browser.exists()) {
                            Debug.println("Browser: checkBrowser() Found browser " +
                                           executable + " in path " + paths[i]);
                            Debug.println("Browser: checkBrowser() returning true");
                            return true;
                        }
                    }
                } else {
                    Debug.println("Browser: checkBrowser() - Error reading PATH");
                    Debug.println("Browser: checkBrowser() returning false");
                    return false;
                }
            }

        } catch (Exception e) {
            Debug.println(0, "Exception -> "+e);
            Debug.println("Browser: checkBrowser() returning false");
            return false;
        }

        /* Browser was not found in path */
        Debug.println("Browser: checkBrowser() unable to find browser " + executable);
        Debug.println("Browser: checkBrowser() returning false");
        return false;
    }


    /**
      * Gets the value for of browser executable's full path.
      *
      * @return  the value of the path
      */
    public String getBrowser() {
        return executable;
    }

    /**
      * Displays the error message in a Message Dialog
      *
      * @param title    the title of the dialog box
      * @param message  the error message for the dialog box
      */
    private void error(String title, String message) {
        SuiOptionPane.showMessageDialog(
                UtilConsoleGlobals.getActivatedFrame(), message, title,
                SuiOptionPane.ERROR_MESSAGE);
        ModalDialogUtil.sleep();
    }


    /**
      * opens the url in an existing browser window.
      *
      * @param url  the url to be opened in the browser
      * @return     true if successful; false if there were no browser open when
      *             the call was made in which case the url will not be displayed.
      */
    public boolean open(URL url) {
        return open(url.toString(), EXISTING_WINDOW);
    }

    /**
      * opens the url in a new or existing browser window.
      *
      * @param url   the url to be opened in the browser
      * @param mode  which takes values EXISTING_WINDOW or NEW_WINDOW for
      *              opening the url in an existing or a new browser window respectively.
      * @return      true if successful; false if it failed to open the url in a
      *              browser window.
      */
    public boolean open(URL url, int mode) {
        return open(url.toString(), mode);
    }

    /**
      * opens the url in an existing browser window.
      *
      * @param url  the url to be opened in the browser
      * @return     true if successful; false if these was no browser open when
      *             the call was made in which case the url will not be displayed.
      */
    public boolean open(String url) {
        return open(url, EXISTING_WINDOW);
    }

    /**
      * opens the url in a new or existing browser window.
      *
      * @param url   the url to be opened in the browser
      * @param mode  which takes values EXISTING_WINDOW or NEW_WINDOW for
      *              opening the url in an existing or a new browser window respectively.
      * @return      true if successful; false if it failed to open the url in a
      *              browser window.
      */
    public boolean open(String url, int mode) {
        Runtime command = Runtime.getRuntime();
        Process proc = null;
        DataInputStream stderr = null;
        String remStr = "";

        Debug.println("Attempting to bring up browser\n");
        try {
            if (osName.startsWith("Windows")) { // proc = command.exec(executable + ((mode == NEW_WINDOW)? "-newwindow ":"") + url); // bug 333328
                // viewurl.exe does not support newwindow

                // Fallback NT browser doesn't like the 'file:/' in the URL
                if (url.startsWith("file:/")) url = url.substring(6);
                Debug.println("Browser.open:  executing " + executable + " " + url);

                proc = command.exec(executable + " " + url);
            } else {
                if (mode == EXISTING_WINDOW) {
                    Debug.println(executable + " -remote openURL("+
                            url + ",new-tab)");
                    proc = command.exec(executable + " -remote openURL("+
                            url + ",new-tab)");
                    stderr = new DataInputStream(proc.getErrorStream());
                } else {
                    // For Unix try first to create a new tab in a running browser (-remote option)
                    Debug.println(executable + " -remote openURL("+
                            url + ",new-tab)");
                    proc = command.exec(executable + " -remote openURL("+
                            url + ",new-tab)");
                    stderr = new DataInputStream(proc.getErrorStream());
                }

                try {
                    proc.waitFor();
                } catch (InterruptedException e) {
                    Debug.println(0, "Exception -> "+e);
                    error(_resource.getString("browser","error-title"),
                            _resource.getString("browser","interruptionError"));
                    Debug.println("Browser: open() returning false");
                    return false;
                }

                Debug.println("exit value="+ proc.exitValue());

                // Can not trust 100% the exit value
                if (proc.exitValue() == 0) {   
                    // check if anything was sent to stderr
                    if (stderr != null) {
                        String line=null, errText="";
                        while ((line = stderr.readLine()) != null) {
                            if (errText.length() != 0) {
                                errText += "\n";
                            }
                            errText+=line;
                        }
                        stderr.close();
                        if (errText.length() == 0) {
			    Debug.println("Browser: open() returning true");
                            return true; // it was really ok
                        }                        
                        else {
                            Debug.println("stderr text="+ errText);
                        }
                    }
                } else {
                    // Try again in a new window this time
                    Debug.println(executable + " -remote openURL("+
                            url + ",new-window)");
                    proc = command.exec(executable + " -remote openURL("+
                            url + ",new-window)");
                    stderr = new DataInputStream(proc.getErrorStream());

                    try {
                        proc.waitFor();
                    } catch (InterruptedException e) {
                        Debug.println(0, "Exception -> "+e);
                        error(_resource.getString("browser","error-title"),
                                _resource.getString("browser","interruptionError"));
                        Debug.println("Browser: open() returning false");
                        return false;
                    }
                                                                                                                            
                    Debug.println("exit value="+ proc.exitValue());

                    if (proc.exitValue() == 0) {
                        // check if anything was sent to stderr
                        if (stderr != null) {
                            String line=null, errText="";
                            while ((line = stderr.readLine()) != null) {
                                if (errText.length() != 0) {
                                    errText += "\n";
                                }
                                errText+=line;
                            }
                            stderr.close();
                            if (errText.length() == 0) {
                                Debug.println("Browser: open() returning true");
                                return true; // it was really ok
                            } else {
                                Debug.println("stderr text="+ errText);
                            }
                        }
                    }
                }

                // For Unix try once again but without -remote option i.e.
                // try to start the browser
                Debug.println(executable + " " + url);
                proc = command.exec(executable + " " + url);
            }
        } catch (Exception e) {
            Debug.println(0, "Exception -> "+e);
            error(_resource.getString("browser","error-title"),
                  _resource.getString( "browser", "error-nobrowser", executable));
            Debug.println("Browser: open() returning false");
            return false;
        }
        Debug.println("Browser: open() returning true");
        return true;
    }
}
