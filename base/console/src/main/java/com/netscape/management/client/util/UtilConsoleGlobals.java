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

import javax.swing.JFrame;
import java.net.URL;
import java.net.MalformedURLException;
import netscape.ldap.factory.JSSSocketFactory;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.AlreadyInitializedException;
import java.security.cert.CertificateFactory;
import com.netscape.management.client.preferences.FilePreferenceManager;
import netscape.ldap.*;

/**
 * UtilConsoleGlobals maintains globally accessed variables which are needed
 * for window management and keeping track of the administration server URL.
 * Window management includes keeping track of the main Console window,
 * which is needed to redisplay the Console if it has been closed; keeping
 * track of the number of windows open, which is needed to handle the close
 * menu option such that the last window closed exits the application; and
 * keeping track of the most recently activated frame, which is needed as a
 * parent for a lot of dialogs and other console windows to properly display.
 */
public class UtilConsoleGlobals {

    private static String _adminURL;
    private static String _adminHelpURL;
    private static JFrame _consoleFrame;
    private static JFrame _activatedFrame;
    private static int _windowCount = 0;
    private static JFrame _rootTopologyFrame;
    private static boolean _doServerAuth = false;
    private static boolean _contextHelp = true;
    private static LDAPSocketFactory _socketFactory;
    private static CertificateFactory _certFactory;
    

    /**
     * Enable or disable context-sensitive help<P>
     * Note: This should be set from the Console class when logging
     * in to an Admin Server; <CODE>true</CODE> if 4.5 or later,
     * otherwise <CODE>false</CODE>.
     *
     * @param enable <CODE>true</CODE> to enable context-sensitive help
     */
    public static void setContextHelpEnabled(boolean enable) {
        _contextHelp = enable;
    }

    /**
     * Report if context-sensitive help is enabled
     *
     * @return <CODE>true</CODE> if context-sensitive help is enabled
     */
    public static boolean isContextHelpEnabled() {
        return _contextHelp;
    }

    /**
     * Enable or disable server authentication
     *
     * @param enable enable server auth
     */
    public static void setServerAuthEnabled(boolean enable) {
        _doServerAuth = enable;
    }

    /**
      *
      * @return true server auth is enabled
      */
    public static boolean isServerAuthEnabled() {
        return _doServerAuth;
    }

    
    public static LDAPSocketFactory getLDAPSSLSocketFactory() {
        initJSS();        
        if (_socketFactory == null) {
            try {
                _socketFactory = new JSSSocketFactory();
            }
            catch (Exception e) {
                Debug.println("Unable to create a JSS ldap socket factory " + e);
            }
        }
        return _socketFactory;
    }

    public static CertificateFactory getX509CertificateFactory() {
        initJSS();
        return _certFactory;
    }

    public static synchronized void initJSS() {
        if (_certFactory != null) {
            return; // already initialized
        }
    
        try { 
            /* WARNING by Shih Ming! Must obtain all the sun provider stuff before 
               executing any jss code.  JSS is also a provider (broken one)
               which will clobber with the default one provided by sun */
            _certFactory = CertificateFactory.getInstance("X.509");
           
            try {
                String homePath = FilePreferenceManager.getHomePath();
                // CryptoManager.initialize(homePath+"/secmod.db", homePath+"/key3.db", homePath+"/cert7.db");
                CryptoManager.initialize(homePath);
            }
            catch (AlreadyInitializedException initialized) {}

        } catch (RuntimeException e) {
            throw e;

        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }
    
    /**
      * Sets the URL for the administration server for serving up Help.
      *
      * @param adminURL  the string URL for the administration server
      */
    public static void setAdminHelpURL(String adminURL) {
        _adminHelpURL = adminURL;
    }


    /**
      * Retrieves the URL for the administration server for serving up Help.
      *
      * @return  the URL for the administration server
      */
    public static URL getAdminHelpURL() {
        URL url;
        try {
            url = new URL(_adminHelpURL);
        } catch (MalformedURLException e) {
            Debug.println(0,
                    "Invalid URL passed to Console.  Exception " + e);
            return null;
        }
        return url;
    }


    /**
      * Sets the URL for the administration server.
      *
      * @param adminURL  the string URL for the administration server
      */
    public static void setAdminURL(String adminURL) {
        _adminURL = adminURL;
    }


    /**
      * Retrieves the URL for the administration server.
      *
      * @return  the URL for the administration server
      */
    public static URL getAdminURL() {
        URL url;
        try {
            url = new URL(_adminURL);
        } catch (MalformedURLException e) {
            Debug.println(0,
                    "Invalid URL passed to Console.  Exception " + e);
            return null;
        }
        return url;
    }


    /**
      * Sets the root frame. The root frame is the main Console frame
      * which pops up when the application is started.
      *
      * @param frame  the root frame
      */
    public static void setRootFrame(JFrame frame) {
        _consoleFrame = frame;
    }


    /**
      * Retrieves the root frame.
      *
      * @return  the root frame
      */
    public static JFrame getRootFrame() {
        return _consoleFrame;
    }


    /**
      * Sets the most recently activated frame. This is synchronized to avoid
      * any conflicts with setClosingFrame(JFrame).
      *
      * @param frame  the active frame
      * @see #setClosingFrame(JFrame)
      */
    public static synchronized void setActivatedFrame(JFrame frame) {
            _activatedFrame = frame;
        }


    /**
      * Retrieves the most recently activated frame.
      *
      * @return  the active frame
      */
    public static synchronized JFrame getActivatedFrame() {
            return _activatedFrame;
        }


    /**
      * This is a work around for OpenWindows. In OpenWindows, the main Console
      * never receives a windowActivated() event. As a result, the activated
      * frame remains whichever server Console was last activated. The problem
      * arises when this last activated frame is dismissed. Even though it is
      * no longer available, the activated frame is still the dismissed frame.
      * When a new Console is launched, the wrong activated frame is returned by
      * this class, causing exception errors. To work around this problem, this
      * method has been added and is called when a console frame is closed. By
      * setting the activated frame to null, this allows the application to
      * return to a valid state when an activated frame is dismissed. This method
      * is synchronized to avoid any problems with setActivatedFrame(JFrame).
      *
      * @param frame  the closing frame
      * @see #setActivatedFrame(JFrame)
      */
    public static synchronized void setClosingFrame(JFrame frame) {
            if (_activatedFrame == frame) {
                _activatedFrame = null;
            }
        }


    /**
      * Retrieves a count of open windows. Used by Framework.
      *
      * @return  count of open windows
      */
    public static int getWindowCount() {
        return _windowCount;
    }


    /**
      * Sets the count of open windows.
      *
      * @param c  count of open windows
      */
    public static int setWindowCount(int c) {
        return _windowCount = c;
    }


    /**
      * Increments the open window count.
      *
      * @return  updated count of open windows
      */
    public static int incrementWindowCount() {
        return ++_windowCount;
    }


    /**
      * Decrements the open window count.
      *
      * @return  updated count of open windows
      */
    public static int decrementWindowCount() {
        return --_windowCount;
    }


    /**
      * Sets the root topology window. Used by Framework to track the root topology window.
      *
      * @param f  the root topology window
      */
    public static void setRootTopologyFrame(JFrame f) {
        _rootTopologyFrame = f;
    }


    /**
      * Retrieves the root topology window. Used by Framework to track the root topology window.
      *
      * @return  the root topology window
      */
    public static JFrame getRootTopologyFrame() {
        return _rootTopologyFrame;
    }
}
