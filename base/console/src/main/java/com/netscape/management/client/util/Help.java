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

import java.applet.Applet;
import java.net.URL;
import java.util.Locale;

/**
 * Displays help content.
 *
 * Two static methods can be used to invoke help:
 * <code>showHelp</code> and <code>showContextHelp</code>.
 * Each method takes a product id and a help topic as parameters.
 * That information is used to construct an URL, and
 * launch a help viewer (browser or java window) to that URL.
 * See methods for details on when to use each method.
 *
 * Typical usage example:
 * Help.showContextHelp("admin", "preferences-fonts");
 *
 * The usage of this class has changed since Console 4.x.
 *
 * It is no longer necessary to use local property files
 * to specify the 'manual' directory for each product.
 * This has now become a method parameter.
 *
 * It is no longer necessary to specify topics as prefix and name
 * combinations, which were formatted to "prefix-name".
 * Help topic names can now be in any format, however
 * it is recommended that you adopt a consistant
 * format across your product. Suggested format:
 *
 * dialog                      example: login
 * tabbeddialog-tab            example: preferences-fonts
 * wizard-step                 example: certrequest-summary
 * panel-tab                   example: database-backup
 *
 * @author Andy Hakim
 * @author Rob Weltman
 * @author David Tompkins
 * @author Atul Bhandari
 */
public class Help {
    protected static Applet applet = null;
    public static void setApplet(Applet _applet) {
        applet = _applet;
    }
    public ResourceSet tokens = null;
	// Index file for help token lookup in Console 4.5
	static final String MAPFILE = "tokens.map";
	static final String USE_BROWSER_PROPERTY =
		"com.netscape.management.client.util.useBrowser";

    /**
     * Initialize the help system, and create a ResourceSet
     * from the propertiesFile argument for token->directory
     * lookups.
     *
     * @param propertiesFile a fully-qualified reference to the
     *  properties file for this session of help.
     *
     * @deprecated replaced by Help.showHelp
	 * @see #showHelp
     */
    @Deprecated
    public Help(String propertiesFile) {
        tokens = new ResourceSet(propertiesFile);
    }

    /**
      * Initialize the help system using the resourceset.
      *
      * @param resourceset a ResourceSet for token->directory lookups.
      * @deprecated replaced by Help.showHelp
      * @see #showHelp
      */
    @Deprecated
    public Help(ResourceSet resourceset) {
        tokens = resourceset;
    }

    /**
      * The help invocation function. The token should be unique
      * for each help launch point. The manual directory for the
      * token will be resolved from the ResourceSet referenced
      * in the constructor.
      *
      * @param token the unique token for this help topic
      *
      * @deprecated replaced by Help.showHelp
      * @see #showHelp
      */
    @Deprecated
    public void help(String token) {
        help(null, token, UtilConsoleGlobals.getAdminURL());
    }


    /**
      * The help invocation function. The token should be unique
      * for each help launch point. The manual directory for the
      * token will be resolved from the ResourceSet referenced
      * in the constructor.
      *
      * @param token the unique token for this help topic
      * @param adminURL the URL for the admin server from where the help
      * documents will be served.
      *
      * @deprecated replaced by Help.showHelp
      * @see #showHelp
      */
    @Deprecated
    public void help(String token, URL adminURL) {
        help(null, token, adminURL);
    }

    /**
      * The help invocation function. The token should be unique
      * for each help launch point. The manual directory for the
      * token will be resolved from the ResourceSet referenced
      * in the constructor.
      *
      * @param token the unique token for this help topic
      * @param name the name of the help token
      *
      * @deprecated replaced by Help.showHelp
      * @see #showHelp
      */
    @Deprecated
    public void help(String prefix, String name) {
        help(prefix, name, UtilConsoleGlobals.getAdminURL());
    }

    /**
      * The help invocation function.
      * The token (prefix-name) should be unique for each help launch point.
      * The manual directory for the token will be resolved from the
      * ResourceSet referenced in the constructor.
      *
      * @param prefix the prefix of the help token
      * @param name the name of the help token
      * @param adminURL the URL for the admin server from where the help
      * documents will be served.
	  * @param contextHelp <CODE>true</CODE> to display help in a
	  * Java window, <CODE>false</CODE> to launch a browser
	  *
      * @deprecated replaced by Help.showHelp
      * @see #showHelp
      */
    @Deprecated
    protected void help(String prefix, String name, URL adminURL,
						boolean contextHelp)
	{
		showHelp(getProduct( prefix, name ), prefix, name, adminURL, contextHelp);
	}

    /**
      * The help invocation function. The token (prefix-name) should
      * be unique for each help launch point. The manual directory
      * for the token will be resolved from the ResourceSet referenced
      * in the constructor.
      *
      * @param dir    the manual directory, typically the product id: "admin" "slapd"
      * @param prefix the prefix of the help token
      * @param name the name of the help token
      * @param adminURL the URL for the admin server from where the help
      * documents will be served.
	  * @param contextHelp <CODE>true</CODE> to display help in a
	  * Java window, <CODE>false</CODE> to launch a browser
      */
    private static void showHelp(String dir, String prefix, String name, URL adminURL,
						boolean contextHelp) {
        if (dir == null) {
            Debug.println( "Help: unable to resolve directory for token (" +
                    name + ")");
            return;
        }

        Debug.println("prefix -> " + prefix);
        Debug.println("name -> " + name);
        Debug.println("dir -> " + dir);

        // added support for help invocation from browser.  The
        // functionality for help invocation from applet is left
        // unchanged in case we support that again.  - atulb
        if (applet == null) {
            String adminServerURL = new String(adminURL.toString());

            if (!adminServerURL.endsWith("/"))
                adminServerURL += "/";

            String url =
				adminServerURL + "manual/help/help?helpdir="+
				dir + "&token=" +
				((prefix != null) ? prefix + "-" : "") + name;

			if ( contextHelp ) {
				// Use a new token map file for context help
				url += "&mapfile=" + MAPFILE;
				Debug.println(url);
				/*
				 * The HTMLEditorKit in the 1.2 JDK is not capable of
				 * rendering HTML well, so for now we will launch a chromeless
				 * browser Window. It's fixed in 1.3, so when we can use that
				 * JDK we can switch back to using a Java window for Help.
				 * Rob / 3/7/2000
				 */
				if (false) {
					// Launch a Java window for Help
					String val =
						System.getProperty( USE_BROWSER_PROPERTY );
					boolean doBrowser = ( (val == null) ||
										  val.equalsIgnoreCase( "true" ) );
					BrowseHtmlDialog dlg =
						new BrowseHtmlDialog( null, url, doBrowser );
					String os = System.getProperty("os.name").toLowerCase();
					if ( os.startsWith( "windows" ) ) {
						dlg.show();
					} else {
						// If the help dialog is launched from a modal dialog
						// on UNIX, the only way to allow clicking on a
						// URL or scrolling is to make the help dialog modal
						dlg.showModal();
					}
				} else {
					// Wrap the URL in JavaScript to cause a chromeless
					// browser window. Doesn't work in Windows, because that
					// uses DDE (mangling the URL) or rundll32 (which doesn't
					// understand it is a URL).
//					java.util.Properties p = System.getProperties();
//					String osName = p.getProperty("os.name");
//					if (!osName.startsWith("Windows")) {
//						url = "javascript:window.open(" +
//							"\"" + url + "\"" +
//							",\"Help\"" +
//							",\"location=false,menubar=false,scrollbars=false," +
//							"status=false\")";
//						Debug.println(url);
//					}
					// Launch a browser
					Browser browser = new Browser("Help");
					boolean res = browser.open(url, Browser.NEW_WINDOW);
				}
				return;
			} else {
				Debug.println(url);
				// Launch a browser
				Browser browser = new Browser("Help");
				boolean res = browser.open(url, Browser.NEW_WINDOW);
			}
        }
    }

    /**
      * The help invocation function. The token (prefix-name) should
      * be unique for each help launch point. The manual directory
      * for the token will be resolved from the ResourceSet referenced
      * in the constructor.
      *
      * @param prefix the prefix of the help token
      * @param name the name of the help token
      * @param adminURL the URL for the admin server from where the help
      * documents will be served.
      *
      * @deprecated replaced by Help.showHelp
      * @see #showHelp
      */
    @Deprecated
    public void help(String prefix, String name, URL adminURL) {
		help( prefix, name, adminURL, false );
	}

    /**
      * The help invocation function. The token (prefix-name) should
      * be unique for each help launch point. The manual directory
      * for the token will be resolved from the ResourceSet referenced
      * in the constructor.
      *
      * @param prefix the prefix of the help token
      * @param name the name of the help token
      * @param adminURL the URL for the admin server from where the help
      * documents will be served.
      *
      * @deprecated replaced by Help.showContextHelp
      * @see #showContextHelp
      */
    @Deprecated
    public void contextHelp(String prefix, String name, URL adminURL) {
		// Use context help if it is supported by the Admin Server
		help( prefix, name, adminURL,
			  UtilConsoleGlobals.isContextHelpEnabled() );
	}

    /**
      * The help invocation function. The token (prefix-name) should
      * be unique for each help launch point. The manual directory
      * for the token will be resolved from the ResourceSet referenced
      * in the constructor.
      *
      * @param prefix the prefix of the help token
      * @param name the name of the help token
      *
      * @deprecated replaced by Help.showContextHelp
      * @see #showContextHelp
      */
    @Deprecated
    public void contextHelp(String prefix, String name) {
		// Use context help if it is supported by the Admin Server
        contextHelp(prefix, name, UtilConsoleGlobals.getAdminHelpURL());
	}

    /**
      * The help invocation function. The token (prefix-name) should
      * be unique for each help launch point. The manual directory
      * for the token will be resolved from the ResourceSet referenced
      * in the constructor.
      *
      * @param name the name of the help token
      *
      * @deprecated replaced by Help.showContextHelp
      * @see #showContextHelp
      */
    @Deprecated
    public void contextHelp(String name) {
		// Use context help if it is supported by the Admin Server
        contextHelp(null, name);
	}

    /**
      * Gets the product associated with this Help instance and
	  * topic (e.g. admin)
      *
      * @param prefix the prefix of the help token
      * @param name the name of the help token
	  * @return the product name, or <CODE>null</CODE> if not registered
	  *
      * @deprecated not needed
      */
    @Deprecated
    public String getProduct( String prefix, String name ) {
        if ( tokens == null ) {
            Debug.println("Help.getProduct: ResourceSet not initialized");
            return null;
        }

        return tokens.getString( prefix, name );
	}

    /**
      * Gets the URL for a help file at the product level
      *
      * @param prefix the prefix of the help token
      * @param token the name of the help token
      * @param filename the base name of an HTML file
      *
      * @deprecated not needed
      */
    @Deprecated
    public URL getHelpUrl(String prefix, String token, String filename) {
        String dir = getProduct( prefix, token );
	return Help.getHelpUrl(dir, prefix, token, filename);
    }


    /**
      * Gets the URL for a help file at the product level
      *
      * @param dir the prefix of the help token
      * @param prefix the prefix of the help token
      * @param token the name of the help token
      * @param filename the base name of an HTML file
      */
    public static URL getHelpUrl(String dir, String prefix, String token, String filename) {
        if (dir == null) {
            Debug.println( "Help.getHelpUrl: unable to resolve directory for token (" +
                    token + ")");
            return null;
        }

		String adminServerURL = UtilConsoleGlobals.getAdminHelpURL().toString();
		if ( !adminServerURL.endsWith("/") ) {
			adminServerURL += "/";
		}

		String url = adminServerURL + "manual/" + Locale.getDefault().getLanguage() +
			'/' + dir + '/' + filename;
		try {
			return new URL( url );
		} catch ( Exception e ) {
			Debug.println( "Help.getHelpUrl: cannot create URL for " + url );
			return null;
		}
    }

	/**
	 * This method brings up the entire online book, but scrolled to
	 * the specified topic of interest.  The help viewer is a
	 * full browser window with navigation capabilities.
	 *
	 * Example usage: help.showHelp("admin", "menubar-contents");
	 * The example shown results in an URL similar to:
	 * <code>http://hostname:port/manual/help/help?helpdir=admin&token=menubar-contents</code>
	 * which maps to the following directory on the backend:
	 * <code><serverroot>\manual\en\admin</code>
	 * In that directory, there is a file called tokens.map which contains
	 * an entry for fontPreferences, such as this:
	 * <code>menubar-contents  =  help/contents.htm</code>
	 *
	 * @param productID the product identifier, which corresponds to the manual directory on the back-end
	 * @param topic		the help topic contained in tokens.map
	 * @see #showContextHelp
	 */
	public static void showHelp(String productID, String topic)
	{
		showHelp(productID, null, topic, UtilConsoleGlobals.getAdminHelpURL(), false);
	}

	/**
	 * This method displays a short document relating to a particular topic.
	 * Call this method from dialogs, panels, wizards and other UI areas
	 * where context sensitive help is required.  The help viewer may be
	 * either a chromeless browser window or a java-based html window.
	 *
	 * If the Admin Server does not support context help (because it is pre-5.0),
	 * showContextHelp falls back to showHelp.
	 *
	 * Example usage: help.showContextHelp("admin", "preferences-fonts");
	 * The example shown results in an URL similar to:
	 * <code>http://hostname:port/manual/help/help?helpdir=admin&token=preferences-fonts&mapfile=tokens.map</code>
	 * which maps to the following directory on the backend:
	 * <code><serverroot>\manual\en\admin</code>
	 * in which there is a file called tokens.map which contains
	 * an entry for preferences-fonts, like this:
	 * <code>preferences-fonts = newhelp/preferences_fonts.htm</code>
	 *
	 * @param productID the product identifier, which corresponds to the manual directory on the back-end
	 * @param topic		the help topic contained in tokens.map
	 * @see #showHelp
	 */
	public static void showContextHelp(String productID, String topic)
	{
		showContextHelp(productID, topic, UtilConsoleGlobals.getAdminHelpURL());
	}

	/**
	 * This method displays a short document relating to a particular topic.
	 * Call this method from dialogs, panels, wizards and other UI areas
	 * where context sensitive help is required.  The help viewer may be
	 * either a chromeless browser window or a java-based html window.
	 *
	 * If the Admin Server does not support context help (because it is pre-5.0),
	 * showContextHelp falls back to showHelp.
	 *
	 * Example usage: help.showContextHelp("admin", "preferences-fonts",
     *                                     new URL("http://adminserver:80"));
	 * The example shown results in an URL similar to:
	 * <code>http://adminserver:80/manual/help/help?helpdir=admin&token=preferences-fonts&mapfile=tokens.map</code>
	 * which maps to the following directory on the backend:
	 * <code><serverroot>\manual\en\admin</code>
	 * in which there is a file called tokens.map which contains
	 * an entry for preferences-fonts, like this:
	 * <code>preferences-fonts = newhelp/preferences_fonts.htm</code>
	 *
	 * @param productID the product identifier, which corresponds to the manual directory on the back-end
	 * @param topic the help topic contained in tokens.map
     * @param adminURL the URL for the admin server where the help file resides
	 * @see #showHelp
	 */
	public static void showContextHelp(String productID, String topic,
                                       URL adminURL)
	{
		showHelp(productID, null, topic, adminURL, true);
	}
}
