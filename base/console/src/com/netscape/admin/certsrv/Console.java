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
package com.netscape.admin.certsrv;

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.io.*;
import java.text.MessageFormat;
import java.net.URL;
import java.net.MalformedURLException;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.border.*;

import com.netscape.management.client.console.*;
import com.netscape.management.nmclf.*;
import com.netscape.management.client.*;
import com.netscape.management.client.preferences.*;
import com.netscape.management.client.components.*;
import com.netscape.management.client.topology.*;
import com.netscape.management.client.util.*;
import com.netscape.management.client.cmd.*;
import com.netscape.management.client.ug.*;
import com.netscape.management.client.comm.*;

import netscape.ldap.*;
import netscape.ldap.util.DN;

/**
 * To start standard CS console, issue the following command
 *
 * /export/nkwan/s71/bin/base/jre/bin/java -ms8m -mx64m  -cp .:./ldapjdk.jar:./base.jar:./jss3.jar:./mcc70_en.jar:./mcc70.jar:./nmclf70_en.jar:./nmclf70.jar:./jars/cms71.jar:./jars/cms71_en.jar -Djava.library.path=/export/nkwan/s71/lib/jss  -Djava.util.prefs.systemRoot=/export/nkwan/s71/java/.java -Djava.util.prefs.userRoot=/export/nkwan/s71/java com.netscape.admin.certsrv.Console -D -s instanceID -a http://water:8200
 *
 */
public class Console implements CommClient {
    // Capture the time before any class is loaded so that we can measure JVM load time
    static long _t0 = System.currentTimeMillis();

    //
    // preference information
    //
    public static final String IDENTIFIER = "Console";
    public static final String VERSION = "4.0";
    public static final String PREFERENCES_LOGIN =
            IDENTIFIER + "." + VERSION + ".Login.preferences";

    public static final String PREFERENCE_UID = "UserID";
    public static final String PREFERENCE_REMEMBER_UID =
            "Remember" + PREFERENCE_UID;
    public static final String PREFERENCE_URL = "HostURL";
    public static final String PREFERENCE_LOCAL = "StorePrefsToDisk";
    public static final String PREFERENCE_X = "X";
    public static final String PREFERENCE_Y = "Y";

    public static final String OPTION_NOWINPOS = "nowinpos";
    public static final String OPTION_NOLOGO = "nologo";
    public static final String OPTION_JAVALAF = "javalaf";

	public static final int MAX_RECENT_URLS = 5;

	protected static final double MIN_CONTEXT_HELP_VERSION = 4.5;

    //
    // global values
    //
    public static Preferences _preferences;
    public static ConsoleInfo _info;
    public static String _consoleAdminURL;
    public static ResourceSet _resource = new ResourceSet("com.netscape.management.client.console.console");

    //
    // private values
    //
    private String _adminServerSIE;
    private JFrame _frame = null;
    private com.netscape.management.client.console.SplashScreen _splashScreen = null;
    private static boolean _showSplashScreen = true;
    private static boolean _useJavaLookAndFeel = false;

    // return valued from LDAPinitialization() method
    private static final int LDAP_INIT_OK = 0;
    private static final int LDAP_INIT_FAILED = 1;
    private static final int LDAP_INIT_DS_RESTART = 2;
    //user password expired, or removed on DS, but admin
    //server still cached the user (user login before the
    //passowrd expired, or invalid).
    private static final int LDAP_INIT_BIND_FAIL = 3;

    // A flag used by LDAPinitialization() to know whether to try to restart DS
    // if ConsoleInfo.setLDAPConnection() has failed
    private boolean _dsHasBeenRestarted = false;

	// Track the version of the admin server
	private String _adminVersion = null;

    //
    // check whether the preference file exist or not
    //
    static {
        if (_preferences == null)
            _preferences = new FilePreferences(PREFERENCES_LOGIN);
    }

    private static final boolean _isWindows =
            System.getProperty("os.name").startsWith("Windows");

    public static void loadFontPreferences() {
        return;
    }

    /**
      * common initialization routine.
      *
      * @param language	language string. For example, "en" for english
      */
    protected static void common_init(String language) {
        Locale.setDefault(
                new Locale(language, Locale.getDefault().getCountry()));

        try {

            // bug 115085: init calls needs to be inside the try block as, on Unix, during
            // initialization any call to java.awt.* will cause an exception to be thrown
            // if Xserver is not accessable. The jvm prints correctly the error message about
            // unaccessable Xserver but exception stack trace makes it less readable

            if (_info == null)
                _info = new ConsoleInfo();

            PreferenceManager.setLocalStorageFlag(
                    _preferences.getBoolean(PREFERENCE_LOCAL, false));

            if (!_useJavaLookAndFeel) {
                SuiLookAndFeel nmclf = new SuiLookAndFeel();
                UIManager.setLookAndFeel(nmclf);

                // With JDK1.4 on Unix, the first instance of JFileChooser
                // has an incorrect layout for some of the buttons. Create
                // and discard an instance.
                if (!_isWindows) {
                    Object o = new JFileChooser();
                    o = null;
                }
            }
            FontFactory.initializeLFFonts(); // load default customized fonts for login/splash

        } catch (InternalError ie) {
            System.err.println("Console: " + ie.getMessage());
            System.exit(1);
        }
        catch (Exception e) {
            Debug.println("Console.common_init: Cannot init " + e);
        }
    }

    /**
      * return the console info object
      *
      * @return	return the global console info object
      */
    public static ConsoleInfo getConsoleInfo() {
        return _info;
    }

    /**
      * set the global console info object.
      *
      * @param	info	consoleInfo object to be set as global console info
      */
    public static void setConsoleInfo(ConsoleInfo info) {
        _info = info;
    }

    /**
      * return whether the preferences is set or not
      *
      * @return true is the preference is set. false otherwise.
      */
    public static boolean canSetLocalPreferencesFlag() {
        return (_preferences != null);
    }

    /**
      * set the local preference flag
      *
      * @param b	preference flag
      */
    public static void setLocalPreferencesFlag(boolean b) {
        if (_preferences != null) {
            _preferences.set(PREFERENCE_LOCAL, b);
            _preferences.save();
        }
    }

    /**
      * return the local preference flag
      *
      * @return local preference flag
      */
    public static boolean getLocalPreferencesFlag() {
        if (_preferences != null)
            return _preferences.getBoolean(PREFERENCE_LOCAL);
        return true;
    }

    /**
      * by given the ldap connection and the server DN, it will find out the admin server for that server.
      *
      * @param ldc ldap connection
      * @param serverDN dn of the server
      * @return full URL of the admin server. It will return null if it cannot find uidthe admin server.
      */
    protected String getInstanceAdminURL(LDAPConnection ldc,
            String serverDN) {
        ServiceLocator sl = new ServiceLocator(_info);
        String dn=null;
        try {
            String productDN =
                    serverDN.substring(serverDN.indexOf(',') + 1);
            String ss40DN = productDN.substring(productDN.indexOf(',') + 1);
            String adminServerDN = sl.getAdminServer(ss40DN);
            if (adminServerDN == null) {
                Debug.println(
                        "ERROR ConsoleInfo.getInstanceAdminURL: could not get admin server entry = " +
                        ss40DN);
                return null;
            }

            String configDN = "cn=configuration," + adminServerDN;
            LDAPEntry configEntry = ldc.read(dn=configDN);
            if (configEntry == null) {
                Debug.println(
                        "ERROR ConsoleInfo.getInstanceAdminURL: could not get admin server config entry = " +
                        configDN);
                return null;
            }

            String host = LDAPUtil.flatting(
                    configEntry.getAttribute("nsserveraddress"));
            String port = LDAPUtil.flatting(
                    configEntry.getAttribute("nsServerport"));
            boolean securityOn = (LDAPUtil.flatting(
                    configEntry.getAttribute("nsServersecurity"))).
                    equalsIgnoreCase("on");

            /*
             * nsserveraddress might not be defined, which means that the
             * admin server should listen on all interfaces rather than on
             * a specific one. Read serverhostname from the SIE entry.
             */
            if (host == null || host.trim().length() == 0) {
                LDAPEntry sieEntry = ldc.read(dn=adminServerDN, new String[] {"serverhostname"});
                if (sieEntry == null) {
                    Debug.println("ERROR Console.getInstanceAdminURL: " +
                    "could not get serverhostname from "  + adminServerDN);
                    return null;
                }
                host = LDAPUtil.flatting(sieEntry.getAttribute("serverhostname"));
            }

            String url = "http";
            if (securityOn) {
                url = url + "s";
            }
            url = url + "://" + host + ":" + port + "/";
            return url;
        } catch (LDAPException e) {
            Debug.println("ERROR Console.getInstanceAdminURL: " +
              "LDAP error " + e + " dn=" + dn);
        }
        return null;
    }

    /**
      * get the OS type of the admin server.
      *
      * @param ldc ldap connection
      * @param serverDN DN of the admin server
      * @return os type of the admin server
      */
    protected String getInstanceAdminOS(LDAPConnection ldc,
            String serverDN) {
        try {
            String productDN =
                    serverDN.substring(serverDN.indexOf(',') + 1);
            String ss40DN = productDN.substring(productDN.indexOf(',') + 1);
            String hostDN = ss40DN.substring(ss40DN.indexOf(',') + 1);

            LDAPEntry hostEntry = ldc.read(hostDN);
            if (hostEntry == null) {
                Debug.println(
                        "ERROR ConsoleInfo.getInstanceAdminOS: could not get host entry = " +
                        hostDN);
                return null;
            }

            String osVersion = LDAPUtil.flatting(
                    hostEntry.getAttribute("nsosversion",
                    LDAPUtil.getLDAPAttributeLocale()));
            return osVersion;
        } catch (LDAPException e) {
            Debug.println(
                    "ERROR ConsoleInfo.getInstanceAdminOS: LDAP error " + e);
        }
        return null;
    }

    /**
     * A helper method to find an SIE DN from its ID. See -s Console option.
     * Called by createPerInstanceUI().
     */
    private String serverIDtoDN(String id) {

        LDAPConnection ldc = _info.getLDAPConnection();
        Vector instances = new Vector();

        try {
            LDAPSearchResults res = ldc.search(
                "o=netscapeRoot",
                LDAPConnection.SCOPE_SUB,
                "(nsServerID=" + id + ")",
                new String[]{"dn"}, false);

            while (res.hasMoreElements()) {
                LDAPEntry hostEntry = res.next();
                instances.addElement(hostEntry.getDN());
            }

            if (instances.size() == 0) {
                System.err.println("Server instance " + id + " does not exist.");
                System.exit(0);
            }
            else if (instances.size() == 1) {
                id = (String) instances.elementAt(0);
            }
            else {

                if (_splashScreen != null) {
                    _splashScreen.setVisible(false);
                }

                int idx = -1;
                while (idx == -1) {
                    System.out.println("\nThere are multiple instances of server \"" + id + "\":\n");
                    for (int i=0; i < instances.size(); i++) {
                        System.out.println( (i+1) + ") " + instances.elementAt(i));
                    }
                    System.out.print("\nPlease select an instance form the above list [1]: ");
                    try {
                        String rsp = new BufferedReader(new InputStreamReader(System.in)).readLine();
                        if (rsp.length() == 0) {
                            idx = 1;
                        }
                        else {
                            try {
                                idx = Integer.parseInt(rsp);
                            }
                            catch (Exception ignore) {}
                        }

                        if (idx >=1 && idx <= instances.size()) {
                               idx = idx - 1;
                        }
                        else {
                            idx = -1;
                        }
                    }
                    catch (Exception e) {
                        break;
                    }
                }
                id = (String) instances.elementAt(idx);
            }
        }
        catch (Exception e) {
            if (Debug.isEnabled()) {
                e.printStackTrace();
            }
        }
        return id;
    }

    protected void createPerInstanceUI(String host) {

        if (!DN.isDN(host)) {
            host = serverIDtoDN(host);
        }

        LDAPConnection ldc = _info.getLDAPConnection();
        String configDN = "cn=configuration," + host;
        try {
            LDAPEntry configEntry = ldc.read(configDN);
            String className = LDAPUtil.flatting(
                    configEntry.getAttribute("nsclassname",
                    LDAPUtil.getLDAPAttributeLocale()));
            if (className == null) {
                Debug.println(
                        "ERROR Console: no 'nsclassname' attribute in " +
                        configDN);
                System.exit(0);
            }

            String adminURL = getInstanceAdminURL(ldc, host);
            if (adminURL == null) {
                Debug.println(
                        "ERROR Console: could not set the adminURL for " +
                        host);
            } else {
                _info.setAdminURL(adminURL);
            }

            String adminOS = getInstanceAdminOS(ldc, host);
            if (adminOS == null) {
                Debug.println(
                        "ERROR Console.constructor: could not set the adminOS for " +
                        host);
            } else {
                _info.setAdminOS(adminOS);
            }
            _info.setCurrentDN(host);

            Class c = ClassLoaderUtil.getClass(_info, className);
            if (c == null) {
                Debug.println(
                        "ERROR Console.constructor: could not get class " +
                        className);
                        System.exit(0);
                    }

            try {
                Hashtable topologyplugin =
                        TopologyInitializer.getTopologyPluginFromDS( _info);
                Enumeration ePlugins = topologyplugin.elements();
                while (ePlugins.hasMoreElements()) {
                    ITopologyPlugin plugin =
                            (ITopologyPlugin) ePlugins.nextElement();
                    ResourceObject resObj =
                            plugin.getResourceObjectByID(host);
                    if (resObj != null) {
                        if (resObj instanceof ServerNode) {

                            ServerNode srvNode = ((ServerNode) resObj);
                            IServerObject srvObj = null;

                            // ServerNode is loaded asynchronously
                            srvNode.reload();
                            while ((srvObj=srvNode.getServerObject()) == null) {
                                try { Thread.sleep(200); } catch (Exception e) {}
                            }
                            IResourceObject sel[] = new IResourceObject[1];
                            sel[0] = srvObj;
                            srvObj.run((IPage) null, sel);
                            return;
                        } else if (resObj instanceof ServerNode) {
                        }
                    }
                }
                Debug.println("ERROR Console.constructor: cannot find associated plugin for "+
                        host);
            } catch (Exception e) {
                if (Debug.isEnabled()) {
                    e.printStackTrace();
                }
                Debug.println(
                        "ERROR Console.constructor: could not create " +
                        className);
                        Debug.println("    Exception: " + e);
                    }
        } catch (LDAPException e) {
            if (Debug.isEnabled()) {
                e.printStackTrace();
            }
            Debug.println("ERROR Console.constructor: createServerInstance failed");
            Debug.println("    LDAPException: " + e);
        }
        System.exit(0);
    }

    public Console(String adminURL, String localAdminURL, String language, String host, String uid, String passwd) {
		Vector recentURLs = new Vector();
		String lastUsedURL;
        common_init(language);
        String userid = uid;
        String password = passwd;

        if (userid == null) {
            userid = _preferences.getString(PREFERENCE_UID);
        }

        lastUsedURL = _preferences.getString(PREFERENCE_URL);
		if(lastUsedURL != null) {
			recentURLs.addElement(lastUsedURL);
			if(adminURL == null) {
				adminURL = lastUsedURL;
				}
	    }

		if(adminURL == null) {
			adminURL = localAdminURL;
		}

		for(int count = 1; count < MAX_RECENT_URLS; count++) {
			String temp;
            temp = _preferences.getString(PREFERENCE_URL+Integer.toString(count));
			if(temp != null && temp.length() > 0)
				recentURLs.addElement(temp);
		}

        _frame = new JFrame();
        // Set the icon image so that login dialog will inherit it
        _frame.setIconImage( new RemoteImage("com/netscape/management/client/images/logo16.gif").getImage());

        ModalDialogUtil.setWindowLocation(_frame);

        //enable server auth
        UtilConsoleGlobals.setServerAuthEnabled(true);

        _splashScreen = new com.netscape.management.client.console.SplashScreen(_frame);
        _splashScreen.addWindowListener (new WindowAdapter() {
                    public void windowClosing(WindowEvent e) {
                        System.exit(0);
                    }
                }
                );
        if (_showSplashScreen)
            _splashScreen.showWindow();

        boolean fSecondTry = false;

        while (true) {
            LoginDialog dialog = null;

            _splashScreen.setStatusText(_resource.getString("splash","PleaseLogin"));
            _splashScreen.setCursor(
                    Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
            if ((adminURL == null) || (userid == null) ||
                    (password == null) || (fSecondTry)) {
                dialog = new LoginDialog(_frame, userid, adminURL, recentURLs);
                Dimension paneSize = dialog.getSize();
                Dimension screenSize = dialog.getToolkit().getScreenSize();
                int centerX = (screenSize.width - paneSize.width) / 2;
                int centerY = (screenSize.height - paneSize.height) / 2;
                int x = _preferences.getInt(PREFERENCE_X, centerX);
                int y = _preferences.getInt(PREFERENCE_Y, centerY);
                UtilConsoleGlobals.setAdminURL(adminURL);
                UtilConsoleGlobals.setAdminHelpURL(adminURL);
                dialog.setInitialLocation(x, y);
                _splashScreen.setCursor(
                        Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
                dialog.showModal();
                if (dialog.isCancel())
                    System.exit(0);
                _splashScreen.setCursor(
                        Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));

                userid = dialog.getUsername();
                adminURL = dialog.getURL();
				if(!adminURL.startsWith("http://") && !adminURL.startsWith("https://"))
				   adminURL = "http://" + adminURL;
                password = dialog.getPassword();
            }
            fSecondTry = true;
            UtilConsoleGlobals.setAdminURL(adminURL);
            UtilConsoleGlobals.setAdminHelpURL(adminURL);
            _consoleAdminURL = adminURL;

			_splashScreen.setStatusText( MessageFormat.format(_resource.getString("splash", "authenticate"), new Object[]{ userid}));

            if (authenticate_user(adminURL, _info, userid, password)) {
                _splashScreen.setStatusText(
                        _resource.getString("splash","initializing"));

                /**
                 * Initialize ldap. In the case config DS is down, the user can restart
                 * the DS from the Console. The Console will need to re-authenticate
                 * the user if that's the case.
                 */
                int ldapInitResult = LDAPinitialization(_info);
                if (ldapInitResult == LDAP_INIT_FAILED) {
                    Debug.println("Console: LDAPinitialization() failed.");
                    System.exit(1);
                } else if (ldapInitResult == LDAP_INIT_DS_RESTART) {
                    Debug.println("Console: LDAPinitialization() DS restarted.");

					// Need to re-authenticate the user
					_splashScreen.setStatusText( MessageFormat.format(_resource.getString("splash", "authenticate"), new Object[]{ userid}));
                    if (authenticate_user(adminURL, _info, userid,
                            password)) {
                        _splashScreen.setStatusText(
                                _resource.getString("splash","initializing"));
                        if (LDAPinitialization(_info) == LDAP_INIT_FAILED) {
                            Debug.println("Console: LDAPinitialization() failed.");
                            System.exit(1);
                        }
                    } else {
                        continue; // Autentication faled, try again
                    }
                } else if (ldapInitResult == LDAP_INIT_BIND_FAIL) {
                    continue;
                }

                boolean rememberUserid = _preferences.getBoolean(
                        PREFERENCE_REMEMBER_UID, true);
                if (rememberUserid) {
                    _preferences.set(PREFERENCE_UID, userid);
                    _preferences.set(PREFERENCE_URL, adminURL);

					String recentlyUsedURL;
					int count = 1;
					Enumeration urlEnum = recentURLs.elements();
					while (urlEnum.hasMoreElements()) {
						recentlyUsedURL = (String)urlEnum.nextElement();
						if(!recentlyUsedURL.equals(adminURL))
							_preferences.set(PREFERENCE_URL+Integer.toString(count++), recentlyUsedURL);
					}

					for(; count < MAX_RECENT_URLS; count++) {
						_preferences.remove(PREFERENCE_URL+Integer.toString(count));
					}

                    if (dialog != null) {
                        Point p = dialog.getLocation();
                        _preferences.set(PREFERENCE_X, p.x);
                        _preferences.set(PREFERENCE_Y, p.y);
                        dialog.dispose();
                        dialog = null;
                    }
                    _preferences.save();
                }

                initialize(_info);
                if (host == null) {
                    Framework framework = createTopologyFrame();
                    UtilConsoleGlobals.setRootFrame(framework.getJFrame());
                } else {
                    // popup the per server configuration UI
                    // first get the java class name
                    createPerInstanceUI(host);
                }

                 _frame.dispose();
                _splashScreen.dispose();
                com.netscape.management.client.console.SplashScreen.removeInstance();
                _splashScreen = null;

                break;
            }
        }
    }

    static public Framework createTopologyFrame() {
        if (_info != null) {
            TopologyInitializer initializer = new TopologyInitializer(_info);
            Framework f = new Framework(initializer);
            UtilConsoleGlobals.setRootTopologyFrame(f.getJFrame());
            return f;
        }
        return null;
    }

    public void setDomainSuffix(String adminServerSIE) {
        String location = "";
        if (adminServerSIE != null) {
            String temp = adminServerSIE;
            int index = 0;
            for (int i = 0; i < 4; i++) {
                index = temp.indexOf(',',index);
                index++;
            }
            location = temp.substring(index);
            LDAPUtil.setInstalledSoftwareDN(location);
        }
    }

    /**
      * get the user and group information.
      *
      * @param info console info
      */
    public void initialize(ConsoleInfo info) {
        setDomainSuffix(_adminServerSIE);

        LDAPConnection ldc = _info.getLDAPConnection();

        if (ldc != null) {
            String sName;
            String sValue;
            int iFirstQuote;
            int iSecondQuote;
            int iThirdQuote;
            int iFourthQuote;
            LDAPAttribute attribute;
            Enumeration eAttributes;
            String ldapLocation = "";
            LDAPEntry entry;
            LDAPSearchResults result;
            LDAPSearchConstraints cons;

            // get default object classes container
            try {
                ldapLocation = "cn=user, cn=DefaultObjectClassesContainer,"+
                        LDAPUtil.getAdminGlobalParameterEntry();
                entry = ldc.read(ldapLocation);
                if (entry != null) {
                    // get the new user / group class information
                    attribute = entry.getAttribute("nsDefaultObjectClass",
                            LDAPUtil.getLDAPAttributeLocale());

                    if (attribute != null) {
                        Vector vUserObjectClasses = new Vector();
                        eAttributes = attribute.getStringValues();
                        while (eAttributes.hasMoreElements()) {
                            String sUserObjectClass =
                                    (String) eAttributes.nextElement();
                            vUserObjectClasses.addElement(
                                    sUserObjectClass);
                        }

                        ResourceEditor.getNewObjectClasses().put(
                                ResourceEditor.KEY_NEW_USER_OBJECTCLASSES,
                                vUserObjectClasses);
                    }
                }
            } catch (LDAPException e) {
                Debug.println("Console: Cannot open: "+ldapLocation);
            }
            if (ResourceEditor.getNewObjectClasses().get(
                    ResourceEditor.KEY_NEW_USER_OBJECTCLASSES) == null) {
                Vector vObject = new Vector();
                vObject.addElement("top");
                vObject.addElement("person");
                vObject.addElement("organizationalPerson");
                vObject.addElement("inetorgperson");
                ResourceEditor.getNewObjectClasses().put(
                        ResourceEditor.KEY_NEW_USER_OBJECTCLASSES, vObject);
            }

            try {
                ldapLocation =
                        "cn=group, cn=DefaultObjectClassesContainer,"+
                        LDAPUtil.getAdminGlobalParameterEntry();
                entry = ldc.read(ldapLocation);
                if (entry != null) {
                    attribute = entry.getAttribute("nsDefaultObjectClass",
                            LDAPUtil.getLDAPAttributeLocale());

                    if (attribute != null) {
                        Vector vGroupObjectClasses = new Vector();
                        eAttributes = attribute.getStringValues();
                        while (eAttributes.hasMoreElements()) {
                            String sGroupObjectClass =
                                    (String) eAttributes.nextElement();
                            vGroupObjectClasses.addElement(
                                    sGroupObjectClass);
                        }

                        ResourceEditor.getNewObjectClasses().put(
                                ResourceEditor.KEY_NEW_GROUP_OBJECTCLASSES,
                                vGroupObjectClasses);
                    }
                }
            } catch (LDAPException e) {
                Debug.println("Console: Cannot open "+ldapLocation);
            }
            if (ResourceEditor.getNewObjectClasses().get(
                    ResourceEditor.KEY_NEW_GROUP_OBJECTCLASSES) == null) {
                Vector vObject = new Vector();
                vObject.addElement("top");
                vObject.addElement("groupofuniquenames");
                ResourceEditor.getNewObjectClasses().put(
                        ResourceEditor.KEY_NEW_GROUP_OBJECTCLASSES,
                        vObject);
            }

            try {
                ldapLocation = "cn=OU, cn=DefaultObjectClassesContainer,"+
                        LDAPUtil.getAdminGlobalParameterEntry();
                entry = ldc.read(ldapLocation);
                if (entry != null) {
                    attribute = entry.getAttribute("nsDefaultObjectClass",
                            LDAPUtil.getLDAPAttributeLocale());

                    if (attribute != null) {
                        Vector vOUObjectClasses = new Vector();
                        eAttributes = attribute.getStringValues();
                        while (eAttributes.hasMoreElements()) {
                            String sOUObjectClass =
                                    (String) eAttributes.nextElement();
                            vOUObjectClasses.addElement(sOUObjectClass);
                        }

                        ResourceEditor.getNewObjectClasses().put(
                                ResourceEditor.KEY_NEW_OU_OBJECTCLASSES,
                                vOUObjectClasses);
                    }
                }
            } catch (LDAPException e) {
                Debug.println("Console: Cannot open "+ldapLocation);
            }
            if (ResourceEditor.getNewObjectClasses().get(
                    ResourceEditor.KEY_NEW_OU_OBJECTCLASSES) == null) {
                Vector vObject = new Vector();
                vObject.addElement("top");
                vObject.addElement("organizationalunit");
                ResourceEditor.getNewObjectClasses().put(
                        ResourceEditor.KEY_NEW_OU_OBJECTCLASSES, vObject);
            }

            try {
                cons = ldc.getSearchConstraints();
                cons.setBatchSize(1);
                // then get the resource editor extension
                ldapLocation = "cn=ResourceEditorExtension,"+
                        LDAPUtil.getAdminGlobalParameterEntry();
                result = ldc.search(ldapLocation,
                        LDAPConnection.SCOPE_ONE, "(Objectclass=nsAdminResourceEditorExtension)",
                        null, false, cons);
                Hashtable hResourceEditorExtension = new Hashtable();
                Hashtable deleteResourceEditorExtension = new Hashtable();

                if (result != null) {
                    while (result.hasMoreElements()) {
                        LDAPEntry ExtensionEntry;
                        try {
                            ExtensionEntry = (LDAPEntry) result.next();
                        } catch (Exception e) {
                            // ldap exception
                            continue;
                        }

                        attribute = ExtensionEntry.getAttribute("cn",
                                LDAPUtil.getLDAPAttributeLocale());
                        Enumeration eValues = attribute.getStringValues();
                        String sCN = "";
                        while (eValues.hasMoreElements()) {
                            sCN = (String) eValues.nextElement(); // Take the first CN
                            break;
                        }

                        attribute =
                                ExtensionEntry.getAttribute("nsClassname",
                                LDAPUtil.getLDAPAttributeLocale());
                        if (attribute != null) {
                            eValues = attribute.getStringValues();
                            Vector vClass = new Vector();
                            while (eValues.hasMoreElements()) {
                                String sJarClassName =
                                        (String) eValues.nextElement();
                                Class c = ClassLoaderUtil.getClass(
                                        _info, sJarClassName);

                                if (c != null) {
                                    vClass.addElement(c);
                                }
                            }
                            hResourceEditorExtension.put(
                                    sCN.toLowerCase(), vClass);
                        }

                        attribute =
                                ExtensionEntry.getAttribute("nsDeleteClassname",
                                LDAPUtil.getLDAPAttributeLocale());
                        if (attribute != null) {
                            Enumeration deleteClasses =
                                    attribute.getStringValues();
                            Vector deleteClassesVector = new Vector();
                            while (deleteClasses.hasMoreElements()) {
                                String jarClassname = (String)
                                        deleteClasses.nextElement();
                                Class c = ClassLoaderUtil.getClass(
                                        _info, jarClassname);
                                if (c != null) {
                                    deleteClassesVector.addElement(c);
                                }
                            }
                            deleteResourceEditorExtension.put(
                                    sCN.toLowerCase(), deleteClassesVector);
                        }
                    }
                    ResourceEditor.setResourceEditorExtension(
                            hResourceEditorExtension);
                    ResourceEditor.setDeleteResourceEditorExtension(
                            deleteResourceEditorExtension);
                }

                // set up resource editor attribute
                ResourceEditor.setUniqueAttribute(
                        LDAPUtil.getUniqueAttribute(
                        _info.getLDAPConnection(),
                        LDAPUtil.getCommonGlobalParameterEntry()));

                String sLocation = LDAPUtil.getCommonGlobalParameterEntry();
                entry = ldc.read(sLocation);

                if (entry != null) {
                    attribute = entry.getAttribute("nsUserRDNComponent");
                    String sAttribute = LDAPUtil.flatting(attribute);
                    ResourceEditor.setUserRDNComponent(sAttribute);
                    attribute = entry.getAttribute("nsUserIDFormat");
                    sAttribute = LDAPUtil.flatting(attribute);
                    ResourceEditor.setUserIDFormat(sAttribute);
                    attribute = entry.getAttribute("nsGroupRDNComponent");
                    sAttribute = LDAPUtil.flatting(attribute);
                    ResourceEditor.setGroupRDNComponent(sAttribute);
                }

                ResourceEditor.setAccountPlugin(
                        buildAccountPluginHashtable());


            }
            catch (LDAPException e) {
                Debug.println("Console: Cannot open "+ldapLocation);
            }

            // this *should* already be created at install time, but just in case
            // note: if this entry is created here, then ACIs (for non-admins) will break
            String userPreferenceDN = LDAPUtil.createEntry(ldc,
                    LDAPUtil.getUserPreferenceOU(),
                    LDAPUtil.getInstalledSoftwareDN());
            userPreferenceDN = LDAPUtil.createEntry(ldc,
                    "\""+_info.getAuthenticationDN() + "\"",
                    userPreferenceDN, true);
            _info.setUserPreferenceDN(userPreferenceDN);
        }
		checkHelpSystem();
    }

	/**
	 * Check if the Admin Server version supports context-sensitive
	 * Help. That is the case if the version is greater than 4.2.
	 */
	protected void checkHelpSystem() {
		boolean hasContextHelp = false;
		if ( _adminVersion != null ) {
			hasContextHelp = ( Double.parseDouble( _adminVersion ) >=
							   MIN_CONTEXT_HELP_VERSION );
			Debug.println( "Console.checkHelpSystem: contextHelp=" +
						   hasContextHelp );
		} else {
			Debug.println( "Console.checkHelpSystem: cannot determine " +
						   "Admin Version" );
		}
		UtilConsoleGlobals.setContextHelpEnabled( hasContextHelp );
	}

    /**
      * build up the resource editor extension plugin.
      *
      * @return hashtable which contain all the resource editor plugin.
      */
    private Hashtable buildAccountPluginHashtable() {
        Hashtable HTAccountPlugin = new Hashtable();
        try {
            LDAPConnection ldc = _info.getLDAPConnection();
            String sExtension = "cn=ResourceEditorExtension, "+
                    LDAPUtil.getAdminGlobalParameterEntry();
            String reqAttrs[] = {"cn","nsadminaccountInfo"};
            LDAPSearchResults results =
                    ldc.search(sExtension, LDAPConnection.SCOPE_ONE, "(nsadminaccountInfo=*)",
                    reqAttrs, false);
            if (results != null) {
                while (results.hasMoreElements()) {
                    LDAPEntry entry;
                    try {
                        entry = (LDAPEntry) results.next();
                    } catch (Exception e) {
                        // ldap exception
                        continue;
                    }
                    LDAPAttributeSet entryAttrs = entry.getAttributeSet();
                    Enumeration attrsInSet = entryAttrs.getAttributes();
                    String sName = "";
                    Vector vJavaClass = new Vector();
                    while (attrsInSet.hasMoreElements()) {
                        LDAPAttribute nextAttr =
                                (LDAPAttribute) attrsInSet.nextElement();
                        if (nextAttr.getName().equalsIgnoreCase("cn")) {
                            sName = LDAPUtil.flatting(
                                    nextAttr.getStringValues());
                        } else if (
                                nextAttr.getName().equalsIgnoreCase("nsadminaccountInfo")) {
                            String sJavaClass = LDAPUtil.flatting(
                                    nextAttr.getStringValues());
                            // parse it
                            // assume it is in [xxx][xxx].. format
                            boolean fFinish = false;
                            do {
                                int iOpenBucket = sJavaClass.indexOf('[');
                                if (iOpenBucket < 0) {
                                    fFinish = true;
                                } else {
                                    int iCloseBucket =
                                            sJavaClass.indexOf(']',
                                            iOpenBucket + 1);
                                    String sClassString =
                                            sJavaClass.substring(
                                            iOpenBucket + 1, iCloseBucket);
                                    vJavaClass.addElement(sClassString);
                                    sJavaClass = sJavaClass.substring(
                                            iCloseBucket + 1);
                                }
                            } while (!fFinish)
                                ;
                        }
                    }
                    if (sName != null) {
                        HTAccountPlugin.put(sName.toLowerCase(),
                                vJavaClass);
                    }
                }
            }
        } catch (LDAPException e) {
            Debug.println("Console.buildAccountPluginHashtable: ResEditorAccountPage LDAP Exception: "+e);
        }
        return HTAccountPlugin;
    }


    /**
      * New authentication method, via CGI. Authenticate the user through the admin server CGI.
      *
      * @param adminServerURL	url of the admin server
      * @param info console info
      * @param user user dn
      * @param pw user password
      * @return true if successful. false otherwise.
      */
    private synchronized final boolean authenticate_user(
            String adminServerURL, ConsoleInfo info, String user,
            String pw) {
        URL url;

        try {
            // DT 5/14/98 This method of URL construction provides some limited
            // validation of the URL, and eliminates any preexisting uri component.
            url = new URL(new URL(adminServerURL), "/admin-serv/authenticate");
        } catch (MalformedURLException mue) {
            Debug.println("Console:authenticate_user():Unable to create authentication URL");
            return false;
        }

        Hashtable ht = new Hashtable();

        boolean successfulAuth = invoke_task(url, user, pw, ht);

        String param;

        // DT 6/29/98 Check Password Expiration data
        if ((param = (String)(ht.get("NW_PASSWD_EXPIRING"))) != null) {
            int secondsToExpiration = Integer.parseInt(param);

            if (secondsToExpiration == 0) {
                // Password expired. For now, show error and exit.
                // Later, this should jump to a UI.
                String msg = _resource.getString("error","pwExpired");
                System.err.println(msg);
                JOptionPane.showMessageDialog(
                        com.netscape.management.client.console.SplashScreen.getInstance(), msg,
                        _resource.getString("error","pwTitle"),
                        JOptionPane.ERROR_MESSAGE);
                ModalDialogUtil.sleep();
                System.exit(1);
            } else {
                double days = (secondsToExpiration / (1.0 * 3600 * 24));
                String msg = MessageFormat.format(
                        _resource.getString("warning","pwExpireSoon"),
                        new Object[]{ new Double(days)});
                Debug.println("Console: " + msg);
                JOptionPane.showMessageDialog(
                        com.netscape.management.client.console.SplashScreen.getInstance(), msg,
                        _resource.getString("warning","title"),
                        JOptionPane.ERROR_MESSAGE);
                ModalDialogUtil.sleep();
            }
        }

        if (!successfulAuth)
            return false;

        if ((param = (String)(ht.get("UserDN"))) != null)
            info.setAuthenticationDN(param);
        else {
            Debug.println("Console:authenticate_user():UserDN not found");
            info.setAuthenticationDN(user);
        }

        info.setAuthenticationPassword(pw);
        info.setAuthenticationValues(ht);

        return true;
    }

    /**
      * return the directory server
      *
      * @param user username
      * @param pw password
      * @param baseURL url of the admin server
      * @return true if successful. false otherwise.
      */
    protected boolean restartDirectoryServer(String user, String pw,
            String baseURL) {
        URL url;

        try {
            // DT 5/14/98 This method of URL construction provides some limited
            // validation of the URL, and eliminates any preexisting uri component.
            url = new URL(new URL(baseURL), "/admin-serv/tasks/operation/StartConfigDS");
        } catch (MalformedURLException mue) {
            Debug.println("Console:restartDirectoryServer():Unable to create start task URL");
            return false;
        }

        return invoke_task(url, user, pw, new Hashtable());
    }

    /**
      * invoking a task
      *
      * @param url URL of the task
      * @param user username
      * @param pw password
      * @param ht hashtable which contain the returned result
      * @return true if successful. false otherwise.
      */

    private synchronized final boolean invoke_task(URL url,
            String user, String pw, Hashtable ht) {
        HttpManager h = new HttpManager();

        InputStream is;
        Response r;
        Exception e = null;

        try {
            h.get(url, this, r = new Response(user, pw),
                    h.FORCE_BASIC_AUTH);
        } catch (Exception ioe) {
            String _url;
            try {
                _url = (new URL(url, "/")).toString();
            } catch (MalformedURLException mue) {
                _url = url.toString();
            }

            String msg = MessageFormat.format(
                    _resource.getString("error","connectAS"),
                    new Object[]{ _url});
            JOptionPane.showMessageDialog(com.netscape.management.client.console.SplashScreen.getInstance(),
                    msg, _resource.getString("error","title"),
                    JOptionPane.ERROR_MESSAGE);
            ModalDialogUtil.sleep();

            return false;
        }

        try {
            while (((is = r.getInputStream()) == null) &&
                    ((e = r.getError()) == null))
                wait();
        } catch (InterruptedException ie) {
            Debug.println("Console:invoke_task():task response interrupted");
            return false;
        }

        if (e != null) {
            String msg = MessageFormat.format(
                    _resource.getString("error","task"),
                    new Object[]{ e.toString()});
            JOptionPane.showMessageDialog(com.netscape.management.client.console.SplashScreen.getInstance(),
                    msg, _resource.getString("error","title"),
                    JOptionPane.ERROR_MESSAGE);
            ModalDialogUtil.sleep();

            if (!(e instanceof HttpException))
                Debug.println("Console:invoke_task():error:" + e);
            return false;
        }

        // parse response
        BufferedReader br;
        try {
            br = new BufferedReader(new InputStreamReader(is, "UTF8"));
        } catch (Exception ioe) {
            br = new BufferedReader(new InputStreamReader(is));
            Debug.println("Console:BufferedReader(UTF8) Error");
        }

        try {
            String line;

            while ((line = br.readLine()) != null) {
                int i = line.indexOf(':');

                if (i == -1)
                    continue;

                // each line is of the form "name: value" (note spacing)
                ht.put(line.substring(0, i), line.substring(i + 2));
            }
        } catch (Exception e2) {
        }

        String status = (String)(ht.get("NMC_Status"));

        if ((status == null) || (Integer.parseInt(status) != 0)) {
            Debug.println("Console:invoke_task():invocation failed");
            return false;
        }

        return true;
    }

    /**
      * initialize the ldap connection according to all the information. If the directory server is
      * not running, try to start the directory server.
      *
      * @param info	ConsoleInfo which store the global information.
      * @return	true if successfull. false otherwise.
      */
    private final int LDAPinitialization(ConsoleInfo info) {
        // Set DS information;

        Hashtable ht = _info.getAuthenticationValues();

        String param;

        // set up configuration data base information

        if ((param = (String)(ht.get("SIE"))) != null)
            _adminServerSIE = param;
        else
            Debug.println("Console:authenticate_user():SIE not found");

        if ((param = (String)(ht.get("ldapHost"))) != null)
            info.setHost(param);
        else
            Debug.println("Console:authenticate_user():ldapHost not found");

        if ((param = (String)(ht.get("ldapPort"))) != null)
            info.setPort(Integer.parseInt(param));
        else
            Debug.println("Console:authenticate_user():ldapPort not found");

        if ((param = (String)(ht.get("ldapBaseDN"))) != null)
            info.setBaseDN(param);
        else
            Debug.println("Console:authenticate_user():ldapBaseDN not found");

        param = (String)(ht.get("ldapSecurity"));
        boolean fLdapSecurity = false;
        if ((param != null) && (param.equals("on"))) {
            info.put("ldapSecurity","on");
            fLdapSecurity = true;
        } else {
            info.put("ldapSecurity","off");
        }

        // Need to open an LDAPConnection for the ConsoleInfo object.

        try {
            LDAPConnection ldapConnection = createLDAPConnection(info);
            if (ldapConnection == null) {
                return LDAP_INIT_BIND_FAIL;
            }
            info.setLDAPConnection(ldapConnection);

        } catch (LDAPException le) {

            // DT 5/19/98 Prompt user to restart the registry DS if ldc.connect() failed
            String dsURL = (fLdapSecurity ? "ldaps" : "ldap") + "://" +
                    info.getHost() + ":" + info.getPort();
            String msg = MessageFormat.format(
                    _resource.getString("error","connectDS"),
                    new Object[]{dsURL, le.getMessage()});
            Debug.println("Console:authenticate_user():" + msg);


            if (_dsHasBeenRestarted) {
                // DS has already been restarted, return an error
                JOptionPane.showMessageDialog(
                        com.netscape.management.client.console.SplashScreen.getInstance(), msg,
                        _resource.getString("error","title"),
                        JOptionPane.ERROR_MESSAGE);
                ModalDialogUtil.sleep();
                return LDAP_INIT_FAILED;
            }

            Object[] choices = { _resource.getString("error", "restartDSButton"),
            _resource.getString("error", "cancelButton")};
            Object[] msgs = { msg, " ",
            _resource.getString("error", "restartDSMessage"), " "};

            int selection = JOptionPane.showOptionDialog(
                    com.netscape.management.client.console.SplashScreen.getInstance(), msgs,
                    _resource.getString("error","inittitle"),
                    JOptionPane.DEFAULT_OPTION,
                    JOptionPane.QUESTION_MESSAGE, null, choices,
                    choices[0]);

            if (selection == 1)
                System.exit(1); // cancel

            // Pop a new login dialog, but this is for the Registry DS AS

/*
            RestartDialog rd = new RestartDialog(_frame);
            rd.setDialogLocation(_frame);
            rd.showModal();
            if (rd.isCancel())
                System.exit(0);
            _splashScreen.toFront();

            if (!restartDirectoryServer(rd.getUsername(),
                    rd.getPassword(), rd.getURL())) {
                return LDAP_INIT_FAILED;
            } else {
                msg = _resource.getString("info","restartDS");
                JOptionPane.showMessageDialog(
                        com.netscape.management.client.console.SplashScreen.getInstance(), msg,
                        _resource.getString("info","restartDSTitle"),
                        JOptionPane.INFORMATION_MESSAGE);
                _dsHasBeenRestarted = true;
                return LDAP_INIT_DS_RESTART;
            }
*/
        }

        // set up user data base information
        // If config DS is unaccessable when authenticate CGI is called, the CGI returns ? for UserDirectory
        if ((param = (String)(ht.get("UserDirectory"))) != null &&
                !param.equals("?")) {
            // this caused I18n problem - param=param.toLowerCase();
            LDAPConnection ldc = null;
            boolean fSSL = false;
            String sHost = info.getHost();
            int iPort = info.getPort();
            String sBaseDN = info.getBaseDN();
            int iStartSearch = 7;
            if (param.startsWith("ldaps://")) {
                fSSL = true;
                iStartSearch = 8;
            }

            int iNextSlash = param.indexOf('/',8);
            int iNextColon = param.indexOf(':',8);
            int iNextSpace = param.indexOf(' ',8); //for failover list

            // if failover list, use the first host and port in the list

            if ((iNextSlash > iNextColon) && (iNextColon != (-1))) {
                // has a port number
                if ((iNextSpace != (-1))&&(iNextSpace<iNextSlash)) {
                    // failover list
                    iPort = Integer.parseInt(
                            param.substring(iNextColon + 1, iNextSpace));
                } else {
                    iPort = Integer.parseInt(
                            param.substring(iNextColon + 1, iNextSlash));
                }
                sHost = param.substring(iStartSearch, iNextColon);
            } else {
                sHost = param.substring(iStartSearch, iNextSlash);
            }

            sBaseDN = param.substring(iNextSlash + 1);
            info.setUserHost(sHost);
            info.setUserPort(iPort);
            info.setUserBaseDN(sBaseDN);

            if (fSSL) {
                ldc = new KingpinLDAPConnection(
                              UtilConsoleGlobals.getLDAPSSLSocketFactory(),
                              info.getAuthenticationDN(),
                              info.getAuthenticationPassword());
            } else {
                ldc = new KingpinLDAPConnection( info.getAuthenticationDN(),
                        info.getAuthenticationPassword());
            }

            try {
                ldc.connect(info.getUserHost(), info.getUserPort());
                ldc.authenticate(LDAPUtil.LDAP_VERSION,
                        info.getAuthenticationDN(),
                        info.getAuthenticationPassword());
            } catch (Exception e) {
                // catch no user exception
                Debug.println("Console: cannot connect to the user database");
            }
            info.setUserLDAPConnection(ldc);
        } else
            Debug.println("Console.authenticate_user():UserDirectory value not found");


        return LDAP_INIT_OK;
    }

    /**
      * create an ldap connection.
      *
      * @param info ConsoleInfo object.
      * @exception LDAPException	Throws LDAPException if it cannot create a LDAP connection.
      */

    protected LDAPConnection createLDAPConnection(ConsoleInfo info)
            throws LDAPException {
        LDAPConnection ldc = null;

        if (info.get("ldapSecurity").equals("on")) {
            ldc = new KingpinLDAPConnection(
                             UtilConsoleGlobals.getLDAPSSLSocketFactory(),
                             info.getAuthenticationDN(),
                             info.getAuthenticationPassword());
        } else {
            ldc = new KingpinLDAPConnection(info.getAuthenticationDN(),
                    info.getAuthenticationPassword());
        }

        ldc.connect(info.getHost(), info.getPort());
        try {
            ldc.authenticate(LDAPUtil.LDAP_VERSION,
                    info.getAuthenticationDN(),
                    info.getAuthenticationPassword());
        } catch (Exception e) {
            // unable to auth the user, either password expired or account didn't exist.
            // perhpas directory server is down.
            JOptionPane.showMessageDialog(null, /*_info.getFrame(),*/

                    _resource.getString("error","cannotconnect") + e,
                            _resource.getString("error","title"),
                            JOptionPane.ERROR_MESSAGE);
            ldc = null;
        }

        return ldc;
    }

    /**
      * The CommClient interface for authentication.
      */

    /**
     * reply the response
     *
     * @param is input stream for the response
     * @param cr communication record
     */
    public synchronized void replyHandler(InputStream is, CommRecord cr) {
		HttpChannel channel = (HttpChannel)cr.getChannel();
		if (channel != null) {
			_adminVersion = channel.getAdminVersion();
			Debug.println("Console.replyHandler: adminVersion = " +
						  _adminVersion );
		} else {
			Debug.println("Console.replyHandler: no channel");
		}
        ((Response)(cr.getArg())).setInputStream(is);
        notifyAll();
    }

    /**
      * error exception handler
      *
      * @param e exception
      * @param cr communication record
      */
    public synchronized void errorHandler(Exception e, CommRecord cr) {
        ((Response)(cr.getArg())).setError(e);
        notifyAll();
    }

    /**
      * return the responsed username
      *
      * @param realm	authenicate object
      * @param cr	communication record
      * @return username
      */
    public String username(Object realm, CommRecord cr) {
        return ((Response)(cr.getArg())).getUsername();
    }

    /**
      * return the responsed password
      *
      * @param realm	authenicate object
      * @param cr	communication record
      * @return password
      */
    public String password(Object realm, CommRecord cr) {
        return ((Response)(cr.getArg())).getPassword();
    }

    static Console _console;

    private static void waitForKeyPress() {
        // On Windows, startconsole window disappears immediately on exit, so
        // we wait for keyboard input to allow the user to read the message
        if (System.getProperty("os.name").startsWith("Win")) {
            System.out.print("\nPress Enter key to continue ...");
            try {
                System.in.read();
            } catch (Exception e) {}
        }
    }

    /**
      * main routine. It will pass the command line parameters then call the Console constructor
      * to create a console instance.
      *
      * @param parameters list
      */

    static public void main(String argv[]) {
		GetOpt opt = new GetOpt("h:a:A:f:l:u:w:s:D:x:", argv);

        if (opt.hasOption('f')) {
            String outFile = opt.getOptionParam('f');
            try {
                TeeStream.tee(outFile);
           }
           catch (Exception e) {
                System.err.println("Missing or invalid output file specification for the -f option: " + e);
                System.exit(1);
           }
        }

        if (opt.hasOption('D')) {
            Debug.setApplicationStartTime(_t0);
            String extraParam = opt.getOptionParam('D');
            if (extraParam != null) {
                if (extraParam.equals("?") ||
                        !Debug.setTraceMode(extraParam)) {
                    System.out.println(Debug.getUsage());
                    waitForKeyPress(); // allow the user to read the msg on Win NT
                    System.exit(0);
                }
            } else {
                Debug.setTraceMode(null);
            }

            // Show all system proprties if debug level is 9
            if (Debug.getTraceLevel() == 9) {
                try {
                    Properties props = System.getProperties();
                    for (Enumeration e = props.keys();
                            e.hasMoreElements();) {
                        String key = (String) e.nextElement();
                        String val = (String) props.get(key);
                        Debug.println(9, key + "="+val);
                    }
                } catch (Exception e) {}
            }
        }

        Debug.println(0,
                "Management-Console/" +
                _resource.getString("console","displayVersion") +
                " B" + VersionInfo.getBuildNumber());

        if (opt.hasOption('x')) {
            String extraParam = opt.getOptionParam('x');
            boolean supportedOption = false;

            if (extraParam == null)
                extraParam = "";

            if (extraParam.indexOf(OPTION_NOLOGO) != -1) {
                _showSplashScreen = false;
                supportedOption = true;
            }
            if (extraParam.indexOf(OPTION_NOWINPOS) != -1) {
                Framework.setEnableWinPositioning(false);
                supportedOption = true;
            }
            if (extraParam.indexOf(OPTION_JAVALAF) != -1) {
                _useJavaLookAndFeel= true;
                supportedOption = true;
            }

            if (supportedOption == false) {
                opt = new GetOpt("h:", new String[]{ "-h"});
            }
        }

        if (opt.hasOption('h'))// help
        {
            System.err.println("Syntax:  Console [-a <URL>] [-l <Language Code>] [-s <SIE DN>] [-x <options>]");
            System.err.println("         -a admin server base URL");
            System.err.println("         -l language code (en fr gr)");
            System.err.println("         -f <file> capture stderr and stdout to <file> (like Unix tee command)");
            System.err.println("         -s server DN (cn=...) or instance ID (e.g. slapd-host)");
            System.err.println("         -x extra options (javalaf,nowinpos,nologo)");
            System.err.println("\nExample: Console -a https://hostname:10021 -l en");
            waitForKeyPress(); // allow the user to read the msg on Win NT
            System.exit(0);
        }

		// bug 353403: -a option intended for end-user to
		// specify default admin url.  This option overrides
		// -A option.
        String sAdminURL = null;
        if (opt.hasOption('a')) {
            sAdminURL = opt.getOptionParam('a');
        }

		// bug 353403, -A option intended for startconsole to
		// specify local admin server url, if one exists.
        String localAdminURL = null;
        if (opt.hasOption('A')) {
            localAdminURL = opt.getOptionParam('A');
        }

        String instanceID = null;
        if (opt.hasOption('s')) {
            instanceID = opt.getOptionParam('s');
        }

        String sLang = "en";
        if (opt.hasOption('l')) {
            sLang = opt.getOptionParam('l');
        }

        String host = null;
        if (opt.hasOption('s')) {
            host = opt.getOptionParam('s');
        }

        String uid = null;
        if (opt.hasOption('u')) {
            uid = opt.getOptionParam('u');
        }

        String password = null;
        if (opt.hasOption('w')) {
            password = opt.getOptionParam('w');
        }


        ConsoleInfo cinfo = new ConsoleInfo();
        CMSAdmin admin = new CMSAdmin();
        URL url = null;
        try {
          url = new URL(sAdminURL);
        } catch (Exception e) {
            String es = e.toString();
            String ep = "java.net.MalformedURLException:";
            if (es != null && es.startsWith(ep)) {
                es = es.substring(ep.length());
            }
            System.err.println("\nURL error: "+es+"\n");
            waitForKeyPress(); // allow the user to read the msg on Win NT
            System.exit(1);
        }
        if (url == null) {
            System.err.println("\nIncorrect URL: "+sAdminURL+"\n");
            waitForKeyPress(); // allow the user to read the msg on Win NT
            System.exit(1);
        }
        cinfo.put("cmsServerInstance", instanceID);

        String protocol = url.getProtocol();
        String hostName = url.getHost();
        String path = url.getPath();
        /* Protocol part of URL is required only by URL class. Console assumes URL protocol. */
        if (protocol == null || protocol.length() == 0 ||
            ((!protocol.equalsIgnoreCase("https")) && (!protocol.equalsIgnoreCase("http"))) ) {
            System.err.println("\nIncorrect protocol"+
                                 ((protocol != null && protocol.length() > 0)?": "+protocol:".")+
                               "\nDefault supported protocol is 'https'.\n");
            waitForKeyPress(); // allow the user to read the msg on Win NT
            System.exit(1);
        }

        if (hostName == null || hostName.length() == 0) {
            System.err.println("\nMissing hostName: "+sAdminURL+"\n");
            waitForKeyPress(); // allow the user to read the msg on Win NT
            System.exit(1);
        }
        if (path == null || path.length() < 2 ) {
            System.err.println("\nMissing URL path: "+sAdminURL+
                               "\nDefault supported URL paths are 'ca', 'kra', 'ocsp', and 'tks'.\n");
            waitForKeyPress(); // allow the user to read the msg on Win NT
            System.exit(1);
        }
        path = path.substring(1);
        if ((!path.equals("ca")) && (!path.equals("kra")) &&
            (!path.equals("ocsp")) && (!path.equals("tks"))) {
            System.err.println("\nWarning: Potentially incorrect URL path: "+path+
                               "\n         Default supported URL paths are 'ca', 'kra', 'ocsp', and 'tks'.\n");
        }
        int portNumber = url.getPort();
        if (portNumber < 0) {
            System.err.println("\nWarning: Unspecified port number: "+sAdminURL+"\n");
        /* Add warning about using non default port numbers after port separation is done.
                               "\n         Default port number is 9443.\n");
        } else if (portNumber != 9443) {
            System.err.println("\nWarning: Attempt to connect to non default port number: "+sAdminURL+
                               "\n         Default port number is 9443.\n");
        */
        }
        cinfo.put("cmsHost", url.getHost());
        cinfo.put("cmsPort", Integer.toString(portNumber));
        cinfo.put("cmsPath", path);
        admin.initialize(cinfo);
        admin.run(null, null);
/*
        _console = new Console(sAdminURL, localAdminURL, sLang, host, uid, password);
*/
        return;
    }
}


/**
 * A class that makes a PrintStream act like a Unix tee command
 */
class TeeStream extends PrintStream {
    static OutputStream logfile;

    private TeeStream(PrintStream ps) {
        super(ps);
    }

    // Redirects stdout and stderr to the logfile
    public static void tee(String f) throws IOException {

        // Create/Open logfile.
        logfile = new PrintStream(
            new BufferedOutputStream(
            new FileOutputStream(f)),
            /*autoFlush=*/true);

        // Start redirecting the output.
        System.setOut(new TeeStream(System.out));
        System.setErr(new TeeStream(System.err));
    }


    // PrintStream override.
    public void write(int b) {
        try {
            logfile.write(b);
        } catch (Exception e) {
            e.printStackTrace();
            setError();
        }
        super.write(b);
    }

    // PrintStream override.
    public void write(
     byte buf[], int off, int len) {
        try {
            logfile.write(buf, off, len);
        } catch (Exception e) {
            e.printStackTrace();
            setError();
        }
        super.write(buf, off, len);
    }
}

/**
  * An internal class used to wrap the parameters of an
  * authentication request.
  *
  * @author David Tompkins, 12/13/97
  */
class Response {
    private InputStream is;
    private Exception ex;
    private String user;
    private String pw;

    /**
     * constructor for the response object.
     *
     * @param _user	username
     * @param	_pw		password
     */
    public Response(String _user, String _pw) {
        user = _user;
        pw = _pw;
        is = null;
        ex = null;
    }

    /**
      * set the input stream
      *
      * @param _is	input stream to be set
      */
    protected void setInputStream(InputStream _is) {
        is = _is;
    }

    /**
      * set the response error
      *
      * @param e	error of the exception
      */
    protected void setError(Exception e) {
        ex = e;
    }

    /**
      * return the response input stream
      *
      * @return return the response input stream.
      */
    protected InputStream getInputStream() {
        return is;
    }

    /**
      * return the error exception
      *
      * @return error exception
      */
    protected Exception getError() {
        return ex;
    }

    /**
      * return the username
      *
      * @return username
      */
    protected String getUsername() {
        return user;
    }

    /**
      * return the password
      *
      * @return password
      */
    protected String getPassword() {
        return pw;
    }
}

