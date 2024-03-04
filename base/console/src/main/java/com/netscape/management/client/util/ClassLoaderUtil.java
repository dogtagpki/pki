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

import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.util.Hashtable;

import com.netscape.management.client.console.ConsoleInfo;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPv3;

/**
 * A utility class that provides functionality relating to
 * class loading.
 */
public class ClassLoaderUtil {
    private static final String debugTag = "ClassLoader: ";
    static public Hashtable loaderHashtable = new Hashtable();
    static ResourceSet _resource = new ResourceSet("com.netscape.management.client.util.default");

    /**
     * check whether we already download the jar file
     *
     * @param sJarName name of the jar file
     * @return true if the jar file is already downloaded. false otherwise.
     */
    static public boolean isAlreadyDownload(String sJarName) {
        String sJarList[] = LocalJarClassLoader.getLocalJarList();

        if (sJarList == null)
            return false;

        if (Debug.getTraceLevel() >= 7) {
            Debug.println(7, debugTag + " Search <" + sJarName + "> in " + LocalJarClassLoader.jarsDir);
            String list = "";
            for (int n = 0 ; n < sJarList.length ; n++) {

                list += "<"+sJarList[n] + ">";
            }
            Debug.println(7, debugTag + LocalJarClassLoader.jarsDir + " content: " + list);
        }

        for (int i = 0 ; i < sJarList.length ; i++)
            if (sJarList[i].equals(sJarName)) {
                Debug.println(7, debugTag + sJarName + " is already downloaded");
                return true;
            }

        return false;
    }

    /**
      * Get the class from class loader
      *
      * @param info ConsoleInfo which will provide the jar file http location if the jar file is not in the local jar directory.
      * @param sFullClassName full class name of the java class
      */
    static public Class getClass(ConsoleInfo info, String sFullClassName) {
        try {
            return getClass(info, sFullClassName, null);
        } catch (Exception e) {
            return null;
        }
    }

    /**
      * Get the java class from the class loader with the progress meter
      *
      * @param info ConsoleInfo which will provide the jar file http location if the jar file is not in the local jar directory.
      * @param sFullClassName full class name of the java class
      * @param progressListener indicate the progress of class loading
      */
    static public Class getClass(ConsoleInfo info, String sFullClassName,
            IProgressListener progressListener) throws Exception {

        if ((sFullClassName == null) || sFullClassName.equals("")) {
            Debug.println(0, debugTag + "getClass:invalid class name argument <null>");
            return null;
        }

        String sClassName = "";
        String sJarName = "";

        try {
            int iAtSign = sFullClassName.indexOf("@");

            if (iAtSign < 0) {
                return Class.forName(sFullClassName); // use default system class loader
            }

            if (Debug.noJarsEnabled()) {
            	if (iAtSign >= 0) {
            		sFullClassName = sFullClassName.substring(0, iAtSign);
            	}
            	// for debuggers - do not download and install and use a jar file
            	// assume the local class loader has all of the classes
            	return Class.forName(sFullClassName); // use default system class loader
            }

            if (Debug.isEnabled()) {
                Debug.println(1, "ClassLoaderUtil.getClass("+sFullClassName+")");
            }

            sClassName = sFullClassName.substring(0, iAtSign);
            sJarName = sFullClassName.substring(iAtSign + 1);

            LocalJarClassLoader loader = getClassLoader(info, sJarName, progressListener);
            return loader.loadClass(sClassName, true);

        }
        catch (ClassNotFoundException cnfe) {
            Debug.println(0, debugTag + "Cannot load: " + sFullClassName);
            Debug.println(0, debugTag + cnfe.getMessage());
            throw new Exception( java.text.MessageFormat.format(
                    _resource.getString("error","ClassNotFound"),
                    new Object[]{sClassName}));
        }
    }

    /**
      * Get the resource from the class loader
      *
      * @param info ConsoleInfo which will provide the jar file http location if the jar file is not in the local jar directory.
      * @param sFullResourceName full resource name
      * @param progressListener indicate the progress of class loading
      * @return a byte array with the resource contents or null
      */
    static public byte[] getResource(ConsoleInfo info, String sFullResourceName){

        try {
            InputStream is = getResourceAsStream(info, sFullResourceName, null);

            // Resource not found
            if (is == null) {
                return null;
            }

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[1024];
            int cnt = -1;
            while((cnt=is.read(buf)) > 0) {
                bos.write(buf,0, cnt);
            }
            return bos.toByteArray();
        }
        catch (Exception e) {
            return null;
        }
    }

    /**
      * Get the resource as a stream from the class loader
      *
      * @param info ConsoleInfo which will provide the jar file http location if the jar file is not in the local jar directory.
      * @param sFullResourceName full resource name
      * @param progressListener indicate the progress of class loading
      * @return an input stream for reading the resource, or null if the resource
      *  could not be found
      */
    static public InputStream getResourceAsStream(ConsoleInfo info, String sFullResourceName,
            IProgressListener progressListener) throws Exception {
        if ((sFullResourceName == null) || sFullResourceName.equals("")) {
            Debug.println(0, debugTag + "getClass:invalid class name argument <null>");
            return null;
        }

        String sResourceName = "";
        String sJarName = "";

        try {
            int iAtSign = sFullResourceName.indexOf("@");

            if (iAtSign < 0) {
                 // use default system class loader
                return ClassLoader.getSystemResourceAsStream(sFullResourceName);
            }

            if (Debug.isEnabled()) {
                Debug.println(1, "ClassLoaderUtil.getResource("+sFullResourceName+")");
            }

            sResourceName = sFullResourceName.substring(0, iAtSign);
            sJarName = sFullResourceName.substring(iAtSign + 1);

            LocalJarClassLoader loader = getClassLoader(info, sJarName, progressListener);
            return loader.getResourceAsStream(sResourceName);

        }
        catch (Exception e) {
            throw e;
        }
    }

    /**
     * Locate the jar specified with jarName[@Localtion] where Location is
     * either Admin Server SIE dn or a http URL.
     */
    static LocalJarClassLoader getClassLoader(ConsoleInfo info, String sFullJarName,
            IProgressListener progressListener) throws Exception {

        String sJarLocation = "";
        String sJarName = sFullJarName;
        String sNewerJarVersion = null;

        try {
            int iAtSign = sFullJarName.indexOf("@");

            if (iAtSign > 0) {
                sJarLocation = sFullJarName.substring(iAtSign + 1);
                sJarName = sFullJarName.substring(0, iAtSign);

                // Use newer backward compatible version if available
                sNewerJarVersion = LocalJarClassLoader.checkForNewerVersion(
                        sJarName);
                if (sNewerJarVersion != null) {
                    Debug.println(5,
                            debugTag + "getClass: use " +
                            sNewerJarVersion + " instead of " +
                            sJarName + " (newer backward compatible version)");
                    sJarName = sNewerJarVersion;
                } else {
                    checkJarAvailability(info, sJarName, sJarLocation,
                            progressListener);
                }
            } else {
                // Use newer backward compatible version if available
                sNewerJarVersion = LocalJarClassLoader.checkForNewerVersion(
                        sJarName);
                if (sNewerJarVersion != null) {
                    Debug.println(5,
                            debugTag + "getClass: use " +
                            sNewerJarVersion + " instead of " +
                            sJarName + " (newer backward compatible version)");
                    sJarName = sNewerJarVersion;
                }
            }

            LocalJarClassLoader loader =
                    (LocalJarClassLoader) loaderHashtable.get(
                    sJarName.toLowerCase());

            if (loader == null) {
                loader = new LocalJarClassLoader(sJarName);
                loaderHashtable.put(sJarName.toLowerCase(), loader);
                if (Debug.isEnabled()) {
                    Debug.println(1, debugTag + "Create loader " + sJarName);
                }
            }
            else if (Debug.isEnabled()) {
                Debug.println(1, debugTag + "Loader " + sJarName + " found in cache");
            }

            return loader;

        }
        catch (MalformedURLException mue) {
            Debug.println(0,
                    debugTag + " Invalid location specifier for " +
                    sJarName + ": " + sJarLocation);
            Debug.println(0, debugTag + mue.getMessage());
            throw new Exception( java.text.MessageFormat.format(
                    _resource.getString("error","InstallError"),
                    new Object[]{sJarName}) + "\n" + mue.getMessage());
        }
        catch (LDAPException le) {
            Debug.println(0,
                    debugTag + "Invalid location specifier for " +
                    sJarName + ": " + sJarLocation);
            Debug.println(0, debugTag + le.getMessage());
            throw new Exception( java.text.MessageFormat.format(
                    _resource.getString("error","InstallError"),
                    new Object[]{sJarName}) + "\n" + le.getMessage());

        }
        catch (FileNotFoundException fnfe) {
            Debug.println(0,
                    debugTag + "Cannot create LocalJarClassLoader for " +
                    sJarName);
            Debug.println(0, debugTag + fnfe.getMessage());
            throw new Exception( java.text.MessageFormat.format(
                    _resource.getString("error","InstallError"),
                    new Object[]{sJarName}) + "\n" + fnfe.getMessage());

        }
        catch (Exception e) {
            Debug.println(0,
                    debugTag + "Cannot create LocalJarClassLoader for " +
                    sJarName);
            Debug.println(0, debugTag + e.getMessage());
            throw new Exception( java.text.MessageFormat.format(
                    _resource.getString("error","InstallError"),
                    new Object[]{sJarName}) + "\n" + e.getMessage());

        }
    }

    /**
      * check whether the java file is available or not
      *
      * @param info ConsoleInfo which will provide the jar file http location if the jar file is not in the local jar directory.
      * @param sJarName name of the jar file
      * @param sLocation http location of the jar file. It is something like: http://host:post/suffix
      * @param progressListener display the progress bar
      * @throws Exception if the jar file is not available
      */
    static public void checkJarAvailability(ConsoleInfo info,
            String sJarName, String sLocation,
            IProgressListener progressListener) throws Exception {
        if (isAlreadyDownload(sJarName))
            return;

        String sHost = null;
        int iPort = 0;
        boolean fSecurity = false;
        String sBaseURL = null;

        if (sLocation.startsWith("http")) {
            // it is a http[s]://<host>:<post>/<suffix format>

            sBaseURL = sLocation;

        } else {
            // assume it is an SIE

            Debug.println(9,
                    debugTag + "checkJarAvailability():sie is " +
                    sLocation);

            LDAPConnection ldc = info.getLDAPConnection();
            String configAttrs[] = {"nsserverport", "nsserveraddress", "nsserversecurity"};
            String sConfig = "cn=Configuration,"+sLocation;
            Debug.println(9,
                debugTag + "checkJarAvailability():reading " + sConfig);

            LDAPEntry entry = readEntry(ldc, sConfig, configAttrs);
            if (entry == null) {
                throw new LDAPException(
                    _resource.getString("error", "UnableToRead") + sConfig);
            }

            LDAPAttribute attribute = entry.getAttribute("nsserveraddress");
            if (attribute != null) {
                sHost = LDAPUtil.flatting(attribute);
            }
            /*
             * nsserveraddress might not be defined, which means that the
             * admin server should listen on all interfaces rather than on
             * a specific one. Read serverhostname from the SIE entry.
             * admin server uses 0.0.0.0 to mean listen on all interfaces
             */
            if ((sHost == null) || (sHost.trim().length() == 0) || sHost.equals("0.0.0.0")) {
                LDAPEntry sieEntry = readEntry(ldc, sLocation, new String[] {"serverhostname"});
                if (sieEntry == null) {
                    throw new LDAPException(
                        _resource.getString("error", "UnableToRead") + sLocation);
                }
                sHost = LDAPUtil.flatting(sieEntry.getAttribute("serverhostname"));
            }
            if (sHost == null || sHost.length() == 0) {
                throw new LDAPException( _resource.getString("error",
                        "NoServerHostName") + sLocation);
            }

            attribute = entry.getAttribute("nsserverport");
            if (attribute == null)
                throw new LDAPException( _resource.getString("error",
                        "NoServerPortName") + sConfig);
            iPort = Integer.parseInt(LDAPUtil.flatting(attribute));

            attribute = entry.getAttribute("nsserversecurity");
            if (attribute != null) {
                String sSecurity = LDAPUtil.flatting(attribute);
                if (!sSecurity.equals(""))
                    fSecurity = sSecurity.toLowerCase().equals("on");
            }

            sBaseURL = (fSecurity ? "https" : "http") + "://" + sHost + ":" +
                iPort + "/";
        }

        LocalJarClassLoader.getJarFile(info, sBaseURL, sJarName, progressListener);
    }


    /**
     * A method for reading entries where objeclass  might not be a readable
     * attribute (can not use default filter (objectclass=*))
     */
    static private LDAPEntry readEntry (LDAPConnection ldc, String DN, String attrs[]) throws LDAPException {

       // Make sure the filter contains an attribute that user can read
       String filter = "(" + attrs[0] + "=*)";

       LDAPSearchResults results =
           ldc.search (DN, LDAPv3.SCOPE_BASE, filter, attrs, false);

       return (results == null) ? null : results.next ();
   }
}
