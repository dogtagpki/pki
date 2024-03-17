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

import java.util.*;
import java.util.zip.*;
import java.io.*;
import java.net.URL;
import com.netscape.management.client.comm.*;
import com.netscape.management.client.console.ConsoleInfo;
import com.netscape.management.client.console.Console;

/**
 * The LocalJarClassLoader is designed to load classes from jars
 * stored locally, independently of other class loaders. The latest
 * update to this class supports a form of manifest file, which is
 * used to specify a collection of jars which constitute the
 * complete class environment of the loader.
 *
 * @author <a href=mailto:dt@netscape.com>David Tompkins</a>
 * @version 0.4, 6/1/98
 * @see KingpinClassLoader
 * @see ClassLoader
 */
public class LocalJarClassLoader extends KingpinClassLoader {
    static final protected String MANIFEST_FILE_NAME = "classes.env";

    static final protected int JAR_FILE_INCLUDE_LIMIT = 100;

    protected Vector jarNames = new Vector(); // A String Vector

    protected Vector jarFiles = new Vector(); // A ZipFile Vector

    static String[] classpath = getClassPath();

    static ResourceSet _resource = new ResourceSet("com.netscape.management.client.util.default");

    private static final String debugTag = "ClassLoader: ";

    static String jarsDir = Console.PREFERENCE_DIR + "jars" + File.separator;

    /**
     *  Patch table lists all files in the PREFERENCE_DIR/patch directory
     */
    static String patchFilePrefix = "patch-";
    static String patchDir = Console.PREFERENCE_DIR + "patch" + File.separator;
    static Hashtable patchTable;

    static {
        patchTable= getPatchList();
    }

    /**
     * Backward compatibility table. The table consists of static
     * entries for mcc*.jar and nmclf*.jar files as well as
     * thoses dynamically created by processing the "backward-compatible"
     * directive in the manifest file.
     */
    static Hashtable compatibilityTable;

    static {
        compatibilityTable = new Hashtable();
        CompatibilityPersistance.parseLine(compatibilityTable, "mcc60.jar:mcc50.jar,mcc42.jar,mcc41.jar,mcc40.jar");
        CompatibilityPersistance.parseLine(compatibilityTable, "nmclf60.jar:nmclf50.jar,nmclf42.jar,nmclf41.jar,nmclf40.jar");
        if (Debug.isEnabled()) {
            Debug.println(3, debugTag + "start parsing");
        }            
        CompatibilityPersistance.parseAllJars(compatibilityTable,
                getLocalJarList());
        if (Debug.isEnabled()) {
            Debug.println(3, debugTag + " done");
        }            
        //CompatibilityPersistance.save(compatibilityTable);
    }

    /**
      * Creates a new LocalJarClassLoader. The jarfilename
      * is expected to refer to a valid class jar. This jar
      * may optionally contain a class loader manifest file,
      * which will direct this class loader to include the
      * jars listed in the manifest in this class loader
      * environment.
      *
      * @param jarfilename the jar filename.
      */
    public LocalJarClassLoader(String jarfilename) throws Exception {
        super(jarfilename);
        loadClassEnvironment(jarfilename);

        if (Debug.isEnabled()) {
            String loader = loaderID + ":{";
            for (int i = 0; i < jarNames.size(); i++)
                loader += (String) jarNames.elementAt(i) + " ";
            loader += "}";
            Debug.println(0,
                    debugTag + "new LocalJarClassLoader " + loader);
        }
    }

    /**
      * Performs the core steps of creating the class loader environment,
      * including processing of the class loader manifest file, if found,
      * and loading of i18n/l10n property jars.
      *
      * @param filename the jar filename, relative to the jars directory.
      */
    protected void loadClassEnvironment(String filename) throws Exception {
        String language = Locale.getDefault().getLanguage();

        // Step 1. Process the contents of filename.
        //
        include(filename);

        // Step 2. Look for a l10n supplement for filename.
        //
        try {
            include(filename, language);
        } catch (Exception e) {
            // If not found it is still acceptable
            if (Debug.isEnabled()) {
                Debug.println(5,
                    debugTag + "No language file for " + filename +
                    " found on local disk, lang=" + language);
            }
        }

        // Step 3. Look for a class loader manifest file.
        //
        PropertyResourceBundle manifest = getManifest(filename);
        if (manifest == null) {
            if (Debug.isEnabled()) {
                Debug.println(3, debugTag + "No manifest file for " + filename);
            }
            return;
        }
        
        // Step 4. Include jars specified in the manifest
        //
        String[] list = getManifestJarList(manifest);
        for (int i = 0 ; i < list.length; i++) {
            String includeJar, newerVersion;

            includeJar = list[i];
            if (Debug.isEnabled()) {
                Debug.println(2, debugTag + "include jar " + includeJar);
            }                

            // Use newer backward compatible version if available
            newerVersion = checkForNewerVersion(includeJar);
            if (newerVersion != null) {
                if (Debug.isEnabled()) {
                    Debug.println(5,
                        debugTag + "Using " + newerVersion + " instead of " +
                        includeJar + " and it's language file");
                }
                includeJar = newerVersion;
            }

            include(includeJar);
            try {
                include(includeJar, language);
            } catch (Exception e) {
                // If not found it is still acceptable
                if (Debug.isEnabled()) {
                    Debug.println(5,
                        debugTag + "No language file for " +
                        includeJar + " found on local disk, lang=" +
                        language);
                }
            }
        }        
    }


    /**
      * Processes the manifest PropertyResourceBundle and produces an array
      * of jarfile names which are to be referenced. This list includes
      * only jars specified by "include-jarN=jarfile.jar" lines in the
      * classes.env file. Any other elements of classes.env are
      * currently ignored.
      *
      * @param manifest a PropertyResourceBundle for the manifest file.
      * @return a String[] of jarfile names, not including their l10n
      *  counterparts.
      */
    protected String[] getManifestJarList(
            PropertyResourceBundle manifest) {
        String[] s = new String[JAR_FILE_INCLUDE_LIMIT];

        int i = 0;
        while (i < JAR_FILE_INCLUDE_LIMIT) {
            String jarname;
            try {
                jarname = manifest.getString("include-jar"+i);
            } catch (MissingResourceException mre) {
                break;
            }
            s[i++] = jarname;
        }

        if (Debug.isEnabled()) {
            Debug.println(9, debugTag + "manifest: " + i + " entries found");
        }

        String[] list = new String[i];

        for (i -= 1 ; i >= 0 ; i--) {
            list[i] = s[i];
            if (Debug.isEnabled()) {
                Debug.println(9, debugTag + "manifest contents: " + list[i]);
            }
        }

        return list;
    }

    /**
      * Retrieves the class loader environment file for this LocalJarClassLoader,
      * looking first in the manifests cache. The name of this file is assumed to
      * be "classes.env", and the format is that of a PropertyResourceBundle
      * file (key=value lines).
      *
      * @return a PropertyResourceBundle for the class loader environment manifest.
      */
    protected PropertyResourceBundle getManifest(String filename) {
        PropertyResourceBundle manifest = null;
        InputStream is = getResourceAsStream(MANIFEST_FILE_NAME);

        if (is == null) {
            if (Debug.isEnabled()) {
                Debug.println(5,
                    debugTag + "no manifest found for " + filename);
            }
            return null;
        }

        try {
            manifest = new PropertyResourceBundle(is);
        } catch (IOException ioe) {
            Debug.println(0,
                    debugTag + "error loading manifest for " +
                    filename + ": " + ioe.getMessage());
            return null;
        }
        if (Debug.isEnabled()) {
            Debug.println(5, debugTag + "manifest loaded for " + filename);
        }            
        return manifest;
    }

    /**
      * Adds the two character language code to the jarfile basename,
      * before the filetype suffix.
      *
      * @param filename the jar filename, of the form file.jar.
      * @param language the two character ISO language identifer.
      * @return a String of the form file_language.jar.
      */
    protected static String addL10Nsuffix(String filename,
            String language) {
        int i = filename.lastIndexOf(".");

        if (i == -1)
            return filename;

        String base = filename.substring(0, i);
        String suffix = filename.substring(i);
        return base + "_" + language + suffix;
    }

    protected static String addL10Nsuffix(String filename) {
        return addL10Nsuffix(filename, Locale.getDefault().getLanguage());
    }


    /**
      * Parse CLASSPATH into a String array
      */
    private static String[] getClassPath() {

        String classpathRaw = System.getProperty("java.class.path");

        StringTokenizer list = new StringTokenizer(classpathRaw,
                File.pathSeparator);
        String[] classpath = new String[list.countTokens()];
        for (int i = 0; i < classpath.length; i++) {
            classpath[i] = list.nextToken();
        }
        return classpath;
    }


    /**
      * Check if a jar file is already in the classpath. If yes, no need to
      * include it, as the jar's class files will be loaded using the system
      * class loader which is much faster. This check is done only for the
      * pre-installed jar files in the <servr-root>/java directory.
      */
    private static boolean isInClassPath(String jar) {

        if (classpath == null)
                    return false;

        int sepIdx = jar.lastIndexOf(File.separator);
        String jarName = (sepIdx >=0) ? jar.substring(sepIdx+1) : jar;  
        for (int j = 0; j < classpath.length; j++) {
            //if (classpath[j].endsWith(jar)) {
            if (classpath[j].endsWith(jarName)) {
                File jarFile = new File(classpath[j]);
                if (jarFile.exists()) {
                    try {
                        String path1 = jarFile.getCanonicalPath();
                        String path2 = (new File(jar)).getCanonicalPath();

                        if (path1.equals(path2)) {
                            return true;
                        }
                    } catch (Exception e) { System.err.println(e);}
                }
            }
        }
        return false;
    }


    /**
      * Add a jarfile to the list of jarFiles
      */
    protected void include(String filename) throws Exception {
        String path = locateJarFile(filename);
        if (path == null) {
            throw new FileNotFoundException("File not found: " + filename);
        }
        
        if (isInClassPath(path)) {
            if (Debug.isEnabled()) {
                Debug.println(5,
                    debugTag + "Use the system class loader for " +
                    filename);
            }                
            return; // the file is already in the classpath no need for a separate class loader
        }

        // Apply patch if exist
        if (patchTable.get(filename) != null) {
            if (Debug.isEnabled()) {
                Debug.println(5, "Apply patch for " + filename);
            }                
            jarNames.addElement( patchFilePrefix + filename );
            jarFiles.addElement(new ZipFile(patchDir + patchFilePrefix + filename));
        }
        
        jarNames.addElement(filename);
        jarFiles.addElement(new ZipFile(path));
    }

    /**
      * Add a language specific jarfile to the list of jarFiles
      */
    protected void include(String filename,
            String language) throws Exception {
        try {
            include(addL10Nsuffix(filename, language));
        } catch (FileNotFoundException fnfe) {
            if (language.equals("en"))
                throw fnfe;

            // DT 8/10/98 If the language suffix is bogus or not found, revert to "en".
            if (Debug.isEnabled()) {
                Debug.println(5, debugTag + fnfe.getMessage());

                Debug.println(5,
                    debugTag + "Attempting to revert to " +
                    addL10Nsuffix(filename, "en"));
            }                
            include(addL10Nsuffix(filename, "en"));
        }
    }

    /**
      * Find the jarfile by name in the jarfile list
      */
    protected int getJarFileIndex(String filename) {
        for (int i = 0; i < jarNames.size(); i++) {
            String name = (String) jarNames.elementAt(i);
            if (name.equals(filename)) {
                return i;
            }
        }
        return -1;
    }


    /**
      * Server jar file located in jarsDir
      */
    protected static String locateJarFile(String jarname) {
        // Look for files in jarsDir.
        String filename = jarsDir + jarname;

        if (!((new File(filename)).exists())) {
            return null;
        } else {
            return filename;
        }
    }


    /**
      * Retrieves the resource specified by path from the admin server,
      * using the comm package. Note that this function should be private
      * for security reasons.
      *
      * @param path the path of the resource, relative to the current prefix.
      * @return resource as a byte array
      * @exception Exception on any error while loading the resource.
      */
    protected byte[] loadData(String path) throws Exception {
        ZipEntry e;
        ZipFile f;

        for (int i = 0; i < jarFiles.size(); i++) {
            f = (ZipFile) jarFiles.elementAt(i);
            e = f.getEntry(path);
            if (e != null) {

                BufferedInputStream zis =
                        new BufferedInputStream(f.getInputStream(e));

                // Read the content
                int size = (int)(e.getSize());
                int cnt = 0;
                byte[] storage = new byte[size];
                while (cnt < size) {
                    int len = zis.read(storage, cnt, size - cnt);
                    cnt += len;
                }

                if (Debug.isEnabled()) {
                    Debug.println(8, debugTag + path + " found in " +
                        jarNames.elementAt(i));
                }

                return storage;
            } else {
                if (Debug.isEnabled()) {
                    Debug.println(9, debugTag + path + "  NOT in " +
                        jarNames.elementAt(i));
                }
            }
        }
        throw new ClassNotFoundException(path);
    }

    /**
      * Returns a list of the jarfiles stored in the local jar directory.
      *
      * @return an array of the locally stored jar files.
      */
    public static String[] getLocalJarList() {
        File f = new File(jarsDir);

        if (!f.exists() || !f.isDirectory()) {
            Debug.println(0, debugTag + "getLocalJarList():Unable to read " + jarsDir + " directory");
            return null;
        }

        return f.list(new FilenameFilter() {
                    public boolean accept(File f, String n) {
                        return (n.endsWith(".jar") || n.endsWith(".zip"));
                    }
                }
        );
    }

    /**
      * Returns a list of the patch files stored in the patch directory.
      * A patch file name format is patch-<jar-file> e.g. patch-ds41.jar
      *
      * @return a hashtable of patchFile
      */
    static Hashtable getPatchList() {
        
        Hashtable tab = new Hashtable();
        Object o = new Object(); // A dummy object to be used as a hash value
        File f = new File(patchDir);

        if (!f.exists() || !f.isDirectory()) {
            Debug.println(0, debugTag + "getLocalJarList():Unable to read " + patchDir + " directory");
            return tab;
        }

        String[] list = f.list(new FilenameFilter() {
                    public boolean accept(File f, String n) {
                        return (n.startsWith(patchFilePrefix));
                    }
                }
        );
        int prefixLength = patchFilePrefix.length();
        for (int i=0; i< list.length; i++) {
            String file = list[i].substring(prefixLength);
            tab.put(file,o);
        }
        
        return tab;
    }

    /**
      * Acquires the jar file from the remote http server and stores it in the local
      * jar directory, which is currently assumed to be PREFERENCE_DIR/jars. It will look in
      * the <baseURL>/java, followed by <baseURL>/java/jars and finally <baseURL>
      * directory, and it will also attempt to retrieve any L10N supplements, if found.
      *
      * @param info ConsoleInfo object used to read user name and password
      * @param baseURL url used as a base for jar file search
      * @param jarname the name of the jarfile.
      * @param progressListener Listener for progress updates or null
      * @exception Exception on i/o error.
      */
    public static void getJarFile(ConsoleInfo info, String baseURL, String jarname,
            IProgressListener progressListener) throws Exception {
                
        Vector createdFiles = new Vector();
        
        try {
            getJarFileFamily(info, baseURL, jarname, progressListener, createdFiles);
        }
        
        catch (Exception e) {
            //Remove created files. Download of the main jar and it's
            // dependents is an atomic action
            
            for (int i=0; i < createdFiles.size(); i++) {
                try {
                    String filename = (String)createdFiles.elementAt(i);
                    File f = new File(jarsDir + filename);
                    boolean deleted = f.delete();
                    if (deleted) {
                        Debug.println(1, debugTag + " Cleanup: removed " + f);
                    }
                    else {
                        Debug.println(0, debugTag + " Cleanup: failed, no exception on " + f);
                    }
                }
                catch (Exception e1) {
                    Debug.println(0, debugTag + " Cleanup: failed " + e1);
                }
            }         
            throw e;
        }
    }    
    
    /**
     * Load the main jar, the language file for the main jar
     * and all jars specified in the main jar manifest along with
     * thair language version jars
     */
    protected static void getJarFileFamily(ConsoleInfo info, String baseURL, String jarname,
            IProgressListener progressListener, Vector createdFiles) throws Exception {
                
        HttpManager manager = null;
        String url = null;

        if (!baseURL.endsWith("/")) {
            baseURL += "/";
        }

        //
        // First try to download the jar from <baseURL>/java/jars directory
        // then from <baseURL>/java and finally from <baseURL>
        //        
        if (!loadJarFile(info, manager, (url=baseURL+"java/jars/"), jarname, progressListener, createdFiles) &&
            !loadJarFile(info, manager, (url=baseURL+"java/"),      jarname, progressListener, createdFiles) &&
            !loadJarFile(info, manager, (url=baseURL),              jarname, progressListener, createdFiles)) {

            Debug.println(0, debugTag + "getJarFile():Unable to download " + jarname);
            
            throw new FileNotFoundException(java.text.MessageFormat.format(
                _resource.getString("error","FileNotFound"),
                new Object[]{jarname , baseURL}));
        }

        //
        // Load language file; Try current language setting, then fall back to English
        //
        if (!loadJarFile(info, manager, url, addL10Nsuffix(jarname),progressListener, createdFiles) &&
            !loadJarFile(info, manager, url, addL10Nsuffix(jarname, "en"), progressListener, createdFiles)) {

            Debug.println(0, debugTag + "getJarFile():Unable to download " +
                url + addL10Nsuffix(jarname, "en"));
       }

        //
        // Process the manifest for any other jars we might need to load
        //
        Vector includeJarList = processManifest(jarname);

        for (int i = 0; i < includeJarList.size(); i++) {
            String includeJar = (String) includeJarList.elementAt(i);
            String jarDir;

            //
            // No need to download if a newer compatible version of the file
            // if locally available
            //
            String newerVersion = checkForNewerVersion(includeJar);
            if (newerVersion != null) {
                if (Debug.isEnabled()) {
                    Debug.println(5, debugTag + "Do not need to load " +
                        includeJar + " using backward compatible " + newerVersion);
                }
                continue;
            }

            if (locateJarFile(includeJar) == null) {
                //
                // Include Jar is not found on the disk. Try to download.
                // Look first in baseURL/java/jars, then in baseURL/java
                // and finally in baseURL
                //
                if (Debug.isEnabled()) {
                    Debug.println(5, debugTag + " Download include jar " + includeJar);
                }                    

                if (! loadJarFile(info, manager, baseURL + (jarDir = "java/jars/"),
                        includeJar, progressListener, createdFiles) &&
                    ! loadJarFile(info, manager, baseURL + (jarDir = "java/"), includeJar,
                        progressListener, createdFiles) &&
                    ! loadJarFile(info, manager, baseURL + (jarDir = ""), includeJar,
                        progressListener, createdFiles)) {

                    Debug.println(0, debugTag + " Can not download include jar " + includeJar);
                    
                    throw new FileNotFoundException(java.text.MessageFormat.format(
                            _resource.getString("error", "FileNotFound"),
                            new Object[]{includeJar, baseURL}));
                }

                //
                // Load language version of the jar file. The file must be in the same
                // directory as the jar file. First try default language, and then fall back
                // to the default "en". It is not necessary to have language file for each
                // jar, so if the file is not found do not throw an exception
                //
                else if ( ! loadJarFile(info, manager, baseURL + jarDir,
                        addL10Nsuffix(includeJar), progressListener, createdFiles)) {
                    
                    if (Debug.isEnabled()) {
                        Debug.println(5, debugTag + " Can not load " +  addL10Nsuffix(includeJar));
                    }

                    String lang = Locale.getDefault().getLanguage();
                    if (lang.equals("en"))
                        continue;

                    // Try to load english version of the file
                    if (! loadJarFile(info, manager, baseURL + jarDir,
                        addL10Nsuffix(includeJar, "en"), progressListener, createdFiles)) {

                        if (Debug.isEnabled()) {
                            Debug.println(5, debugTag + "Can not load " + addL10Nsuffix(includeJar, "en"));
                        }
                    }
                }
            } else {
                if (Debug.isEnabled()) {
                    Debug.println(9, debugTag + "do not need to load include jar " + includeJar);
                }                    
            }
        }
    }

    /**
      * Check compatibility table if a newer version of the jar is available
      */
    public static String checkForNewerVersion(String jarname) {
        String newVersion = (String) compatibilityTable.get(jarname);
        if (newVersion != null && locateJarFile(newVersion) != null) {
            return newVersion;
        }
        return null;
    }


    protected static boolean loadJarFile(ConsoleInfo info, HttpManager manager,
            String baseURL, String filename,
            IProgressListener progressListener,  Vector createdFiles) throws Exception {

        if (manager == null) {
            manager = new HttpManager();
            manager.setBufferSize(32 * 1024);
            manager.setTimeout(20); // Close channel immediately after request is completed
        }    

        if (Debug.isEnabled()) {
            Debug.println(5,
                debugTag + "loadJarFile(): attempting to download " +
                baseURL + filename);
        }            

        if (progressListener != null) {
            progressListener.progressUpdate(filename, 0, 0);
        }

        URL url = null;
        try {
            url = new URL(baseURL + filename);

            InputStream is;
            Response r;

            GetJarCommClient commClient =
                    new GetJarCommClient(info, filename, progressListener);

            manager.get(url, commClient, r = new Response(), CommManager.FORCE_BASIC_AUTH);

            while ((is = r.getInputStream()) == null) {
                if (commClient.isError()) {
                    if (commClient.getException() != null) {
                        throw commClient.getException();
                    } else {
                        return false;
                    }
                }

                Thread.currentThread();
                Thread.sleep(20);
            }

            File f = new File(jarsDir);
            if (!f.exists())
                f.mkdir();

            FileOutputStream fos =
                    new FileOutputStream(jarsDir + filename);
            AsyncByteArrayInputStream ais = (AsyncByteArrayInputStream) is;
            fos.write(ais.getBuf(), 0, ais.size());
            fos.close();
            createdFiles.addElement(filename);            
            return true;
        } catch (java.net.ConnectException ce) {
            String target = baseURL;
            if (url != null) {
                target = url.getProtocol() + "://" + url.getHost() + ":" +
                        url.getPort();
            }
            Debug.println(0,
                    debugTag + "loadJarFile(): unable to connect " + ce);
            throw new java.net.ConnectException(
                    java.text.MessageFormat.format(
                    _resource.getString("error","CanNotConnect"),
                    new Object[]{target}));
        }
        catch (FileNotFoundException fnfe) {
            //This exception is thrown if write to the output file fails
            Debug.println(0, debugTag + "loadJarFile(): " + fnfe);
            throw new Exception( java.text.MessageFormat.format(
                    _resource.getString("error","SaveFile"),
                    new Object[]{fnfe.getMessage()}));
        }
        catch (HttpException he) {
            Debug.println(0, debugTag + "loadJarFile(): " + he);
            /*if (he.getStatusCode() == HttpManager.HTTP_NOTFOUND) {
                return false;
            } else {
                throw he;
            }*/
            return false;
        }

        catch (Exception e) {
            Debug.println(0, debugTag + "loadJarFile(): " + e);
            throw e;
        }
    }

    /**
      * Process the manifest after the main jar is loaded. Return the list of include
      * files, and update the compatibility table if backward-compatible directive is
      * present
      */
    protected static Vector processManifest(String mainJar)
            throws Exception {
        
        BufferedInputStream zis = null;
        ZipFile f = null;
        Vector jars = new Vector();

        try {
            f = new ZipFile(jarsDir + mainJar);
            ZipEntry e = f.getEntry(MANIFEST_FILE_NAME);
            String jarname, compList = null;

            if (e == null)
                return jars;

            zis = new BufferedInputStream(f.getInputStream(e));
            PropertyResourceBundle manifest = new PropertyResourceBundle(zis);

            if (manifest == null)
                return jars;

            for (int i = 0; i < JAR_FILE_INCLUDE_LIMIT; i++) {
                try {
                    jarname = manifest.getString("include-jar"+i);
                } catch (MissingResourceException mre) {
                    break;
                }
                jars.addElement(jarname);
            }

            try {
                compList = manifest.getString("backward-compatible");
            } catch (MissingResourceException mre) {}

            if (compList != null) {
                CompatibilityPersistance.parseLine(compatibilityTable,
                        mainJar + ":"+compList);
                //CompatibilityPersistance.save(compatibilityTable);
                if (Debug.isEnabled()){
                    Debug.println(5,
                    debugTag + "Added to compatibiliy " + mainJar + ":"+
                    compList);
                }
            }

        }
        finally {
            if (f != null) { f.close();}
            if (zis != null) { zis.close(); }
        }
        
        return jars;
    }


    public String toString() {
        String s = className + " contents: \n";

                for (int i = 0; i < jarNames.size(); i++)
                    s += jarNames.elementAt(i).toString() + '\n';

                return s;
            }

    public static void main(String[] args) throws Exception {
        Debug.setTrace(true);

        LocalJarClassLoader cl1 = new LocalJarClassLoader("test.jar");
        Debug.println(cl1.toString());
        LocalJarClassLoader cl2 = new LocalJarClassLoader("test.jar");
        Debug.println(cl2.toString());
        System.exit(0);
    }
}

/**
  * Comm Client for downloading jar files using comm package HttpManager
  */
class GetJarCommClient implements CommClient2 {
    boolean fError = false;
    IProgressListener progressListener = null;
    Exception exception;
    ConsoleInfo info;
    String file;

    public GetJarCommClient(ConsoleInfo info, String file,
            IProgressListener progressListener) {
        this.progressListener = progressListener;
        this.file = file;
        this.info = info;
    }

    public synchronized void replyHandler(InputStream is, CommRecord cr) {
        ((Response)(cr.getArg())).setInputStream(is);
        notifyAll();
    }
    public synchronized void errorHandler(Exception e, CommRecord cr) {
        ((Response)(cr.getArg())).setException(e);
        fError = true;
        exception = e;
        notifyAll();
    }
    public String username (Object realm, CommRecord cr) {
        return (info == null) ? null : info.getAuthenticationDN(); 
    }
    public String password (Object realm, CommRecord cr) {
        return (info == null) ? null : info.getAuthenticationPassword(); 
    }
    public boolean isError() {
        return fError;
    }
    public Exception getException() {
        return exception;
    }


    public void progressUpdate(String text, int total, int done) {
        if (progressListener != null) {
            progressListener.progressUpdate( file , total, done);
        }
    }
}

/**
  * Compatibility Persistance encapsulates loading and saving of the
  * compatibilityTable.
  */
class CompatibilityPersistance {

    private static final String debugTag = "ClassLoader:persistanceTable ";
    static final String compFile = "loader41.conf";

    private static String fileComment =
            "# This file contains the jar file version compatibilty table\n" +
            "# It is created by the Console Local Class Loader\n" +
            "# The file entry format is <JarFile>:<CompatiblityList>\n" +
            "# CompatibilityList is a comma separated list of files the JarFile\n"+
            "# is backward compatible with. If the JarFile is present, it is used \n" +
            "# instead of jars in the backward compatibility list\n";

    public static Hashtable load() {
        File file = new File(compFile);
        if (!file.exists())
            return null;
        if (!file.canRead()) {
            Debug.println(0, debugTag + "Can not read " + compFile);
            return null;
        }

        BufferedReader f = null;
        Hashtable table = new Hashtable();
        try {
            f = new BufferedReader(
                    new InputStreamReader(new FileInputStream(file)));

            String line;
            int lineNo = 0;
            while ((line = f.readLine()) != null) {
                lineNo++;
                if (!parseLine(table, line)) {
                    Debug.println(0,
                            debugTag + compFile + " corrupted, line " +
                            lineNo + ":" +line);
                    return null;
                }
            }
        } catch (Exception e) {
            Debug.println(0, debugTag + "Can not read " + compFile);
        }
        finally { if (f != null) {
                try {
                    f.close();
                } catch (Exception e) {}
            }
        } return table;
    }

    /**
      * Parse all jars in jarsDir for 'backward-compatible'
      * directive in the manifest file
      */
    public static void parseAllJars(Hashtable table, String[] jars) {
        if (jars == null)
            return;
        for (int i = 0; i < jars.length; i++) {
            try {
                ZipFile f = new ZipFile(LocalJarClassLoader.jarsDir + jars[i]);
                ZipEntry e = f.getEntry(
                        LocalJarClassLoader.MANIFEST_FILE_NAME);
                if (e == null) {
                    Debug.println(7,
                            debugTag + "no manifest in " + jars[i]);
                    continue; // no manifest file
                }

                BufferedInputStream zis =
                        new BufferedInputStream(f.getInputStream(e));
                PropertyResourceBundle manifest =
                        new PropertyResourceBundle(zis);
                if (manifest == null)
                    continue;

                String compList = null;

                try {
                    compList = manifest.getString("backward-compatible");
                } catch (MissingResourceException mre) {
                    Debug.println(7,
                            debugTag + "no backward-compatible in manifest for " +
                            jars[i]);
                }
                if (compList != null) {
                    CompatibilityPersistance.parseLine(table,
                            jars[i] + ":"+compList);
                    Debug.println(5,
                            debugTag + "Added to compatibiliy " +
                            jars[i] + ":"+compList);
                }
            } catch (Exception ex) {
                Debug.println(0,
                        debugTag + " error process manifest for " + LocalJarClassLoader.jarsDir +
                        jars[i] + " " + ex);
                continue;
            }
        }
    }

    public static void save(Hashtable table) {
        File file = new File(compFile);
        if (file.exists() && !file.canWrite()) {
            Debug.println(0, debugTag + "Can not write " + compFile);
            return;
        }

        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(compFile);

            fos.write((fileComment + tableToText(table)).getBytes());
        } catch (Exception e) {
            Debug.println(0, debugTag + "Can not write " + compFile);
        }
        finally { if (fos != null) {
                try {
                    fos.close();
                } catch (Exception e) {}
            }
        } Debug.println(9, debugTag + "tableToText="+tableToText(table));
        return;
    }

    /**
      * Parse a line. The format is newJar:oldJar1,oldJar2,...
      */
    public static boolean parseLine(Hashtable table, String line) {
        String newJar, oldJar, oldJarList;
        int sep;

        line.trim();
        if (line.length() == 0 || line.charAt(0) == '#')
            return true;

        if ((sep = line.indexOf(':')) < 0) {
            return false; // No ':' separator
        }

        newJar = line.substring(0, sep);
        oldJarList = line.substring(sep + 1);
        Debug.println(9,
                debugTag + "LINE=" +line + " newJar="+newJar + " oldJars="+
                oldJarList);

        StringTokenizer list = new StringTokenizer(oldJarList, ",");
        for (int i = 0; list.hasMoreElements(); i++) {
            oldJar = list.nextToken();
            Debug.println(9, debugTag + oldJar + " use instead " + newJar);
            table.put(oldJar, newJar);
        }
        return true;
    }

    /**
      * Convert compatibility hash table into a text representation
      */
    private static String tableToText(Hashtable table) {
        Hashtable out = new Hashtable();
        for (Enumeration e = table.keys(); e.hasMoreElements();) {
            String oldJar = (String) e.nextElement();
            String newJar = (String) table.get(oldJar);

            String oldJarList = (String) out.get(newJar);
            if (oldJarList != null) {
                out.put(newJar, oldJarList + "," + oldJar);
            } else {
                out.put(newJar, oldJar);
            }
        }

        String text = "";
        for (Enumeration e = out.keys(); e.hasMoreElements();) {
            String newJar = (String) e.nextElement();
            String oldJarList = (String) out.get(newJar);

            text += newJar + ":" + oldJarList + "\n";
        }
        return text;
    }
}
