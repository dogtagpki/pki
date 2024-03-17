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

import java.util.Hashtable;
import java.io.InputStream;

/**
 * The KingpinClassLoader is the superclass for all Kingpin
 * Class Loaders. Multiple instances of KingpinClassLoader
 * for the same loader identifer will share a common class
 * cache.
 *
 * @author <a href=mailto:dt@netscape.com>David Tompkins</a>
 * @version 0.2, 1/16/98
 * @see ClassLoader
 * @todo rename class
 */
public abstract class KingpinClassLoader extends ClassLoader {
    static protected Hashtable classLoaderCache = new Hashtable();

            protected final static String debugTag = "ClassLoader: ";

            protected Object loaderID;
            protected String className;
            protected Hashtable classCache;

            /**
             * Stores the KingpinClassLoader in the class loader cache.
             *
             * @param _loaderID a unique identifier.
             */
    protected KingpinClassLoader(Object _loaderID) {
        loaderID = _loaderID;
        String cn = this.getClass().getName();
        className = cn.substring(cn.lastIndexOf('.') + 1);

        synchronized (classLoaderCache) {
            KingpinClassLoader kcl;

            if ((kcl = (KingpinClassLoader)
                    (classLoaderCache.get(loaderID))) != null) {
                classCache = kcl.classCache;
                        return;
                    }

                    classCache = new Hashtable();
                    classLoaderCache.put(loaderID, this);
                }
            }

            /**
              * Attempts to load the named class. If resolve is true,
              * the class will also be resolved. If the class is not found on the admin
              * server, the super class loadClass() function will be called.
              *
              * @param name the fully-qualified class name, in '.' form.
              * @param resolve if true, the class will be resolved after loading.
              * @return the Class object of the named class.
              * @exception ClassNotFoundException if the class cannot be found on the
              *  admin server nor by the base ClassLoader.
              */
    public Class loadClass(String name,
            boolean resolve) throws ClassNotFoundException {
        Class c = loadClass(name);

        if (resolve) {
            Debug.println(9, debugTag + ":loadClass():resolving " + name);
            resolveClass(c);
        }

        return c;
    }

    /**
      * Attempts to load the named class. If the class is
      * not found, the super class loadClass() function will be called.
      *
      * @param name the fully-qualified class name, in '.' form.
      * @return the Class object of the named class.
      * @exception ClassNotFoundException if the class cannot be found on the
      *  admin server nor by the base ClassLoader.
      */
    public Class loadClass(String name) throws ClassNotFoundException {
        Class c = null;

        if (Debug.isEnabled()) {
            Debug.println(9, debugTag + ":loadClass():name:" + name);
        }

        if (name.startsWith("java."))
            return findSystemClass(name);

        try {
            synchronized (classCache) {
                if ((c = (Class)(classCache.get(name))) == null) {
                    String path = name.replace('.', '/') + ".class";

                    if (Debug.isEnabled()) {
                        Debug.println(9,
                                debugTag + ":loadClass():loading:" + name);
                    }

                    byte[] data = loadData(path);
                    c = defineClass(name, data, 0, data.length);
                    classCache.put(name, c);
                } else if (Debug.isEnabled()) {
                    Debug.println(9,
                            debugTag + ":loadClass():cached class:" + name);
                }
            }
        } catch (Exception e) {
            return findSystemClass(name);
        }

        return c;
    }

    /**
      * Attempts to load the named resource. If the
      * resource is not found, the super class
      * getSystemResourceAsStream() function will be called.
      *
      * @param path the fully-qualified path name of the resource.
      * @return an InputStream for the resource, or null if not found.
      */
    public InputStream getResourceAsStream(String path) {
        try {
            return new java.io.ByteArrayInputStream(loadData(path));
        } catch (Exception e) {
            return ClassLoader.getSystemResourceAsStream(path);
        }
    }

    public String toString() {
        return className + "[" + loaderID + "]";
            }

            /**
              * Retrieves the resource specified by path from the admin server,
              * using the comm package. Note that the implementation of this
              * function should call another private function for security reasons.
              *
              * @param path the path of the resource, relative to the current prefix.
              * @return resource as a byte array.
              * @exception Exception on any error while loading the resource.
              */
            protected abstract byte[] loadData(String path)
                    throws Exception;
        }
