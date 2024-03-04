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

import java.util.PropertyResourceBundle;
import java.util.Locale;
import java.util.Hashtable;
import java.io.InputStream;
import java.io.IOException;

/**
 * The ResourceSet class implements a simple API over the java.util.PropertyResourceBundle
 * class, and the underlying .properties files.
 *
 * @author  David Tompkins
 * @version 0.4 11/3/97
 * @see     PropertyResourceBundle
 */
public class ResourceSet {
    protected static final String separator = "-";
    protected static final char parameter = '%';

    protected static Hashtable cache = new Hashtable();

    protected static String sysLoaderCacheID = "sysLoader"; // null can not be used as a hash key

    protected PropertyResourceBundle prb;
    protected ClassLoader loader;
    protected Object loaderCacheID; // Caching is dene per loader
    protected String loaderName; // For debug statements

    static class StackLookup extends SecurityManager {
        public ClassLoader getLoader() {
            Class[] stack = getClassContext();

            // magic number 3 is the class which called ResourceSet, and
            // we want its loader.
            Class c = stack[3];
            return ((c == null) ? null : c.getClassLoader());
        }
    }

    /**
      * Initialize a ResourceSet.
      *
      * @param bundle a fully-qualified property file, within the current classpath
      *  and excluding the .properties suffix.
      * @param locale the Locale to be used to initialize the Resource Set.
      * @returns a reference to the ResourceSet.
      */
    public ResourceSet(String bundle, Locale locale) {
        loader = new StackLookup().getLoader();
        loaderCacheID = (loader == null) ? (Object) sysLoaderCacheID :
                (Object) loader;
        loaderName = (loader == null) ? sysLoaderCacheID :
                ("loader"+loader.hashCode());
        prb = getBundle(bundle, locale);
    }

    /**
      * A version of the ResourceSet contructor which uses the default Locale.
      *
      * @param bundle a fully-qualified property file, within the current classpath
      *  and excluding the .properties suffix.
      * @returns a reference to the ResourceSet.
      */
    public ResourceSet(String bundle) {
        this(bundle, Locale.getDefault());
    }

    /**
      * Returns the value of a named resource in the ResourceSet.
      * The search order is: "prefix-name", then "name".
      * This version assumes no parameter substitution is neccessary
      * in the value.
      *
      * @param prefix the name prefix of the resource.
      * @param name the name suffix of the resource.
      * @returns the String value of the resource, or null if not found.
      */
    public String getString(String prefix, String name) {
        return getString(prefix, name, (String[]) null);
    }

    /**
      * Returns the value of a named resource in the ResourceSet.
      * The search order is: "prefix-name", then "name".
      * If the value is found and it contains parameter substitution
      * marks (%num, where num is an integer), these marks will be replaced
      * by the corresponding member of the args[] array (args[num]).
      * If num is invalid with respect to args[], then the substitution will
      * not take place.
      *
      * @param prefix the name prefix of the resource.
      * @param name the name suffix of the resource.
      * @param args values for parameter substitution.
      * @returns the String value of the resource, or null if not found.
      */
    public String getString(String prefix, String name, String[] args) {
        if (prb != null) {
            if (prefix != null) {
                try {
                    return substitute(
                            prb.getString(prefix + separator + name), args);
                } catch (Exception e) { }
            }

            try {
                return substitute(prb.getString(name), args);
            } catch (Exception e) { }
        }

        Debug.println(1,
                "ResourceSet:getString():Unable to resolve " +
                prefix + separator + name);
        return null;
    }

    /**
      * This version getString() differs only in that it takes a single String
      * args argument, rather than an array, as a convenience.
      *
      * @param prefix the name prefix of the resource.
      * @param name the name suffix of the resource.
      * @param args a single value for parameter substitution.
      * @returns the String value of the resource, or null if not found.
      */
    public String getString(String prefix, String name, String arg) {
        String[] s = new String[1];
        s[0] = arg;
        return getString(prefix, name, s);
    }

    protected String substitute(String s, String[] args) {
        if (args == null)
            return s;

        char[] val = s.toCharArray();
        StringBuffer sb = new StringBuffer();

        for (int i = 0 ; i < val.length ; i++) {
            if (val[i] != parameter) {
                sb.append(val[i]);
                continue;
            }

            // Check for bad param mark as last character...
            if (++i == val.length) {
                // Shouldn't happen...
                sb.append(val[i]);
                break;
            }

            // get param index
            int num = Character.getNumericValue(val[i]);

            if ((num < 0) || (num >= args.length)) {
                // bad param index. put in an error marker
                sb.append("<error>");
                continue;
            }

            if (args[num] != null)
                sb.append(args[num]);
        }

        return sb.toString();
    }

    /**
      * Since Communicator doesn't want to support PropertyResourceBundles in their classes (for some unknown
      * reason), I've implemented the PropertyResourceBundle loader here for our use.
      *
      * @param bundle the bundle identifier.
      * @param locale the locale.
      * @throws IOException an error in creating the PropertyResourceBundle.
      */
    protected synchronized PropertyResourceBundle getBundle(
            String bundle, Locale locale) {
        PropertyResourceBundle prb;

        // first, check the cache

        if ((prb = getFromCache(bundle)) != null) {
            notifyAll();
            return prb;
        }

        // not cached, so search for it...

        String localeSuffix = "_" + locale.toString();
        String bundleName = bundle.replace('.', '/');

        while (true) {
            String searchName = bundleName + localeSuffix + ".properties";

            InputStream is;

            if (loader != null)
                is = loader.getResourceAsStream(searchName);
            else
                is = ClassLoader.getSystemResourceAsStream(searchName);

            if (is != null) {
                try {
                    prb = new PropertyResourceBundle(is);
                } catch (IOException ioe) {
                    Debug.println(0,
                            "ResourceSet(): unable to process " + bundle);
                    notifyAll();
                    return null;
                }
                putInCache(bundle, prb);
                notifyAll();
                return prb;
            }

            // try again with last locale suffix removed

            int bar = localeSuffix.lastIndexOf('_');

            if (bar == -1) {
                Debug.println(0, "ResourceSet(): unable to open " + bundle);
                notifyAll();
                return null;
            }

            localeSuffix = localeSuffix.substring(0, bar);
        }
    }

    private PropertyResourceBundle getFromCache(String bundle) {
        Hashtable loaderCache = (Hashtable) cache.get(loaderCacheID);
        PropertyResourceBundle prb = null;
        if (loaderCache != null) {
            prb = (PropertyResourceBundle) loaderCache.get(bundle);
        }
        if (Debug.getTraceLevel() == 9) {
            Debug.println(9,
                    "ResourceSet: " + ((prb == null) ? "NOT ":"") +
                    "found in cache " + loaderName + ":"+bundle);
        }
        return prb;
    }

    private void putInCache(String bundle, PropertyResourceBundle prb) {
        Hashtable loaderCache = (Hashtable) cache.get(loaderCacheID);
        if (loaderCache == null) {
            loaderCache = new Hashtable();
            cache.put(loaderCacheID, loaderCache);
            Debug.println(5,
                    "ResourceSet: Create ResourceSet cache for " +
                    loaderName);
        }
        loaderCache.put(bundle, prb);
    }
}
