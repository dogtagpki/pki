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

import javax.swing.ImageIcon;

import java.awt.Toolkit;
import java.awt.Image;
import java.io.*;
import java.util.Hashtable;

/**
 * A version of ImageIcon that retrieves an image
 * from a remote location, such as an HTTP url.
 * The image is caches locally to help optimization.
 */
public class RemoteImage extends ImageIcon {
    /*
     * RemoteImage caching works as follows:
     *   Whenever a RemoteImage is created from scratch, the path is
     *   looked up in the class cache to see if the image has already
     *   been created. If so, the Image from that RemoteImage is
     *   used to initialize the Image for the new RemoteImage,
     *   obviating the need to do an expensive (memory wise)
     *   getSystemImage() operation.
     */
    static private Hashtable _imageCache = new Hashtable();

    protected static String sysLoaderCacheID = "sysLoader"; // null can not be used as a hash key

    protected ClassLoader loader;
    protected Object loaderCacheID; // Caching is dene per loader
    protected String loaderName; // For debug statements

    static class StackLookup extends SecurityManager {
        public ClassLoader getLoader() {
            Class[] stack = getClassContext();

            // magic number 3 is the class which called RemoteImage, and
            // we want its loader.
            Class c = stack[3];
            return ((c == null) ? null : c.getClassLoader());
        }
    }

    public RemoteImage() {
        loader = new StackLookup().getLoader();
        loaderCacheID = (loader == null) ? (Object) sysLoaderCacheID :
                (Object) loader;
        loaderName = (loader == null) ? sysLoaderCacheID :
                ("loader"+loader.hashCode());
    }

    public RemoteImage(Image image) {
        this();
        setImage(image);
    }

    public RemoteImage(String path) {
        this();
        RemoteImage ri;
        if ((ri = getFromCache(path)) != null) {
            // If the image already exists in the cache, use that
            // image to set the image for this RemoteImage and return.
            //Debug.println("RemoteImage: reusing image: " + path);
            setImage(ri.getImage());
            return;
        }

        Image img;

        // First try to find the image as a system resource.
        // This will search the CLASSPATH or codebase, checking
        // archives if found.

        if ((img = getSystemImage(path)) != null) {
            setImage(img);
            setDescription(path);
            putInCache(path, this);
            return;
        }

        if (Permissions.isApplet()) {
            Debug.println(0,
                    "RemoteImage:RemoteImage():unable to load image (" +
                    path + ")");
            return;
        }

        // If we're running as an application, try a relative path
        // from the current working directory. This will throw an
        // exception if the file is not found.
        setImage(Toolkit.getDefaultToolkit().getImage(path));
        setDescription(path);
        putInCache(path, this);
        return;
    }

    protected Image getSystemImage(String path) {
        InputStream is;

        try {
            ClassLoader cl = new StackLookup().getLoader();

            if (cl != null) {
                if ((is = cl.getResourceAsStream(path)) == null)
                    return null;
            } else {
                if ((is = ClassLoader.getSystemResourceAsStream(path)) ==
                        null)
                    return null;
            }

            //byte[] buf = new byte[is.available()];
            //is.read(buf);

			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			byte[] buf = new byte[1024];
			int cnt = -1;
			while((cnt=is.read(buf)) > 0) {
				bos.write(buf,0, cnt);
			}
			buf = bos.toByteArray(); 
            return Toolkit.getDefaultToolkit().createImage(buf);
        } catch (IOException ioe) {
            Debug.println(0, "RemoteImage: " + ioe + "(" + path + ")");
            return null;
        }
        catch (Exception e) {
            Debug.println(0, "RemoteImage: " + e + "(" + path + ")");
            return null;
        }
    }

    private RemoteImage getFromCache(String path) {
        Hashtable loaderCache = (Hashtable)_imageCache.get(loaderCacheID);
        RemoteImage image = null;
        if (loaderCache != null) {
            image = (RemoteImage) loaderCache.get(path);
        }
        if (Debug.getTraceLevel() == 9) {
            Debug.println(9,
                    "RemoteImage: " + ((image == null) ? "NOT ":"") +
                    "found in cache " + loaderName + ":"+path);
        }
        return image;
    }

    private void putInCache(String path, RemoteImage image) {
        Hashtable loaderCache = (Hashtable)_imageCache.get(loaderCacheID);
        if (loaderCache == null) {
            loaderCache = new Hashtable();
            _imageCache.put(loaderCacheID, loaderCache);
            Debug.println(9,
                    "RemoteImage: Create RemoteImage cache for " +
                    loaderName);
        }
        loaderCache.put(path, image);
    }

}
