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
package com.netscape.cms.servlet.common;

import java.io.File;
import java.io.IOException;
import java.util.Enumeration;
import java.util.Hashtable;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;

/**
 * CMSFileLoader - file cache.
 *
 * @version $Revision$, $Date$
 */

public class CMSFileLoader {
    // default max size
    public final int MAX_SIZE = 200;
    // default number of files to clear when max is reached.
    public final int CLEAR_SIZE = 50;
    // max size property
    public final String PROP_MAX_SIZE = "maxSize";
    // clear size property
    public final String PROP_CLEAR_SIZE = "clearSize";
    // property to cache templates only
    public final String PROP_CACHE_TEMPLATES_ONLY = "cacheTemplatesOnly";

    // hash of files to their content.
    private Hashtable<String, CMSFile> mLoadedFiles = new Hashtable<String, CMSFile>();

    // max number of files
    private int mMaxSize = MAX_SIZE;

    // number of files to clear when max is reached.
    private int mClearSize = CLEAR_SIZE;

    // whether to cache templates and forms only.
    @SuppressWarnings("unused")
    private boolean mCacheTemplatesOnly = true;

    public CMSFileLoader() {
    }

    public void init(IConfigStore config) throws EBaseException {
        mMaxSize = config.getInteger(PROP_MAX_SIZE, MAX_SIZE);
        mClearSize = config.getInteger(PROP_CLEAR_SIZE, CLEAR_SIZE);
        mCacheTemplatesOnly =
                config.getBoolean(PROP_CACHE_TEMPLATES_ONLY, true);
    }

    // Changed by bskim
    //public byte[] get(String absPath) throws EBaseException, IOException {
    //	File file = new File(absPath);
    //	return get(file);
    //}
    public byte[] get(String absPath, String enc) throws EBaseException, IOException {
        File file = new File(absPath);

        return get(file, enc);
    }

    // Change end

    // Changed by bskim
    //public byte[] get(File file) throws EBaseException, IOException {
    //	CMSFile cmsFile = getCMSFile(file);
    public byte[] get(File file, String enc) throws EBaseException, IOException {
        CMSFile cmsFile = getCMSFile(file, enc);

        // Change end
        return cmsFile.getContent();
    }

    // Changed by bskim
    //public CMSFile getCMSFile(File file) throws EBaseException, IOException {
    public CMSFile getCMSFile(File file, String enc) throws EBaseException, IOException {
        // Change end
        String absPath = file.getAbsolutePath();
        long modified = file.lastModified();
        CMSFile cmsFile = mLoadedFiles.get(absPath);
        long lastModified = (cmsFile == null ? 0 : cmsFile.getLastModified());

        // new file.
        if (cmsFile == null || modified != lastModified) {
            // Changed by bskim
            //cmsFile = updateFile(absPath, file);
            cmsFile = updateFile(absPath, file, enc);
            // Change end
        }
        cmsFile.setLastAccess(System.currentTimeMillis());
        return cmsFile;
    }

    // Changed by bskim
    //private CMSFile updateFile(String absPath, File file)
    private CMSFile updateFile(String absPath, File file, String enc)
            // Change end
            throws EBaseException, IOException {
        // clear if cache size exceeded.
        if (mLoadedFiles.size() >= mMaxSize) {
            clearSomeFiles();
        }

        CMSFile cmsFile = null;

        // check if file is a js template or plain template by its first String
        if (absPath.endsWith(CMSTemplate.SUFFIX)) {
            // Changed by bskim
            //cmsFile = new CMSTemplate(file);
            cmsFile = new CMSTemplate(file, enc);
            // End of Change
        } else {
            cmsFile = new CMSFile(file);
        }
        mLoadedFiles.put(absPath, cmsFile); // replace old one if any.
        return cmsFile;
    }

    private synchronized void clearSomeFiles() {

        // recheck this in case some other thread has cleared it.
        if (mLoadedFiles.size() < mMaxSize)
            return;

        // remove the LRU files.
        // XXX could be optimized more.
        Enumeration<CMSFile> elements = mLoadedFiles.elements();

        for (int i = mClearSize; i > 0; i--) {
            long lru = java.lang.Long.MAX_VALUE;
            CMSFile lruFile = null;

            while (elements.hasMoreElements()) {
                CMSFile cmsFile = elements.nextElement();

                if (cmsFile.getLastAccess() < lru) {
                    lruFile = cmsFile;
                }
                mLoadedFiles.remove(lruFile.getAbsPath());
            }
        }
    }
}
