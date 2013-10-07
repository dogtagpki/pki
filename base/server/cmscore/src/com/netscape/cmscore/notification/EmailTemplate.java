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
package com.netscape.cmscore.notification;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.notification.IEmailTemplate;

/**
 * Files to be processed and returned to the requested parties. It
 * is a template with $tokens to be used by the form/template processor.
 *
 *
 * @author cfu
 * @version $Revision$, $Date$
 */

public class EmailTemplate implements IEmailTemplate {

    /*==========================================================
     * variables
     *==========================================================*/

    /* private variables */
    private String mTemplateFile = "";
    private ILogger mLogger = CMS.getLogger();

    /* public vaiables */
    public String mFileContents;

    /*==========================================================
     * constructors
     *==========================================================*/

    /**
     * Default Constructor
     *
     * @param templateFile File name of the template including the full path and
     *            file extension
     */

    public EmailTemplate(String templatePath) {
        mTemplateFile = templatePath;
    }

    /*==========================================================
     * public methods
     *==========================================================*/

    /*
     * Load the template from the file
     *
     * @return true if successful
     */
    public boolean init() {

        File template = new File(mTemplateFile);

        /* check if file exists and is accessible */
        if ((!template.exists()) || (!template.canRead()) || (template.isDirectory())) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_NOTIFY_TEMPLATE_NOT_EXIST", mTemplateFile));
            return false;
        }

        /* create input stream */
        FileReader input;

        try {
            input = new FileReader(template);
        } catch (FileNotFoundException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_NOTIFY_TEMPLATE_NOT_FOUND", mTemplateFile));

            return false;
        }

        /* load template */
        mFileContents = loadFile(input);
        if (mFileContents == null) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_NOTIFY_TEMPLATE_LOAD_ERROR"));
            return false;
        }

        // close the stream
        try {
            input.close();
        } catch (IOException e) {
            return false;
        }
        return true;
    }

    /**
     * @return Template Name in string form
     */
    public String getTemplateName() {
        return mTemplateFile;
    }

    /**
     * @return true if template is an html file, false otherwise
     */
    public boolean isHTML() {
        if (mTemplateFile.endsWith(".html") ||
                mTemplateFile.endsWith(".HTML") ||
                mTemplateFile.endsWith(".htm") ||
                mTemplateFile.endsWith(".HTM"))
            return true;
        else
            return false;
    }

    /**
     * @return Content of the template
     */
    public String toString() {
        return mFileContents;
    }

    /*==========================================================
     * private methods
     *==========================================================*/

    /* load file into string */
    private String loadFile(FileReader input) {

        BufferedReader in = new BufferedReader(input);
        StringBuffer buf = new StringBuffer();
        String line;

        try {
            while ((line = in.readLine()) != null) {
                buf.append(line);
                buf.append("\n");
            }
        } catch (IOException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_NOTIFY_TEMPLATE_LOADING"));
            return null;
        }

        return buf.toString();
    }

    public int length() {
        return (mFileContents == null) ? 0 : mFileContents.length();
    }

    private void log(int level, String msg) {
        if (mLogger == null)
            return;
        mLogger.log(ILogger.EV_SYSTEM, null, ILogger.S_OTHER,
                level, msg);
    }

}
