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
package com.netscape.certsrv.notification;


import java.lang.*;
import java.io.*;
import java.util.*;

import com.netscape.certsrv.logging.*;
import com.netscape.certsrv.notification.*;


/**
 * Files to be processed and returned to the requested parties. It
 * is a template with $tokens to be used by the form/template processor.
 *
 * @version $Revision$, $Date$
 */

public interface IEmailTemplate {

    public boolean init();

    /**
     * @return Template Name in string form
     */
    public String getTemplateName();

    /** 
     * @return true if template is an html file, false otherwise
     */
    public boolean isHTML();

    /**
     * @return Content of the template
     */
    public String toString();

    public int length();

}
