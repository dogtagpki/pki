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
package com.netscape.admin.certsrv.status;

import java.awt.*;
import java.util.*;
import java.text.*;
import java.io.*;
import java.awt.event.*;
import javax.swing.*;
import com.netscape.admin.certsrv.*;
import com.netscape.certsrv.common.*;
import com.netscape.management.client.util.*;

/**
 * Parse the log in the following default format:
 *      pid.thread - [SIMPLEDATEFORMAT][resource][level][message]
 *
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.status
 */
class DefaultLogParser implements ILogParser {

    /*==========================================================
     * variables
     *==========================================================*/
    private final String SOURCE_PROPERTY = "LOGCONTENT_COMBOBOX_SOURCE_VALUE_";
    private final String LEVEL_PROPERTY = "LOGCONTENT_COMBOBOX_LOGLEVEL_VALUE_";

    private final String DATE_PATTERN = "dd/MMM/yyyy:hh:mm:ss z";
    protected ResourceBundle mResource;

    /*==========================================================
     * constructors
     *==========================================================*/
    public DefaultLogParser() {
        mResource = ResourceBundle.getBundle(CMSAdminResources.class.getName());
    }

    /*==========================================================
	 * public methods
     *==========================================================*/
    public Vector parse(Object entry) throws ParseException {
        String logEntry = (String)entry;
        //parsing the log Entry and return segments
        //Debug.println("LogDataModel: DefaultLogParser: parse() -" +logEntry);
        int x = logEntry.indexOf("[");
        if (x == -1)
            throw new ParseException(logEntry,0);
        String temp = logEntry.substring(x+1);
        x = temp.indexOf("]");
        if (x == -1)
            throw new ParseException(logEntry,0);

        String dateStr = temp.substring(0,x);
        //Debug.println("LogDataModel: DefaultLogParser: parse() -"+dateStr+" "+temp);
        SimpleDateFormat format = new SimpleDateFormat(DATE_PATTERN);
        Date date = format.parse(dateStr);
        String dateColumn = DateFormat.getDateInstance().format(date);
        String timeColumn = DateFormat.getTimeInstance().format(date);

        //Debug.println("LogDataModel: DefaultLogParser: parse() -"+dateColumn+" "+timeColumn);
        temp = temp.substring(x+2);
        x = temp.indexOf("]");
        if (x == -1)
            throw new ParseException(logEntry,0);
        String source = temp.substring(1,x);
        temp = temp.substring(x+2);
        x = temp.indexOf("]");
        if (x == -1)
            throw new ParseException(logEntry,0);
        String level = temp.substring(1,x);
        temp = temp.substring(x+2);
        Vector row = new Vector();
        row.addElement(getSourceString(source));
        row.addElement(getLevelString(level));
        row.addElement(dateColumn);
        row.addElement(timeColumn);
        JLabel detail = new JLabel(temp);
        detail.setToolTipText(temp);
        row.addElement(detail);
        return row;
    }

    public String getSourceString(String code) {
        try {
            return mResource.getString(SOURCE_PROPERTY+code);
        } catch (MissingResourceException e) {
            return code;
        }
    }

    public String getLevelString(String code) {
        try {
            return mResource.getString(LEVEL_PROPERTY+code);
        } catch (MissingResourceException e) {
            return code;
        }
    }

}