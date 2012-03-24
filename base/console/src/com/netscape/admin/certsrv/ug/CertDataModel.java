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
package com.netscape.admin.certsrv.ug;

import com.netscape.admin.certsrv.*;
import com.netscape.certsrv.common.*;
import com.netscape.management.client.util.*;
import java.util.*;
import javax.swing.*;

/**
 * Certificate Data Model
 * Single column display with internal data object as NVP
 * which stores Name and Data Blob (PrettyPrint or B64E)
 */
public class CertDataModel extends CMSContentTableModel
    implements IDataProcessor
{
    /*==========================================================
     * variables
     *==========================================================*/
    public static final String CERT_NAME="CERT_NAME";
    public static final String CERT_DATA="CERT_DATA";
    public static final String CERT_VIEW="CERT_VIEW";
    public static final String CERT_B64E="CERT_B64E";
    public static final String CERT_PP="CERT_PP";

    private static String[] mColumns = {CERTIFICATE};

    /*==========================================================
     * constructors
     *==========================================================*/
    public CertDataModel() {
        super();
        init(mColumns);
    }

    /*==========================================================
	 * public methods
     *==========================================================*/
    public void processData(Object data) {
        Vector v = new Vector();

        NameValuePairs obj = (NameValuePairs) data;

        //XXX NEED TO CHANGE if we are going to have multi-column table
        v.addElement(new JLabel(obj.get(CERT_NAME),
            CMSAdminUtil.getImage(CMSAdminResources.IMAGE_CERTICON_SMALL),
            JLabel.LEFT));
        addRow(v, data);
    }

    /**
     * Retrieve the data blob, Certificate Pretty Print
     * or Base64Encode cert, from the data object. Used
     * by the view functionality.
     *
     * @param row cert table row number
     * @retrun data in string format
     */
    public String getDataBlob(int row) {
        try {
            NameValuePairs obj = (NameValuePairs)getObjectValueAt(row);
            return obj.get(CERT_DATA);
        } catch (Exception e) {
            Debug.println("CertDataModel: getDataBlob()- "+e.toString());
            return "";
        }
    }
}