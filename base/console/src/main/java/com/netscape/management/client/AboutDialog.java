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
package com.netscape.management.client;

import javax.swing.*;
import javax.swing.border.*;

import java.awt.*;

import com.netscape.management.client.util.*;
import com.netscape.management.client.console.*;

/**
 * AboutDialog is a class to display a standard "about box",
 * which conveys the product's version and copyright information.
 *
 * The dialog content can be customized in three ways:
 * 1) The dialog title; specified through the contructor.
 * 2) The product name; specified through the setProduct method.
 * 3) Information on one or more vendors, specified through the addVendor method.
 *
 * The visual specification for AboutDialog can be found at:
 * http://gooey/servers/visual/spec/layout/about.html"
 *
 * @author shihcm@netscape.com
 */
public class AboutDialog extends AbstractDialog {

    //Main panel
    JPanel content;


    //where all vendors' license reside
    JPanel vendors = new JPanel();
    int yIndex = 0;


    /**
     * Creates an AboutDialog with the title "About productName", and
     * a scroll pane which displays license and vendor information.
     *
     * @param parent		the parent frame for this dialog
     * @param productName	the product name; appears in the dialog title; prefixed with "About "
     */
    public AboutDialog(Frame parent, String productName) {
        super(parent, "", OK);

        setModal(true);

        setTitle(
                (new ResourceSet("com.netscape.management.client.default")).
                getString("aboutDialog", "dialogTitlePrefix") +
                productName);

        vendors.setLayout(new GridBagLayout());

        content = new JPanel();
        content.setLayout(new GridBagLayout());

        JScrollPane sp = new JScrollPane(vendors,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
		Border border = UITools.createLoweredBorder();
		sp.setBorder(border);
        GridBagUtil.constrain(content, sp, 1, 1, 1, 1, 1, 1,
                GridBagConstraints.NORTH, GridBagConstraints.BOTH, 0,
                0, 0, 0);

        super.getContentPane().add(content);
        setMinimumSize(432, 350);

    }

    /**
      * Specifies product information for this dialog.
      *
      * @param logo		the product logo; appears in top left corner of dialog
      * @param copyright	copyright text; appears right of logo
      * @param license	license information; appears at top of scrollable region; may be multi-line
      */
    public void setProduct(Icon logo, String copyright, String license) {
        if (logo != null) {
            GridBagUtil.constrain(content, new JLabel(logo), 0, 0, 1,
                    1, 0, 0, GridBagConstraints.NORTHWEST,
                    GridBagConstraints.NONE, 0, 0,
                    SEPARATED_COMPONENT_SPACE, DIFFERENT_COMPONENT_SPACE);
        }


        GridBagUtil.constrain(content, new MultilineLabel(copyright + "\n\n" +
                (new ResourceSet("com.netscape.management.client.default")).
                getString("aboutDialog", "dialogFrameworkPrefix") + " " +
                VersionInfo.getVersionNumber()),
                1, 0, 1, 1, 1, 0, GridBagConstraints.NORTH,
                GridBagConstraints.HORIZONTAL, 0, 0,
                SEPARATED_COMPONENT_SPACE, 0);

        addVendor(null, license);


    }

    class HorizontalLine extends Component {
        int thickness = 1;
        public void paint(Graphics g) {
            int w = getSize().width;

            g.setColor(Color.black);
            g.fillRect(0, 0, w, thickness);
        }
    }

    /**
      * Specifies information about a vendor whose services are
      * (example: code libraries) have been used in this product.
      * The vendor information is displayed in the scrollable
      * region of the dialog.  Each vendor is seperated by a
      * horizontal line.
      *
      * @param logo		icon specifing vendor's logo
      * @param license	string specifying vendor's license or copyright message; may be multi-line
      */
    public void addVendor(Icon logo, String license) {
        if (yIndex > 0) {
            GridBagUtil.constrain(vendors, new HorizontalLine(), 0,
                    ++yIndex, 1, 1, 1, 0, GridBagConstraints.NORTH,
                    GridBagConstraints.HORIZONTAL, 0, 0, 0, 0);
        }

        if (logo != null) {
            GridBagUtil.constrain(vendors, new JLabel(logo), 0,
                    ++yIndex, 1, 1, 0, 0, GridBagConstraints.NORTHWEST,
                    GridBagConstraints.NONE, HORIZ_COMPONENT_INSET,
                    HORIZ_COMPONENT_INSET, 0, 0);
        }

        GridBagUtil.constrain(vendors, new MultilineLabel(license), 0,
                ++yIndex, 1, 1, 1, 0, GridBagConstraints.NORTH,
                GridBagConstraints.HORIZONTAL, 0,
                HORIZ_COMPONENT_INSET, DIFFERENT_COMPONENT_SPACE, 0);
    }


    /**
      * Displays the about dialog on the screen; is modal.
      */
    public void show() {
        GridBagUtil.constrain(vendors, Box.createVerticalGlue(), 0,
                ++yIndex, 1, 1, 1, 1, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0,
                DIFFERENT_COMPONENT_SPACE, 0);
        super.show();
    }

}
