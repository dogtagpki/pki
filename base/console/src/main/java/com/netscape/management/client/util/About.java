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

import java.awt.Dimension;
import java.io.File;
import java.net.URL;
import java.util.StringTokenizer;

import javax.swing.BoxLayout;
import javax.swing.ImageIcon;
import javax.swing.JEditorPane;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JViewport;
import javax.swing.border.BevelBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.SoftBevelBorder;

/**
 * A dialog that displays an About screen.
 */
public class About extends AbstractDialog {

    Dimension company_logoDimension, other_logoDimension;
    String fileLoc;

    ResourceSet _resource;


    /**
     * Constructor.  Version 0.0000001  expect more changes comming
     * <p>Property file example: <A href="http://buddha/aboutDialog/aboutdialog.html">http://buddha/aboutDialog/aboutdialog.html</A>
     * <p>usage:  About aboutDialog = new About(parentFrame, new ResourceSet("mypropertyFile"));
     *
     * @param parent         the owner of the dialog
     * @param resourceSet    about dialog parameters
     * @deprecated           replaced by com.netscape.management.client.AboutDialog
     */
    @Deprecated
    public About(JFrame parent, ResourceSet resourceSet) {
        //create a modal dialog with ok button
        super(parent, "", true, OK);

        _resource = resourceSet;

        try {
            JPanel aboutPane = new JPanel();
            aboutPane.setLayout(
                    new BoxLayout(aboutPane, BoxLayout.Y_AXIS));

            company_logoDimension = new Dimension( Integer.parseInt(
                    _resource.getString("", "company_maxWidth")),
                    Integer.parseInt(_resource.getString("", "company_maxHeight")));

            other_logoDimension = new Dimension( Integer.parseInt(
                    _resource.getString("", "other_maxWidth")),
                    Integer.parseInt(_resource.getString("", "other_maxHeight")));

            fileLoc = _resource.getString("", "fileLocation");

            aboutPane.add(createTitlePane());

            setMinimumSize(
                    Integer.parseInt(_resource.getString("", "dialogWidth"))
                    , Integer.parseInt(_resource.getString("", "dialogHeight")));

            JPanel thirdPartyLogosPane = new JPanel();
            thirdPartyLogosPane.setLayout(
                    new BoxLayout(thirdPartyLogosPane, BoxLayout.Y_AXIS));
            JScrollPane scroller = new JScrollPane();
            scroller.setBorder(new SoftBevelBorder(BevelBorder.LOWERED));
            JViewport vp = scroller.getViewport();
            vp.add(thirdPartyLogosPane);
            vp.setBackingStoreEnabled(true);
            vp.setSize(0, 0);
            vp.setPreferredSize(new Dimension(0, 0));
            scroller.setPreferredSize(new Dimension(0, 0));

            for (int i = 1; ;i++) {
                if (_resource.getString("", "company"+i) != null) {
                    thirdPartyLogosPane.add( createContentPane("company"+i,
                            other_logoDimension));
                } else {
                    break;
                }
            }
            aboutPane.add(scroller);

            getContentPane().add(aboutPane);
        } catch (Exception e) {
            Debug.println(0, "client.util.about: Resource not found!");
            return;
        }

        setResizable(false);
    }


    /**
      * Title pane will contain copyright
      */
    JPanel createTitlePane() {
        JPanel titlePane = new JPanel();
        titlePane.setLayout(new BoxLayout(titlePane, BoxLayout.Y_AXIS));
        titlePane.add(
                createContentPane("company", company_logoDimension));
        return titlePane;
    }


    /**
      * Content pane will contain one single copyright of another company.
      */
    JPanel createContentPane(String index, Dimension iconSize) {
        JPanel othersPane = new JPanel();
        othersPane.setLayout(new BoxLayout(othersPane, BoxLayout.X_AXIS));

        // get resource string, figure out which logo file and copyright file to grab
        // path is relative to datadir
        // copyright and logo info will stay under datadir/manual/
        StringTokenizer st =
                new StringTokenizer(_resource.getString("", index), ",\n\r");
        String htmlFile = "";
        String imageFile = "";
        try {
            htmlFile = st.nextToken();
            imageFile = st.nextToken();
        } catch (Exception e) {
            Debug.println(0, "About: invalid properties file!");
            return othersPane;
        }

        JLabel l = null;
        //add logo icon
        try {
            l = new JLabel( new ImageIcon( (new URL("file:"+
                    (new File("..")).getCanonicalPath() +
                    File.separator + fileLoc + File.separator +
                    imageFile)), index));
            l.getAccessibleContext().setAccessibleDescription(_resource.getString("","logo"));
            l.setPreferredSize(iconSize);
        } catch (Exception e) {
            Debug.println(0, "About: image not found, or invalid image type!");
            return othersPane;
        }

        othersPane.add(l);
        //add copyright text
        try {
            JEditorPane editor = new JEditorPane("file:"+
                    (new File("..")).getCanonicalPath() +
                    File.separator + fileLoc + File.separator + htmlFile);
            //don't want to have any inset
            editor.setBorder(new EmptyBorder(0, 0, 0, 0));
            editor.setEditable(false);
            editor.setOpaque(false);
            othersPane.add(editor);
        } catch (Exception e) {
            Debug.println(0, "About: license not found, or invalid html document!");
            return othersPane;
        }

        return othersPane;
    }


    /*
     public static void main(String arg[]) {
         JFrame f = new JFrame();
         f.setBounds(300,200,200,200);
         f.show();
         JDialog d = (new About(f, (new ResourceSet("com.netscape.management.admserv.about"))));
         d.show();
     }
     */
}

