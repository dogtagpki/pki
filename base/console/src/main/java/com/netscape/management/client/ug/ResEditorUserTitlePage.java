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

package com.netscape.management.client.ug;

import java.awt.*;
import java.util.*;

import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;

import javax.swing.*;


/**
 * ResEditorUserTitlePage is used when editing a user entry. This panel
 * occupies the top portion of the ResourceEditor.
 *
 * @see ResourceEditor
 */
public class ResEditorUserTitlePage extends JPanel implements Observer {

    JLabel _name, _department, _faxPhone, _wPhone;
    JLabel _imageLabel;
    static private RemoteImage _defaultIcon =
        new RemoteImage("com/netscape/management/nmclf/icons/user24.gif");

    /**
     * Constructor
     *
     * @param observable  the observable object
     */
    public ResEditorUserTitlePage(ResourcePageObservable observable) {
        super(true);
        String name = "", title = "", workphone = "", faxphone = "";

        name = observable.get("cn", 0);
        workphone = observable.get("telephonenumber", 0);
        faxphone = observable.get("facsimiletelephonenumber", 0);
        title = observable.get("ou", 0);

        init(name, title, workphone, faxphone, getPhotoAttribute(observable));
    }

    /**
     * Constructor
     *
     * @param name       the name of the person
     * @param title      job title
     * @param workPhone  work phone number
     * @param faxPhone   fax number
     */
    public ResEditorUserTitlePage(String name, String title,
                                  String workPhone, String faxPhone) {
        super(true);
        init(name, title, workPhone, faxPhone, null);
    }

    /**
     * Sets the name of the person.
     *
     * @param name  the name of the person
     */
    public void setName(String name) {
        _name.setText(name);
    }

    /**
     * Sets the title of the person.
     *
     * @param title  job title
     */
    public void setTitle(String title) {
        _department.setText(title);
    }

    /**
     * Sets the work phone number for the person.
     *
     * @param workPhone  work phone number
     */
    public void setWorkPhone(String workPhone) {
        _wPhone.setText(workPhone);
    }

    /**
     * Sets the fax number for the person.
     *
     * @param faxPhone  fax number
     */
    public void setFaxPhone(String faxPhone) {
        _faxPhone.setText(faxPhone);
    }


    /**
     * Implements the Observer interface. Updates the information in
     * this pane when called.
     *
     * @param o    the observable object
     * @param arg  argument
     */
    public void update(Observable o, Object arg) {
        ResourcePageObservable observable = (ResourcePageObservable) o;

        _name.setText(observable.get("cn", 0));
        _wPhone.setText(observable.get("telephonenumber", 0));
        _faxPhone.setText(observable.get("facsimiletelephonenumber", 0));
        _department.setText(observable.get("ou", 0));
        // Update the user image
        ImageIcon icon = createImageIcon(getPhotoAttribute(observable));
        if (_imageLabel != null && _imageLabel.getIcon() != icon ) {
            _imageLabel.setIcon(icon);
        }
    }

    /**
     * Lays out the components for this panel.
     *
     * @param name       the name of the person
     * @param title      job title
     * @param workPhone  work phone number
     * @param faxPhone   fax number
     * @param photo      picture for person
     */
    void init(String name, String title, String workPhone,
              String faxPhone, byte[] photo) {

        GridBagLayout layout = new GridBagLayout();
        GridBagConstraints c = new GridBagConstraints();
        setLayout(layout);

        JLabel lblPhone, lblFax;

        PickerEditorResourceSet resource = new PickerEditorResourceSet();

        lblPhone =
            new JLabel(resource.getString("userTitlePage", "phoneWork"),
                       SwingConstants.RIGHT);
        lblPhone.setLabelFor(_wPhone);
        c.fill = GridBagConstraints.BOTH;
        c.gridx = 3;
        c.gridy = 1;
        c.gridwidth = 1;
        c.gridheight = 1;
        c.anchor = GridBagConstraints.NORTHWEST;
        c.weightx = 0;
        c.weighty = 0;
        layout.setConstraints(lblPhone, c);
        add(lblPhone);

        lblFax = new JLabel(resource.getString("userTitlePage", "phoneFax"),
                            SwingConstants.RIGHT);
        lblFax.setLabelFor(_faxPhone);
        c.gridy = 2;
        layout.setConstraints(lblFax, c);
        add(lblFax);

        _name = new SuiTitle("");
        c.gridx = 1;
        c.gridy = 0;
        c.insets = new Insets(0, SuiLookAndFeel.COMPONENT_SPACE, 0,
                              SuiLookAndFeel.COMPONENT_SPACE);
        layout.setConstraints(_name, c);
        add(_name);
        _department = new JLabel("");
        c.gridx = 1;
        c.gridy = 1;
        c.gridheight = 2;
        layout.setConstraints(_department, c);
        add(_department);
        _wPhone = new JLabel("");
        c.gridx = 4;
        c.gridy = 1;
        c.gridheight = 1;
        layout.setConstraints(_wPhone, c);
        add(_wPhone);
        _faxPhone = new JLabel("");
        c.gridx = 4;
        c.gridy = 2;
        layout.setConstraints(_faxPhone, c);
        add(_faxPhone);

        _imageLabel = new JLabel(createImageIcon(photo));
        _imageLabel.getAccessibleContext().setAccessibleDescription(resource.getString("userTitlePage", "photo_tt"));
        c.gridx = 0;
        c.gridy = 0;
        c.gridheight = 3;
        c.insets = new Insets(SuiLookAndFeel.COMPONENT_SPACE,
                              SuiLookAndFeel.COMPONENT_SPACE,
                              SuiLookAndFeel.COMPONENT_SPACE,
                              SuiLookAndFeel.COMPONENT_SPACE);
        c.anchor = GridBagConstraints.CENTER;
        layout.setConstraints(_imageLabel, c);
        add(_imageLabel);

        JLabel label = new JLabel();
        c.gridx = 2;
        c.gridy = 0;
        c.weightx = 1;
        c.insets = new Insets(0, 0, 0, 0);
        layout.setConstraints(label, c);
        add(label);

        label = new JLabel();
        c.gridx = 2;
        c.gridy = 1;
        c.weightx = 1;
        c.gridheight = 2;
        layout.setConstraints(label, c);
        add(label);

        label = new JLabel();
        c.gridx = 2;
        c.gridy = 1;
        c.weightx = 0;
        c.gridheight = 1;
        c.gridwidth = GridBagConstraints.REMAINDER;
        layout.setConstraints(label, c);
        add(label);

        setName(name);
        setTitle(title);
        setWorkPhone(workPhone);
        setFaxPhone(faxPhone);
    }

    /**
     * Creates an icon from a byte array
     */
    private ImageIcon createImageIcon(byte[] photo) {
        if (photo != null) {
            ImageIcon icon = new ImageIcon(photo);
            Image img = icon.getImage();
            if (img != null) {
                if (img.getHeight(null) > 30) {
                    img = img.getScaledInstance(-1, 30, Image.SCALE_FAST);
                    icon = new ImageIcon(img);
                }
            }
            return icon;

        } else {
            return _defaultIcon;
        }
    }

    /**
     * Return user photo stored as 'photo' or 'jpegphoto' attribute.
     */
    private byte[] getPhotoAttribute(ResourcePageObservable observable) {    
        byte photo[] = observable.getBytes("photo");
        if (photo == null) {
            photo = observable.getBytes("jpegphoto");
        }
        return photo;
    }
}
