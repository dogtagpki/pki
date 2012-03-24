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
package com.netscape.admin.certsrv.wizard;

import javax.swing.*;
import java.util.Properties;

/**
 * Wizard Data Container
 */
public class WizardInfo extends Properties {

    /*==========================================================
     * variables
     *==========================================================*/
    protected JButton mBNext_Done, mBCancel, mBBack;

    /*==========================================================
     * constructors
     *==========================================================*/
    public WizardInfo() {
        super();
    }

    /*==========================================================
	 * public methods
     *==========================================================*/
    public void addEntry(String name, Object entry) {
        put(name, entry);
    }

    public Object getEntry(String name) {
        return get(name);
    }
    
    /**
     * access method to NEXT-DONE function buttons
     */
    public JButton getNextDoneButton() {
        return mBNext_Done;   
    }
    
    /**
     * access method to CANCEL function buttons
     */
    public JButton getCancelButton() {
        return mBCancel;
    }
    
    /**
     * access method to BACK function buttons
     */    
    public JButton getBackButton() {
        return mBBack;
    }

    /*==========================================================
	 * package methods
     *==========================================================*/
     
    /**
     * set function buttons. Called by the WizardWidget to set the
     * button reference.
     */
    void setButtons(JButton next, JButton cancel, JButton back ) {
        mBNext_Done = next;
        mBCancel = cancel; 
        mBBack = back;
    }
}



