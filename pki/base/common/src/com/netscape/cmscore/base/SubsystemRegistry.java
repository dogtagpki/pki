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
package com.netscape.cmscore.base;

import java.util.Hashtable;

import com.netscape.certsrv.base.ISubsystem;

public class SubsystemRegistry extends Hashtable<String, ISubsystem> {
    private static final long serialVersionUID = 7801949114531559118L;
    private static SubsystemRegistry mInstance = null;

    public static SubsystemRegistry getInstance() {
        if (mInstance == null) {
            mInstance = new SubsystemRegistry();
        }
        return mInstance;
    }

    private SubsystemRegistry() {
        super();
    }

    public ISubsystem get(String key) {
        return super.get(key);
    }

}
