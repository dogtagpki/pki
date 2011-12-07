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
package com.netscape.certsrv.request;

/**
 * The INotify interface defines operations that are invoked when a request is
 * completely processed. A class implementing this interface may be registered
 * with a IRequestQueue. The interface will be invoked when a request is
 * completely serviced by the IService object.
 * 
 * @version $Revision$ $Date$
 */
public interface INotify {

    /**
     * Provides notification that a request has been completed. The
     * implementation may use values stored in the IRequest object, and may
     * implement any type publishing (such as email or writing values into a
     * directory)
     * 
     * @param request the request that is completed.
     */
    public void notify(IRequest request);
}
