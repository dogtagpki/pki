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
// (C) 2014 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package org.dogtagpki.server.tps.cms;

import java.util.Hashtable;

import org.dogtagpki.server.connector.IRemoteRequest;
import org.dogtagpki.tps.main.TPSBuffer;

/**
 * TKSComputeSessionKeyResponse is the class for the response to
 * TKS Remote Request: computeSessionKey()
 *
 */
public class TKSComputeSessionKeyResponse extends TKSResponse
{

    public TKSComputeSessionKeyResponse(Hashtable<String, Object> ht) {
        nameValTable = ht;
    }

    public TPSBuffer getKeySetData() {
        return (TPSBuffer) nameValTable.get(IRemoteRequest.TKS_RESPONSE_KeySetData);
    }

    public TPSBuffer getSessionKey() {
        return (TPSBuffer) nameValTable.get(IRemoteRequest.TKS_RESPONSE_SessionKey);
    }

    public TPSBuffer getEncSessionKey() {
        return (TPSBuffer) nameValTable.get(IRemoteRequest.TKS_RESPONSE_EncSessionKey);
    }

    public TPSBuffer getDRM_Trans_DesKey() {
        return (TPSBuffer) nameValTable.get(IRemoteRequest.TKS_RESPONSE_DRM_Trans_DesKey);
    }

    public TPSBuffer getKeyCheck() {
        return (TPSBuffer) nameValTable.get(IRemoteRequest.TKS_RESPONSE_KeyCheck);
    }

    public TPSBuffer getHostCryptogram() {
        return (TPSBuffer) nameValTable.get(IRemoteRequest.TKS_RESPONSE_HostCryptogram);
    }
}
