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
public class TKSComputeSessionKeyResponse extends RemoteResponse
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

    public TPSBuffer getDRM_Trans_AesKey() {
        return (TPSBuffer) nameValTable.get(IRemoteRequest.TKS_RESPONSE_DRM_Trans_AesKey);
    }

    public TPSBuffer getKeyCheck() {
        return (TPSBuffer) nameValTable.get(IRemoteRequest.TKS_RESPONSE_KeyCheck);
    }

    // Applet and Alg Selection by Token Range Support
    public TPSBuffer getKeyCheckDes() {
        return (TPSBuffer) nameValTable.get(IRemoteRequest.TKS_RESPONSE_KeyCheck_Des);
    }

    public TPSBuffer getHostCryptogram() {
        return (TPSBuffer) nameValTable.get(IRemoteRequest.TKS_RESPONSE_HostCryptogram);
    }

    public TPSBuffer getKekWrappedDesKey() {
        return (TPSBuffer) nameValTable.get(IRemoteRequest.TKS_RESPONSE_KEK_DesKey);
    }

    public TPSBuffer getKekWrappedAesKey() {
        return (TPSBuffer) nameValTable.get(IRemoteRequest.TKS_RESPONSE_KEK_AesKey);
    }

    public TPSBuffer getKekSessionKey() {
        return (TPSBuffer) nameValTable.get(IRemoteRequest.TKS_RESPONSE_KekSessionKey);
    }

    public TPSBuffer getMacSessionKey() {
        return (TPSBuffer) nameValTable.get(IRemoteRequest.TKS_RESPONSE_MacSessionKey);
    }
}
