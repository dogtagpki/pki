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

import java.util.*;
import java.io.*;
import java.net.*;


public class Certificate_Record {

    public String revokedOn = null;
    public String revokedBy = null;
    public String revocation_info = null;
    public String signatureAlgorithm = null;
    public String serialNumber = null;
    public String subjectPublicKeyLength = null;
    public String type = null;
    public String subject = null;
    public String issuedOn = null;
    public String validNotBefore = null;
    public String validNotAfter = null;
    public String issuedBy = null;
    public String subjectPublicKeyAlgorithm = null;
    public String certChainBase64 = null;
    public String certFingerprint = null;
    public String pkcs7ChainBase64 = null;
    public String certPrettyPrint = null;

    public Certificate_Record() {// Do nothing
    }

}


;
