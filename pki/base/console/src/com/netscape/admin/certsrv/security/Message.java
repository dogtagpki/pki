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
package com.netscape.admin.certsrv.security;

import java.util.*;
import java.io.*;
import com.netscape.management.client.util.Debug;

class Index {
    String _indexValue;
    int _pos;

    public Index(String indexValue, int pos) {
        _indexValue = indexValue;
        _pos = pos;
    }

    public String getIndexValue() {
        return _indexValue;
    }

    public int getPos() {
        return _pos;
    }
}
class Message {

    public final static int NMC_SUCCESS = 0;
    public final static int NMC_FAILURE = 1;
    public final static int NMC_WARNING = 2;
    public final static int NMC_UNKNOWN = 3;

    /*    final static int FILE_ERROR              = 0;
    final static int MEMORY_ERROR            = 1;
    final static int SYSTEM_ERROR            = 2;
    final static int INCORRECT_USAGE         = 3;
    final static int ELEM_MISSING            = 4;
    final static int REGISTRY_DATABASE_ERROR = 5;
    final static int NETWORK_ERROR           = 6;
    final static int GENERAL_FAILURE         = 7;
    final static int APP_ERROR               = 8;
    final static int WARNING                 = 9;*/

    final static int DEFAULT_ERROR = 3;

    final static String NMC_STATUS = "NMC_Status:";
    final static String NMC_ERRTYPE = "NMC_ErrType:";
    final static String NMC_ERRINFO = "NMC_ErrInfo:";
    final static String NMC_ERRDETAIL = "NMC_ErrDetail:";
    final static String NMC_DESCRIPTION = "NMC_Description:";
    final static String NMC_EXTRA = "NMC_EXTRA:";

    int NMC_Status = -1;
    //int    NMC_ErrType     = -1;
    String NMC_ErrType = "";
    String NMC_ErrInfo = "";
    String NMC_ErrDetail = "";
    String NMC_Description = "";
    String NMC_Extra = "";

    public Message(String message) {
        Vector indexes = new Vector();
        int pos1 = message.indexOf(NMC_STATUS);
        if (pos1 != -1) {
            indexes.addElement(new Index(NMC_STATUS, pos1));
        }

        int pos2 = message.indexOf(NMC_ERRTYPE);
        if (pos2 != -1) {
            indexes.addElement(new Index(NMC_ERRTYPE, pos2));
        }

        int pos3 = message.indexOf(NMC_ERRINFO);
        if (pos3 != -1) {
            indexes.addElement(new Index(NMC_ERRINFO, pos3));
        }

        int pos4 = message.indexOf(NMC_ERRDETAIL);
        if (pos4 != -1) {
            indexes.addElement(new Index(NMC_ERRDETAIL, pos4));
        }

        int pos5 = message.indexOf(NMC_DESCRIPTION);
        if (pos5 != -1) {
            indexes.addElement(new Index(NMC_DESCRIPTION, pos5));
        }

        int extraIndex = message.indexOf('\n',
                Math.max(
                Math.max(Math.max(pos1, pos2), Math.max(pos3, pos4)),
                pos5));
        if (extraIndex != -1) {
            NMC_Extra = message.substring(extraIndex + 1, message.length());

            /* temp solution until Yu-Jen can think up another header schema */
            NMC_Extra =
                    KeyCertUtility.replace(NMC_Extra, "Content-type: text/html", "");
        }
        indexes.addElement(new Index(NMC_EXTRA, extraIndex + 1));

        int size = indexes.size();
        for (int i = 0; i < size - 1; i++) {
            Index beginIndex = (Index)(indexes.elementAt(i));
            Index endIndex = (Index)(indexes.elementAt(i + 1));
            if (beginIndex.getIndexValue().equals(NMC_STATUS)) {
                String val = message.substring(beginIndex.getPos() +
                        NMC_STATUS.length(), endIndex.getPos());
                NMC_Status = Integer.parseInt(val.trim());
            } else if (
                    beginIndex.getIndexValue().equals(NMC_DESCRIPTION)) {
                NMC_Description = message.substring(beginIndex.getPos() +
                        NMC_DESCRIPTION.length(), endIndex.getPos());
            } else if (beginIndex.getIndexValue().equals(NMC_ERRTYPE)) {
                NMC_ErrType = message.substring(beginIndex.getPos() +
                        NMC_ERRTYPE.length(), endIndex.getPos());
            } else if (beginIndex.getIndexValue().equals(NMC_ERRINFO)) {
                NMC_ErrInfo = message.substring(beginIndex.getPos() +
                        NMC_ERRINFO.length(), endIndex.getPos());
            } else if (beginIndex.getIndexValue().equals(NMC_ERRDETAIL)) {
                NMC_ErrDetail = message.substring(beginIndex.getPos() +
                        NMC_ERRDETAIL.length(), endIndex.getPos());
            }
        }

    }

    public int getStatus() {
        return NMC_Status;
    }

    public boolean isSuccess() {
        return (getStatus() == NMC_SUCCESS);
    }
    public boolean isFailure() {
        return (getStatus() == NMC_FAILURE);
    }
    public boolean isWarning() {
        return (getStatus() == NMC_WARNING);
    }
    public boolean isUnknown() {
        return (getStatus() == NMC_UNKNOWN);
    }

    public String getStatusString() {
        String status = "";
        switch (NMC_Status) {
        case NMC_SUCCESS:
            status = "Success";
            break;
        case NMC_FAILURE:
            status = "Failure";
            break;
        case NMC_WARNING:
            status = "Warning";
            break;
        case NMC_UNKNOWN:
            status = "Unknown";
            break;
        }
        return status;
    }

    public String getErrorType() {
        return NMC_ErrType;
    }

    /*int getErrorType(String errorType) {
         int errVal = -1;
         if (errorType.indexOf("FILE ERROR") != -1) {
             errVal = FILE_ERROR;
         } else if (errorType.indexOf("MEMORY ERROR") != -1) {
             errVal = MEMORY_ERROR;
         } else if (errorType.indexOf("SYSTEM ERROR") != -1) {
             errVal = SYSTEM_ERROR;
         } else if (errorType.indexOf("INCORRECT USAGE") != -1) {
             errVal = INCORRECT_USAGE;
         } else if (errorType.indexOf("ELEMENT MISSING") != -1) {
             errVal = ELEM_MISSING;
         } else if (errorType.indexOf("REGISTRY DATABASE ERROR") != -1) {
             errVal = REGISTRY_DATABASE_ERROR;
         } else if (errorType.indexOf("NETWORK ERROR") != -1) {
             errVal = NETWORK_ERROR;
         } else if (errorType.indexOf("GENERAL FAILURE") != -1) {
             errVal = GENERAL_FAILURE;
         } else if (errorType.indexOf("APPLICATION ERROR") != -1) {
             errVal = APP_ERROR;
         } else if (errorType.indexOf("WARNING") != -1) {
             errVal = WARNING;
         }
         return errVal;
     }

     public String getErrorTypeString() {
         String type = "";
         switch (NMC_ErrType) {
             case FILE_ERROR              : type = "FILE ERROR";              break;
             case MEMORY_ERROR            : type = "MEMORY ERROR";            break;
             case SYSTEM_ERROR            : type = "SYSTEM ERROR";            break;
             case INCORRECT_USAGE         : type = "INCORRECT USAGE";         break;
             case ELEM_MISSING            : type = "ELEMENT MISSING";         break;
             case REGISTRY_DATABASE_ERROR : type = "REGISTRY DATABASE ERROR"; break;
             case NETWORK_ERROR           : type = "NETWORK ERROR";           break;
             case GENERAL_FAILURE         : type = "GENERAL FAILURE";         break;
             case APP_ERROR               : type = "APPLICATION ERROR";       break;
             case WARNING                 : type = "WARNING";                 break;
             default                      : type = "UNKNOW ERROR";            break;
         }
         return type;
     }*/

    public String getErrorInfo() {
        return NMC_ErrInfo;
    }

    public String getErrorDetail() {
        return NMC_ErrDetail;
    }

    public String getDescription() {
        return NMC_Description;
    }

    public String getExtraMessage() {
        return NMC_Extra;
    }
}
