/* --- BEGIN COPYRIGHT BLOCK ---
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301  USA 
 * 
 * Copyright (C) 2007 Red Hat, Inc.
 * All rights reserved.
 * --- END COPYRIGHT BLOCK ---
 */

#ifndef APDU_H
#define APDU_H

#ifdef HAVE_CONFIG_H
#ifndef AUTOTOOLS_CONFIG_H
#define AUTOTOOLS_CONFIG_H

/* Eliminate warnings when using Autotools */
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#include <config.h>
#endif /* AUTOTOOLS_CONFIG_H */
#endif /* HAVE_CONFIG_H */

#include "pk11func.h"
#include "main/Base.h"
#include "main/Buffer.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

enum APDU_Type {
        APDU_UNDEFINED = 0,
        APDU_CREATE_OBJECT = 1,
        APDU_EXTERNAL_AUTHENTICATE = 2,
        APDU_INITIALIZE_UPDATE = 3,
        APDU_LIFECYCLE = 4,
        APDU_READ_BUFFER = 5,
        APDU_SET_PIN = 6,
        APDU_UNBLOCK_PIN = 7,
        APDU_WRITE_OBJECT = 8,
        APDU_GENERATE_KEY = 9,
        APDU_PUT_KEY = 10,
        APDU_SELECT = 11,
        APDU_GET_VERSION = 12,
        APDU_DELETE_FILE = 13,
        APDU_INSTALL_APPLET = 14,
        APDU_FORMAT_MUSCLE_APPLET = 15,
        APDU_LOAD_FILE = 16,
        APDU_INSTALL_LOAD = 17,
        APDU_GET_STATUS = 18 ,
        APDU_LIST_PINS = 19,
        APDU_CREATE_PIN = 20,
        APDU_GET_DATA = 21,
        APDU_READ_OBJECT = 22,
        APDU_LIST_OBJECTS = 23,
	    APDU_IMPORT_KEY = 24,
	    APDU_IMPORT_KEY_ENC = 25,
	    APDU_SET_ISSUERINFO = 26,
	    APDU_GET_ISSUERINFO = 27,
        APDU_GENERATE_KEY_ECC = 28
};

class APDU
{
  public:
	TPS_PUBLIC APDU();
	TPS_PUBLIC APDU(const APDU &cpy);
	TPS_PUBLIC virtual ~APDU();
  public:
	TPS_PUBLIC APDU& operator=(const APDU& cpy);
  public:
	TPS_PUBLIC virtual void SetCLA(BYTE cla);
	TPS_PUBLIC virtual void SetINS(BYTE ins);
	TPS_PUBLIC virtual void SetP1(BYTE p1);
	TPS_PUBLIC virtual void SetP2(BYTE p2);
	TPS_PUBLIC virtual void SetData(Buffer &data);
	TPS_PUBLIC virtual void SetMAC(Buffer &mac);
	TPS_PUBLIC virtual void GetEncoding(Buffer &data);
	TPS_PUBLIC virtual void GetDataToMAC(Buffer &data);
	TPS_PUBLIC virtual PRStatus SecureMessage(PK11SymKey *encSessionKey);
	TPS_PUBLIC virtual APDU_Type GetType();
	TPS_PUBLIC Buffer &GetData();
	TPS_PUBLIC Buffer &GetMAC();
	TPS_PUBLIC BYTE GetCLA();
	TPS_PUBLIC BYTE GetINS();
	TPS_PUBLIC BYTE GetP1();
	TPS_PUBLIC BYTE GetP2();
  protected:
	BYTE m_cla;
	BYTE m_ins;
	BYTE m_p1;
	BYTE m_p2;
	Buffer m_data;
	Buffer m_plainText;
	Buffer m_mac;
};

#endif /* APDU_H */
