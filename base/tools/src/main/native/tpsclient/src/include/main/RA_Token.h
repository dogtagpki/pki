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

#ifndef RA_TOKEN_H
#define RA_TOKEN_H

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

#include <stdio.h>
#include "main/Buffer.h"
#include "main/NameValueSet.h"
#include "apdu/APDU_Response.h"
#include "apdu/APDU.h"
#include "apdu/Initialize_Update_APDU.h"
#include "apdu/External_Authenticate_APDU.h"
#include "apdu/Set_Pin_APDU.h"
#include "apdu/Get_Status_APDU.h"
#include "apdu/Create_Object_APDU.h"
#include "apdu/Lifecycle_APDU.h"
#include "apdu/Read_Buffer_APDU.h"
#include "apdu/Get_IssuerInfo_APDU.h"
#include "apdu/Set_IssuerInfo_APDU.h"
#include "apdu/Load_File_APDU.h"
#include "apdu/Format_Muscle_Applet_APDU.h"
#include "apdu/Install_Applet_APDU.h"
#include "apdu/Install_Load_APDU.h"
#include "apdu/Unblock_Pin_APDU.h"
#include "apdu/Write_Object_APDU.h"
#include "apdu/Read_Object_APDU.h"
#include "apdu/List_Pins_APDU.h"
#include "apdu/List_Objects_APDU.h"
#include "apdu/Create_Pin_APDU.h"
#include "apdu/Generate_Key_APDU.h"
#include "apdu/Generate_Key_ECC_APDU.h"
#include "apdu/Select_APDU.h"
#include "apdu/Delete_File_APDU.h"
#include "apdu/Get_Version_APDU.h"
#include "apdu/Get_Data_APDU.h"
#include "apdu/Put_Key_APDU.h"
#include "apdu/Import_Key_APDU.h"
#include "apdu/Import_Key_Enc_APDU.h"

typedef enum {
        auth,
        mac,
        kek
        } keyType;


class RA_Token
{
  public:
	  RA_Token();
	  ~RA_Token();
  public:
	  char *GetPIN();
	  Buffer &GetAuthKey();
	  Buffer &GetMacKey();
	  Buffer &GetKekKey();
	  Buffer &GetAppletVersion();
	  void SetAppletVersion(Buffer &version);
	  Buffer &GetCUID();
	  void SetCUID(Buffer &cuid);
	  Buffer &GetMSN();
	  void SetMSN(Buffer &msn);
	  Buffer &GetKeyInfo();
	  int GetMajorVersion();
	  int GetMinorVersion();
	  void SetKeyInfo(Buffer &key_info);
	  void SetAuthKey(Buffer &key);
	  void SetMacKey(Buffer &key);
	  void SetKekKey(Buffer &key);
	  void SetMajorVersion(int v);
	  void SetMinorVersion(int v);
	  BYTE GetLifeCycleState();
  public:
typedef struct {
    enum {
    PW_NONE = 0,
    PW_FROMFILE = 1,
    PW_PLAINTEXT = 2,
    PW_EXTERNAL = 3
    } source;
    char *data;
} secuPWData;

     static char *getModulePasswordText(PK11SlotInfo *slot, PRBool retry, void *arg);
          int VerifyMAC(APDU *apdu);
          void ComputeAPDUMac(APDU *apdu, Buffer &new_mac);
          PK11SymKey *CreateSessionKey(keyType keytype,
				Buffer &card_challenge,  
		                Buffer &host_challenge);
	  RA_Token *Clone();
	  void decryptMsg(Buffer &in_data, Buffer &out_data);
	  PK11SymKey *GetEncSessionKey();
  public:
	int NoOfCertificates();
	CERTCertificate *GetCertificate(int pos);
	int NoOfPrivateKeys();
	SECKEYPrivateKey *GetPrivateKey(int pos);
  public:
	  APDU_Response *Process(APDU *apdu, NameValueSet *vars, NameValueSet *params);
	  APDU_Response *ProcessInitializeUpdate(
			  Initialize_Update_APDU *apdu, 
			  NameValueSet *vars,
			  NameValueSet *params);
	  APDU_Response *ProcessExternalAuthenticate(
			  External_Authenticate_APDU *apdu, 
			  NameValueSet *vars,
			  NameValueSet *params);
	  APDU_Response *ProcessReadObject(Read_Object_APDU *apdu, 
			  NameValueSet *vars,
			  NameValueSet *params);
	  APDU_Response *ProcessListObjects(List_Objects_APDU *apdu, 
			  NameValueSet *vars,
			  NameValueSet *params);
	  APDU_Response *ProcessDeleteFile(Delete_File_APDU *apdu, 
			  NameValueSet *vars,
			  NameValueSet *params);
	  APDU_Response *ProcessSetPin(Set_Pin_APDU *apdu, 
			  NameValueSet *vars,
			  NameValueSet *params);
	  APDU_Response *ProcessInstallApplet(Install_Applet_APDU *apdu, 
			  NameValueSet *vars,
			  NameValueSet *params);
	  APDU_Response *ProcessInstallLoad(Install_Load_APDU *apdu, 
			  NameValueSet *vars,
			  NameValueSet *params);
	  APDU_Response *ProcessLoadFile(Load_File_APDU *apdu, 
			  NameValueSet *vars,
			  NameValueSet *params);
	  APDU_Response *ProcessFormatMuscleApplet(Format_Muscle_Applet_APDU *apdu, 
			  NameValueSet *vars,
			  NameValueSet *params);
	  APDU_Response *ProcessGetVersion(Get_Version_APDU *apdu, 
			  NameValueSet *vars,
			  NameValueSet *params);
	  APDU_Response *ProcessListPins(List_Pins_APDU *apdu, 
			  NameValueSet *vars,
			  NameValueSet *params);
	  APDU_Response *ProcessCreatePin(Create_Pin_APDU *apdu, 
			  NameValueSet *vars,
			  NameValueSet *params);
	  APDU_Response *ProcessGetData(Get_Data_APDU *apdu, 
			  NameValueSet *vars,
			  NameValueSet *params);
	  APDU_Response *ProcessGetStatus(Get_Status_APDU *apdu, 
			  NameValueSet *vars,
			  NameValueSet *params);
	  APDU_Response *ProcessCreateObject(Create_Object_APDU *apdu,
			  NameValueSet *vars,
			  NameValueSet *params);
	  APDU_Response *ProcessLifecycle(Lifecycle_APDU *apdu,
			  NameValueSet *vars,
			  NameValueSet *params);
	  APDU_Response *ProcessReadBuffer(Read_Buffer_APDU *apdu,
			  NameValueSet *vars,
			  NameValueSet *params);
	  APDU_Response *ProcessUnblockPin(Unblock_Pin_APDU *apdu,
			  NameValueSet *vars,
			  NameValueSet *params);
	  APDU_Response *ProcessGetIssuerInfo(Get_IssuerInfo_APDU *apdu,
			  NameValueSet *vars,
			  NameValueSet *params);
	  APDU_Response *ProcessSetIssuerInfo(Set_IssuerInfo_APDU *apdu,
			  NameValueSet *vars,
			  NameValueSet *params);
	  APDU_Response *ProcessWriteBuffer(Write_Object_APDU *apdu,
			  NameValueSet *vars,
			  NameValueSet *params);
	  APDU_Response *ProcessGenerateKey(Generate_Key_APDU *apdu,
			  NameValueSet *vars,
			  NameValueSet *params);
	  APDU_Response *ProcessGenerateKeyECC(Generate_Key_ECC_APDU *apdu,
			  NameValueSet *vars,
			  NameValueSet *params);
	  APDU_Response *ProcessImportKeyEnc(Import_Key_Enc_APDU *apdu,
			  NameValueSet *vars,
			  NameValueSet *params);
	  APDU_Response *ProcessSelect(Select_APDU *apdu,
			  NameValueSet *vars,
			  NameValueSet *params);
	  APDU_Response *ProcessPutKey(Put_Key_APDU *apdu,
			  NameValueSet *vars,
			  NameValueSet *params);

#define DEFAULT_CURVE_OID_TAG  SEC_OID_SECG_EC_SECP192R1
/* #define DEFAULT_CURVE_OID_TAG  SEC_OID_SECG_EC_SECP160R1 */

      static SECKEYECParams *getECParams(const char *curve);
  public:
      Buffer m_card_challenge;
      Buffer m_host_challenge;
      PK11SymKey *m_session_key;
      PK11SymKey *m_enc_session_key;
      Buffer m_icv;
      Buffer m_cuid;
      Buffer m_msn;
      Buffer m_version;
      Buffer m_key_info;
      Buffer m_auth_key;
      Buffer m_mac_key;
      Buffer m_kek_key;
      Buffer m_buffer;
      BYTE m_lifecycle_state;
      char *m_pin;
      Buffer* m_object;
      int m_major_version;
      int m_minor_version;
      int m_object_len;
      int m_chunk_len;
      char m_objectid[3];
      char *m_tokenpassword;
};

#endif /* RA_TOKEN_H */
