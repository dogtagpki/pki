// --- BEGIN COPYRIGHT BLOCK ---
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation;
// version 2.1 of the License.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor,
// Boston, MA  02110-1301  USA 
// 
// Copyright (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

#include "main/Base.h"
#include "main/Buffer.h"
#include "main/Util.h"
#include "engine/RA.h"
#include "channel/Secure_Channel.h"
#include "msg/RA_Token_PDU_Request_Msg.h"
#include "msg/RA_Token_PDU_Response_Msg.h"
#include "apdu/Lifecycle_APDU.h"
#include "apdu/Initialize_Update_APDU.h"
#include "apdu/External_Authenticate_APDU.h"
#include "apdu/Create_Object_APDU.h"
#include "apdu/Set_Pin_APDU.h"
#include "apdu/Set_IssuerInfo_APDU.h"
#include "apdu/Get_IssuerInfo_APDU.h"
#include "apdu/Import_Key_APDU.h"
#include "apdu/Import_Key_Enc_APDU.h"
#include "apdu/Read_Buffer_APDU.h"
#include "apdu/Read_Object_APDU.h"
#include "apdu/Write_Object_APDU.h"
#include "apdu/Generate_Key_APDU.h"
#include "apdu/Generate_Key_ECC_APDU.h"
#include "apdu/Put_Key_APDU.h"
#include "apdu/Delete_File_APDU.h"
#include "apdu/Load_File_APDU.h"
#include "apdu/Install_Applet_APDU.h"
#include "apdu/Install_Load_APDU.h"
#include "apdu/Format_Muscle_Applet_APDU.h"
#include "apdu/Create_Pin_APDU.h"
#include "apdu/List_Pins_APDU.h"
#include "apdu/APDU_Response.h"
#include "main/Memory.h"

/**
 * Constructs a secure channel between the RA and the 
 * token key directly. APDUs that are sent via this channel 
 * will be  mac'ed using the session key calculated by
 * TKS which maintains all the user keys.
 */

Secure_Channel::Secure_Channel(RA_Session *session, PK11SymKey *session_key,
			       PK11SymKey *enc_session_key,
			       char *drm_des_key_s,
			       char *kek_des_key_s, char *keycheck_s,
    Buffer &key_diversification_data, Buffer &key_info_data,
    Buffer &card_challenge, Buffer &card_cryptogram,
    Buffer &host_challenge, Buffer &host_cryptogram)
{
    m_icv = Buffer(8,(BYTE)0);
    m_session = session;
    m_session_key = session_key;
    m_enc_session_key = enc_session_key;
    m_drm_wrapped_des_key_s = drm_des_key_s;
    m_kek_wrapped_des_key_s = kek_des_key_s;
    m_keycheck_s = keycheck_s;
    m_key_diversification_data = key_diversification_data;
    m_key_info_data = key_info_data;
    m_card_challenge = card_challenge;
    m_card_cryptogram = card_cryptogram;
    m_host_challenge = host_challenge;
    m_host_cryptogram = host_cryptogram;
} /* Secure_Channel */

/**
 * Destroys this secure channel.
 */
Secure_Channel::~Secure_Channel ()
{
    /* m_session (RA_Session) should not be destroyed at this level. */
    if( m_session_key != NULL ) {
        PK11_FreeSymKey( m_session_key );
        m_session_key = NULL;
    }
    if( m_enc_session_key != NULL ) {
        PK11_FreeSymKey( m_enc_session_key );
        m_enc_session_key = NULL;
    }
    if (m_drm_wrapped_des_key_s != NULL) {
      PR_Free(m_drm_wrapped_des_key_s);
      m_drm_wrapped_des_key_s = NULL;
    }
    if (m_kek_wrapped_des_key_s != NULL) {
      PR_Free(m_kek_wrapped_des_key_s);
      m_kek_wrapped_des_key_s = NULL;
    }
    if (m_keycheck_s != NULL) {
      PR_Free(m_keycheck_s);
      m_keycheck_s = NULL;
    }
} /* ~Secure_Channel */

/**
 * Closes secure channel.
 */
int Secure_Channel::Close()
{
    /* currently do not have anything to terminate here */
    return 1;
}

/*
 * to be called by all token request types
 * it resets m_data if security level is to do encryption
 */
int Secure_Channel::ComputeAPDU(APDU *apdu)
{
    int rc = -1;
    Buffer *mac = NULL;

    if (apdu == NULL) {
      goto loser;
    }
    RA::Debug(LL_PER_PDU, "Secure_Channel::ComputeAPDU", "apdu type = %d",
	      apdu->GetType());

    mac = ComputeAPDUMac(apdu);
    if (mac == NULL)
      goto loser;

    if (m_security_level == SECURE_MSG_MAC_ENC) {
      PRStatus status = apdu->SecureMessage(m_enc_session_key);
      if (status == PR_FAILURE) {
	goto loser;
      }
    }

    RA::Debug(LL_PER_PDU,"Secure_Channel::ComputeAPDU","Completed apdu.");
    rc = 1;
 loser: 
    if( mac != NULL ) {
        delete mac;
        mac = NULL;
    }

    return rc;
}

/**
 * Calculates MAC for the given APDU.
 */
Buffer *Secure_Channel::ComputeAPDUMac(APDU *apdu)
{
    Buffer data;
    Buffer *mac = new Buffer(8, (BYTE)0);

    if (apdu == NULL) {
      RA::Error("Secure_Channel::ComputeAPDUMac", "apdu NULL");
      if( mac != NULL ) {
          delete mac;
          mac = NULL;
      }
      return NULL;
    }
    apdu->GetDataToMAC(data);

    // developer debugging only - not for deployment
    //        RA::DebugBuffer("Secure_Channel::ComputeAPDUMac", "Data To MAC'ed",
    //    		&data);

    // Compute MAC will padd the data if it is 
    // not in 8 byte multiples
    Util::ComputeMAC(m_session_key, data, m_icv, *mac);
    apdu->SetMAC(*mac);
    m_icv = *mac;

    RA::DebugBuffer("Secure_Channel::ComputeAPDUMac ", "mac",
                       mac);
    return mac;
} /* EncodeAPDUMac */

/**
 * Sends the token an external authenticate APDU.
 */
int Secure_Channel::ExternalAuthenticate()
{
    int rc = -1;
    RA_Token_PDU_Request_Msg *token_pdu_request_msg = NULL;
    RA_Token_PDU_Response_Msg *token_pdu_response_msg = NULL;
    External_Authenticate_APDU *external_auth_apdu = NULL;
    APDU_Response *response = NULL;
    Buffer *mac = NULL;

    RA::Debug("Secure_Channel::ExternalAuthenticate",
        "Secure_Channel::ExternalAuthenticate");

    // This command is very strange
    external_auth_apdu =
        new External_Authenticate_APDU(m_host_cryptogram, m_security_level);

    // Need to update APDU length to include 8-bytes MAC
    // before mac'ing the data
    mac = ComputeAPDUMac(external_auth_apdu);
    external_auth_apdu->SetMAC(*mac);

    token_pdu_request_msg =
        new RA_Token_PDU_Request_Msg(external_auth_apdu);
    m_session->WriteMsg(token_pdu_request_msg);
    RA::Debug("Secure_Channel::ExternalAuthenticate",
        "Sent external_auth_request_msg");

    token_pdu_response_msg = (RA_Token_PDU_Response_Msg *)
        m_session->ReadMsg();
    if (token_pdu_response_msg == NULL)
    {
        RA::Error("Secure_Channel::ExternalAuthenticate",
            "No Token PDU Response Msg Received");
        goto loser;
    }
    if (token_pdu_response_msg->GetType() != MSG_TOKEN_PDU_RESPONSE) {
        RA::Error("Secure_Channel::ExternalAuthenticate",
            "Invalid Msg Type");
        goto loser;
    }
    response = token_pdu_response_msg->GetResponse();
    if (response == NULL) {
        RA::Error("Secure_Channel::ExternalAuthenticate",
            "No Response From Token");
        goto loser;
    }
    if (response->GetData().size() < 2) {
        RA::Error("Secure_Channel::ExternalAuthenticate",
            "Invalid Response From Token");
        goto loser;
    }

    // must return 0x90 0x00
    if (!(response->GetSW1() == 0x90 && response->GetSW2() == 0x00)) {
           RA::Error("RA_Processor::ExternalAuthenticate",
                "Bad Response %x %x", response->GetSW1(), response->GetSW2());
           goto loser;
     }

    rc = 1;
loser:
    if( mac != NULL ) {
        delete mac;
        mac = NULL;
    }
    if( token_pdu_request_msg != NULL ) {
        delete token_pdu_request_msg;
        token_pdu_request_msg = NULL;
    }
    if( token_pdu_response_msg != NULL ) {
        delete token_pdu_response_msg;
        token_pdu_response_msg = NULL;
    }

    return rc;
} /* ExternalAuthenticate */

int Secure_Channel::DeleteFileX(RA_Session *session, Buffer *aid)
{
    int rc = 0;
    APDU_Response *delete_response = NULL;
    RA_Token_PDU_Request_Msg *delete_request_msg = NULL;
    RA_Token_PDU_Response_Msg *delete_response_msg = NULL;
    Delete_File_APDU *delete_apdu = NULL;
    // Buffer *mac = NULL;

    RA::Debug("RA_Processor::DeleteFile",
        "RA_Processor::DeleteFile");

    delete_apdu = new Delete_File_APDU(*aid);
    rc = ComputeAPDU(delete_apdu);
    if (rc == -1)
      goto loser;

    /*
    mac = ComputeAPDUMac(delete_apdu);
    delete_apdu->SetMAC(*mac);
    */
    delete_request_msg =
        new RA_Token_PDU_Request_Msg(delete_apdu);
    session->WriteMsg(delete_request_msg);

    RA::Debug("RA_Processor::DeleteFile",
        "Sent delete_request_msg");

    delete_response_msg = (RA_Token_PDU_Response_Msg *)
        session->ReadMsg();
    if (delete_response_msg == NULL)
    {
       RA::Error("RA_Processor::DeleteFile",
            "No Token PDU Response Msg Received");
	rc = -1;
        goto loser;
    }
    if (delete_response_msg->GetType() != MSG_TOKEN_PDU_RESPONSE) {
        RA::Error("Secure_Channel::DeleteFile",
            "Invalid Msg Type");
	rc = -1;
        goto loser;
    }
    delete_response = delete_response_msg->GetResponse();
    if (delete_response == NULL) {
        RA::Error("Secure_Channel::DeleteFile",
            "No Response From Token");
	rc = -1;
        goto loser;
    }
    if (delete_response->GetData().size() < 2) {
        RA::Error("Secure_Channel::DeleteFile",
            "Invalid Response From Token");
	rc = -1;
        goto loser;
    }

    if (!(delete_response->GetSW1() == 0x90 && 
	 	delete_response->GetSW2() == 0x00)) {
           RA::Error("RA_Processor::DeleteFile",
                "Bad Response %x %x", delete_response->GetSW1(),
		delete_response->GetSW2());
	   rc = -1;
           goto loser;
     }

    rc = 1;

loser:
    if( delete_request_msg != NULL ) {
        delete delete_request_msg;
        delete_request_msg = NULL;
    }
    if( delete_response_msg != NULL ) {
        delete delete_response_msg;
        delete_response_msg = NULL;
    }

    return rc;
}

int Secure_Channel::InstallLoad(RA_Session *session, 
		Buffer& packageAID, Buffer& sdAID, unsigned int fileLen)
{
    int rc = 0;
    APDU_Response *install_response = NULL;
    RA_Token_PDU_Request_Msg *install_request_msg = NULL;
    RA_Token_PDU_Response_Msg *install_response_msg = NULL;
    Install_Load_APDU *install_apdu = NULL;
    // Buffer *mac = NULL;

    RA::Debug("RA_Processor::InstallLoad",
        "RA_Processor::InstallLoad");

    install_apdu = new Install_Load_APDU(packageAID, sdAID, fileLen);
    rc = ComputeAPDU(install_apdu);
    if (rc == -1)
      goto loser;

    /*
    mac = ComputeAPDUMac(install_apdu);
    install_apdu->SetMAC(*mac);
    */
    install_request_msg =
        new RA_Token_PDU_Request_Msg(install_apdu);
    session->WriteMsg(install_request_msg);

    RA::Debug("RA_Processor::InstallLoad",
        "Sent install_request_msg");

    install_response_msg = (RA_Token_PDU_Response_Msg *)
        session->ReadMsg();
    if (install_response_msg == NULL)
    {
       RA::Error("RA_Processor::InstallLoad",
            "No Token PDU Response Msg Received");
	rc = -1;
        goto loser;
    }
    if (install_response_msg->GetType() != MSG_TOKEN_PDU_RESPONSE) {
        RA::Error("Secure_Channel::InstallLoad",
            "Invalid Msg Type");
	rc = -1;
        goto loser;
    }
    install_response = install_response_msg->GetResponse();
    if (install_response == NULL) {
        RA::Error("Secure_Channel::InstallLoad",
            "No Response From Token");
	rc = -1;
        goto loser;
    }
    if (install_response->GetData().size() < 2) {
        RA::Error("Secure_Channel::InstallLoad",
            "Invalid Response From Token");
	rc = -1;
        goto loser;
    }

    if (!(install_response->GetSW1() == 0x90 && 
	 	install_response->GetSW2() == 0x00)) {
           RA::Error("Secure_Channel::InstallLoad",
                "Error Response from token %2x%2x",
				install_response->GetSW1(),
				install_response->GetSW2());
	rc = -1;
           goto loser;
     }

    rc = 1;

loser:
    if( install_request_msg != NULL ) {
        delete install_request_msg;
        install_request_msg = NULL;
    }
    if( install_response_msg != NULL ) {
        delete install_response_msg;
        install_response_msg = NULL;
    }

    return rc;
}

int Secure_Channel::InstallApplet(RA_Session *session, 
		Buffer &packageAID, Buffer &appletAID, 
		BYTE appPrivileges, unsigned int instanceSize, unsigned int appletMemorySize)
{
    int rc = 0;
    APDU_Response *install_response = NULL;
    RA_Token_PDU_Request_Msg *install_request_msg = NULL;
    RA_Token_PDU_Response_Msg *install_response_msg = NULL;
    Install_Applet_APDU *install_apdu = NULL;
    // Buffer *mac = NULL;

    RA::Debug("RA_Processor::InstallApplet",
        "RA_Processor::InstallApplet");

    install_apdu = new Install_Applet_APDU(packageAID, appletAID, appPrivileges, 
		    	instanceSize, appletMemorySize );
    rc =  ComputeAPDU(install_apdu);
    if (rc == -1)
      goto loser;

    /*
    mac = ComputeAPDUMac(install_apdu);
    install_apdu->SetMAC(*mac);
    */
    install_request_msg =
        new RA_Token_PDU_Request_Msg(install_apdu);
    session->WriteMsg(install_request_msg);

    RA::Debug("RA_Processor::InstallApplet",
        "Sent install_request_msg");

    install_response_msg = (RA_Token_PDU_Response_Msg *)
        session->ReadMsg();
    if (install_response_msg == NULL)
    {
        RA::Error("RA_Processor::InstallApplet",
            "No Token PDU Response Msg Received");
	rc = -1;
        goto loser;
    }
    if (install_response_msg->GetType() != MSG_TOKEN_PDU_RESPONSE) {
        RA::Error("Secure_Channel::InstallApplet",
            "Invalid Msg Type");
	rc = -1;
        goto loser;
    }
    install_response = install_response_msg->GetResponse();
    if (install_response == NULL) {
        RA::Error("Secure_Channel::InstallApplet",
            "No Response From Token");
	rc = -1;
        goto loser;
    }
    if (install_response->GetData().size() < 2) {
        RA::Debug("Secure_Channel::InstallApplet",
            "Invalid Response From Token");
	rc = -1;
        goto loser;
    }

    if (!(install_response->GetSW1() == 0x90 && 
	 	install_response->GetSW2() == 0x00)) {
           RA::Error("Secure_Channel::InstallApplet",
                "Error Response from Token %2x%2x",
				install_response->GetSW1(),
				install_response->GetSW2());
	rc = -1;
           goto loser;
     }

    rc = 1;

loser:
    if( install_request_msg != NULL ) {
        delete install_request_msg;
        install_request_msg = NULL;
    }
    if( install_response_msg != NULL ) {
        delete install_response_msg;
        install_response_msg = NULL;
    }

    return rc;
}

int Secure_Channel::LoadFile(RA_Session *session, BYTE refControl, BYTE blockNum, 
	Buffer *data)
{
    int rc = 0;
    APDU_Response *load_file_response = NULL;
    RA_Token_PDU_Request_Msg *load_file_request_msg = NULL;
    RA_Token_PDU_Response_Msg *load_file_response_msg = NULL;
    Load_File_APDU *load_file_apdu = NULL;
    //    Buffer *mac = NULL;

    RA::Debug("Secure_Channel::LoadFile",
        "begin LoadFile");

    load_file_apdu = new Load_File_APDU(refControl, blockNum, *data);

    rc = ComputeAPDU(load_file_apdu);
    if (rc == -1)
      goto loser;

    /*
    mac = ComputeAPDUMac(load_file_apdu);
    load_file_apdu->SetMAC(*mac);
    */
    load_file_request_msg =
        new RA_Token_PDU_Request_Msg(load_file_apdu);

    session->WriteMsg(load_file_request_msg);

    RA::Debug("RA_Processor::LoadFile",
        "Sent load_file_request_msg");

    load_file_response_msg = (RA_Token_PDU_Response_Msg *)
        session->ReadMsg();
    if (load_file_response_msg == NULL)
    {
        RA::Error("RA_Processor::LoadFile",
            "No Token PDU Response Msg Received");
	rc = -1;
        goto loser;
    }
    if (load_file_response_msg->GetType() != MSG_TOKEN_PDU_RESPONSE) {
        RA::Error("Secure_Channel::LoadFile",
            "Invalid Msg Type");
	rc = -1;
        goto loser;
    }
    load_file_response = load_file_response_msg->GetResponse();
    if (load_file_response == NULL) {
        RA::Error("Secure_Channel::LoadFile",
            "No Response From Token");
	rc = -1;
        goto loser;
    }
    if (load_file_response->GetData().size() < 2) {
        RA::Error("Secure_Channel::LoadFile",
            "Invalid Response From Token");
	rc = -1;
        goto loser;
    }
    if (!(load_file_response->GetSW1() == 0x90 && 
	 	load_file_response->GetSW2() == 0x00)) {
           RA::Error("Secure_Channel::LoadFile",
                "Error Response from Token %2x%2x",
				load_file_response->GetSW1(),
				load_file_response->GetSW2());
	rc = -1;
           goto loser;
     }

    rc = 1;

loser:
    if( load_file_request_msg != NULL ) {
        delete load_file_request_msg;
        load_file_request_msg = NULL;
    }
    if( load_file_response_msg != NULL ) {
        delete load_file_response_msg;
        load_file_response_msg = NULL;
    }

    return rc;
}

int Secure_Channel::IsPinPresent(BYTE pin_number)
{
    int rc = -1;
    List_Pins_APDU *list_pins_apdu = NULL;
    APDU_Response *response = NULL;
    RA_Token_PDU_Request_Msg *token_pdu_request_msg = NULL;
    RA_Token_PDU_Response_Msg *token_pdu_response_msg = NULL;
    Buffer *mac = NULL;

    RA::Debug("Secure_Channel::IsPinPresent",
        "Secure_Channel::IsPinPresent");
    list_pins_apdu = new List_Pins_APDU(2);
    list_pins_apdu = (List_Pins_APDU *) ComputeAPDU(list_pins_apdu);

    /*
    mac = ComputeAPDUMac(set_pin_apdu);
    set_pin_apdu->SetMAC(*mac);
    */
    token_pdu_request_msg = new RA_Token_PDU_Request_Msg(
        list_pins_apdu);
    m_session->WriteMsg(token_pdu_request_msg);
    RA::Debug("Secure_Channel::IsPinPresent",
        "Sent token_pdu_request_msg");

    token_pdu_response_msg = (RA_Token_PDU_Response_Msg *)
        m_session->ReadMsg();
    if (token_pdu_response_msg == NULL)
    {
        RA::Error("Secure_Channel::IsPinReset",
            "No Token PDU Response Msg Received");
        goto loser;
    }
    if (token_pdu_response_msg->GetType() != MSG_TOKEN_PDU_RESPONSE) {
        RA::Error("Secure_Channel::IsPinReset",
            "Invalid Msg Type");
        goto loser;
    }
    response = token_pdu_response_msg->GetResponse();
    if (response == NULL) {
        RA::Error("Secure_Channel::IsPinReset",
            "No Response From Token");
        goto loser;
    }

    rc = 1;
loser:
    if( mac != NULL ) {
        delete mac;
        mac = NULL;
    }
    if( token_pdu_request_msg != NULL ) {
        delete token_pdu_request_msg;
        token_pdu_request_msg = NULL;
    }
    if( token_pdu_response_msg != NULL ) {
        delete token_pdu_response_msg;
        token_pdu_response_msg = NULL;
    }

    return rc;
}

/**
 * Get Issuer Info
 */
Buffer Secure_Channel::GetIssuerInfo()
{
    Buffer data;
    int rc = -1;
    Get_IssuerInfo_APDU *get_issuerinfo_apdu = NULL;
    APDU_Response *response = NULL;
    RA_Token_PDU_Request_Msg *token_pdu_request_msg = NULL;
    RA_Token_PDU_Response_Msg *token_pdu_response_msg = NULL;

    RA::Debug("Secure_Channel::GetIssuerInfo",
        "Secure_Channel::GetIssuerInfo");
    get_issuerinfo_apdu = new Get_IssuerInfo_APDU();
    rc = ComputeAPDU(get_issuerinfo_apdu);
    if (rc == -1) {
      goto loser;
    }

    token_pdu_request_msg = new RA_Token_PDU_Request_Msg(
        get_issuerinfo_apdu);
    m_session->WriteMsg(token_pdu_request_msg);
    RA::Debug("Secure_Channel::GetIssuerInfo",
        "Sent token_pdu_request_msg");

    token_pdu_response_msg = (RA_Token_PDU_Response_Msg *)
        m_session->ReadMsg();
    if (token_pdu_response_msg == NULL)
    {
        RA::Error("Secure_Channel::GetIssuerInfo",
            "No Token PDU Response Msg Received");
	    rc = -1;
        goto loser;
    }
    if (token_pdu_response_msg->GetType() != MSG_TOKEN_PDU_RESPONSE) {
        RA::Error("Secure_Channel::GetIssuerInfo",
            "Invalid Msg Type");
	    rc = -1;
        goto loser;
    }

    response = token_pdu_response_msg->GetResponse();
    if (response == NULL) {
        RA::Error("Secure_Channel::GetIssuerInfo",
            "No Response From Token");
	rc = -1;
        goto loser;
    }
    if (response->GetData().size() < 2) {
        RA::Error("Secure_Channel::GetIssuerInfo",
            "Invalid Response From Token");
	    rc = -1;
        goto loser;
    }
    if (!(response->GetSW1() == 0x90 && 
	 	response->GetSW2() == 0x00)) {
           RA::Error("RA_Processor::GetIssuerInfo",
                "Bad Response");
	       rc = -1;
           goto loser;
     }

    data = response->GetData();
    rc = 1;
loser:
    if( token_pdu_request_msg != NULL ) {
        delete token_pdu_request_msg;
        token_pdu_request_msg = NULL;
    }
    if( token_pdu_response_msg != NULL ) {
        delete token_pdu_response_msg;
        token_pdu_response_msg = NULL;
    }

    return data;
} /* SetIssuerInfo */
/**
 * Set Issuer Info
 */
int Secure_Channel::SetIssuerInfo(Buffer *info)
{
    int rc = -1;
    Set_IssuerInfo_APDU *set_issuerinfo_apdu = NULL;
    APDU_Response *response = NULL;
    RA_Token_PDU_Request_Msg *token_pdu_request_msg = NULL;
    RA_Token_PDU_Response_Msg *token_pdu_response_msg = NULL;

    RA::Debug("Secure_Channel::SetIssuerInfo",
        "Secure_Channel::SetIssuerInfo");
    set_issuerinfo_apdu = new Set_IssuerInfo_APDU(0x0, 0x0, *info);
    rc = ComputeAPDU(set_issuerinfo_apdu);
    if (rc == -1) {
      goto loser;
    }

    token_pdu_request_msg = new RA_Token_PDU_Request_Msg(
        set_issuerinfo_apdu);
    m_session->WriteMsg(token_pdu_request_msg);
    RA::Debug("Secure_Channel::SetIssuerInfo",
        "Sent token_pdu_request_msg");

    token_pdu_response_msg = (RA_Token_PDU_Response_Msg *)
        m_session->ReadMsg();
    if (token_pdu_response_msg == NULL)
    {
        RA::Error("Secure_Channel::SetIssuerInfo",
            "No Token PDU Response Msg Received");
	    rc = -1;
        goto loser;
    }
    if (token_pdu_response_msg->GetType() != MSG_TOKEN_PDU_RESPONSE) {
        RA::Error("Secure_Channel::SetIssuerInfo",
            "Invalid Msg Type");
	    rc = -1;
        goto loser;
    }

    response = token_pdu_response_msg->GetResponse();
    if (response == NULL) {
        RA::Error("Secure_Channel::SetIssuerInfo",
            "No Response From Token");
	rc = -1;
        goto loser;
    }
    if (response->GetData().size() < 2) {
        RA::Error("Secure_Channel::SetIssuerInfo",
            "Invalid Response From Token");
	    rc = -1;
        goto loser;
    }
    if (!(response->GetSW1() == 0x90 && 
	 	response->GetSW2() == 0x00)) {
           RA::Error("RA_Processor::SetIssuerInfo",
                "Bad Response");
	       rc = -1;
           goto loser;
     }

    rc = 1;
loser:
    if( token_pdu_request_msg != NULL ) {
        delete token_pdu_request_msg;
        token_pdu_request_msg = NULL;
    }
    if( token_pdu_response_msg != NULL ) {
        delete token_pdu_response_msg;
        token_pdu_response_msg = NULL;
    }

    return rc;
} /* SetIssuerInfo */

/**
 * Resets token's pin.
 */
int Secure_Channel::ResetPin(BYTE pin_number, char *new_pin)
{
    int rc = -1;
    Set_Pin_APDU *set_pin_apdu = NULL;
    APDU_Response *response = NULL;
    RA_Token_PDU_Request_Msg *token_pdu_request_msg = NULL;
    RA_Token_PDU_Response_Msg *token_pdu_response_msg = NULL;

    RA::Debug("Secure_Channel::ResetPin",
        "Secure_Channel::ResetPin");
    Buffer data = Buffer((BYTE *)new_pin, strlen(new_pin));
    set_pin_apdu = new Set_Pin_APDU(0x0, 0x0, data);
    rc = ComputeAPDU(set_pin_apdu);
    if (rc == -1) {
      goto loser;
    }

    token_pdu_request_msg = new RA_Token_PDU_Request_Msg(
        set_pin_apdu);
    m_session->WriteMsg(token_pdu_request_msg);
    RA::Debug("Secure_Channel::ResetPin",
        "Sent token_pdu_request_msg");

    token_pdu_response_msg = (RA_Token_PDU_Response_Msg *)
        m_session->ReadMsg();
    if (token_pdu_response_msg == NULL)
    {
        RA::Error("Secure_Channel::ResetPin",
            "No Token PDU Response Msg Received");
	rc = -1;
        goto loser;
    }
    if (token_pdu_response_msg->GetType() != MSG_TOKEN_PDU_RESPONSE) {
        RA::Error("Secure_Channel::ResetPin",
            "Invalid Msg Type");
	rc = -1;
        goto loser;
    }

    response = token_pdu_response_msg->GetResponse();
    if (response == NULL) {
        RA::Error("Secure_Channel::ResetPin",
            "No Response From Token");
	rc = -1;
        goto loser;
    }
    if (response->GetData().size() < 2) {
        RA::Error("Secure_Channel::ResetPin",
            "Invalid Response From Token");
	rc = -1;
        goto loser;
    }
    if (!(response->GetSW1() == 0x90 && 
	 	response->GetSW2() == 0x00)) {
           RA::Error("RA_Processor::ResetPin",
                "Bad Response");
	rc = -1;
           goto loser;
     }

    rc = 1;
loser:
    if( token_pdu_request_msg != NULL ) {
        delete token_pdu_request_msg;
        token_pdu_request_msg = NULL;
    }
    if( token_pdu_response_msg != NULL ) {
        delete token_pdu_response_msg;
        token_pdu_response_msg = NULL;
    }

    return rc;
} /* ResetPin */

/**
 * inject key (public key, mostly)
 * @param key_number key slot number (from config file)
 */
int Secure_Channel::ImportKey(BYTE key_number)
{
    int rc = -1;
    Import_Key_APDU *import_key_apdu = NULL;
    APDU_Response *response = NULL;
    RA_Token_PDU_Request_Msg *token_pdu_request_msg = NULL;
    RA_Token_PDU_Response_Msg *token_pdu_response_msg = NULL;
    Buffer *mac = NULL;

    RA::Debug("Secure_Channel::ImportKey",
        "Secure_Channel::ImportKey");

    import_key_apdu = new Import_Key_APDU(key_number);
    rc = ComputeAPDU(import_key_apdu);
    if (rc == -1) {
      goto loser;
    }

    /*
    mac = ComputeAPDUMac(import_key_apdu);
    import_key_apdu->SetMAC(*mac);
    */
    token_pdu_request_msg = new RA_Token_PDU_Request_Msg(
        import_key_apdu);
    m_session->WriteMsg(token_pdu_request_msg);
    RA::Debug("Secure_Channel::ImportKey",
        "Sent token_pdu_request_msg");

    token_pdu_response_msg = (RA_Token_PDU_Response_Msg *)
        m_session->ReadMsg();
    if (token_pdu_response_msg == NULL)
    {
        RA::Error("Secure_Channel::ImportKey",
            "No Token PDU Response Msg Received");
	rc = -1;
        goto loser;
    }
    if (token_pdu_response_msg->GetType() != MSG_TOKEN_PDU_RESPONSE) {
        RA::Error("Secure_Channel::ImportKey",
            "Invalid Msg Type");
	rc = -1;
        goto loser;
    }

    response = token_pdu_response_msg->GetResponse();
    if (response == NULL) {
        RA::Error("Secure_Channel::ImportKey",
            "No Response From Token");
	rc = -1;
        goto loser;
    }
    if (response->GetData().size() < 2) {
        RA::Error("Secure_Channel::ImportKey",
            "Invalid Response From Token");
	rc = -1;
        goto loser;
    }
    if (!(response->GetSW1() == 0x90 && 
	 	response->GetSW2() == 0x00)) {
           RA::Error("RA_Processor::ImportKey",
                "Error Response from Token %2x%2x",
			response->GetSW1(),
			response->GetSW2());
	rc = -1;
           goto loser;
     }

    rc = 1;
loser:
    if( mac != NULL ) {
        delete mac;
        mac = NULL;
    }
    if( token_pdu_request_msg != NULL ) {
        delete token_pdu_request_msg;
        token_pdu_request_msg = NULL;
    }
    if( token_pdu_response_msg != NULL ) {
        delete token_pdu_response_msg;
        token_pdu_response_msg = NULL;
    }

    return rc;
} /* ImportKey */

/**
 * inject an encrypted key (private key, mostly)
 * @param key_number key slot number (from config file)
 */
int Secure_Channel::ImportKeyEnc(BYTE priv_key_number, BYTE pub_key_number, Buffer* data)
{
    int rc = -1;
    Import_Key_Enc_APDU *import_key_enc_apdu = NULL;
    APDU_Response *response = NULL;
    RA_Token_PDU_Request_Msg *token_pdu_request_msg = NULL;
    RA_Token_PDU_Response_Msg *token_pdu_response_msg = NULL;
    Buffer *mac = NULL;
      BYTE objid[4];

      objid[0] = 0xFF;
      objid[1] = 0xFF;
      objid[2] = 0xFF;
      objid[3] = 0xFE;


    RA::Debug("Secure_Channel::ImportKeyEnc",
        "Secure_Channel::ImportKeyEnc");

    import_key_enc_apdu = new Import_Key_Enc_APDU(priv_key_number, pub_key_number, *data);
    rc = ComputeAPDU(import_key_enc_apdu);
    if (rc == -1) {
      goto loser;
    }

    /*
    mac = ComputeAPDUMac(import_key_enc_apdu);
    import_key_enc_apdu->SetMAC(*mac);
    */
    token_pdu_request_msg = new RA_Token_PDU_Request_Msg(
        import_key_enc_apdu);
    m_session->WriteMsg(token_pdu_request_msg);
    RA::Debug("Secure_Channel::ImportKeyEnc",
        "Sent token_pdu_request_msg");

    token_pdu_response_msg = (RA_Token_PDU_Response_Msg *)
        m_session->ReadMsg();
    if (token_pdu_response_msg == NULL)
    {
        RA::Error("Secure_Channel::ImportKeyEnc",
            "No Token PDU Response Msg Received");
	rc = -1;
        goto loser;
    }
    if (token_pdu_response_msg->GetType() != MSG_TOKEN_PDU_RESPONSE) {
        RA::Error("Secure_Channel::ImportKeyEnc",
            "Invalid Msg Type");
	rc = -1;
        goto loser;
    }

    response = token_pdu_response_msg->GetResponse();
    if (response == NULL) {
        RA::Error("Secure_Channel::ImportKeyEnc",
            "No Response From Token");
	rc = -1;
        goto loser;
    }
    if (response->GetData().size() < 2) {
        RA::Error("Secure_Channel::ImportKeyEnc",
            "Invalid Response From Token");
	rc = -1;
        goto loser;
    }

    if (!(response->GetSW1() == 0x90 && 
		response->GetSW2() == 0x00)) {
      RA::Error("RA_Processor::ImportKeyEnc",
                "Error Response from Token %2x%2x",
				response->GetSW1(),
				response->GetSW2());
      /*XXX debuging
      debugBuf = ReadObject((BYTE*)objid, 0, 16);
      if (debugBuf != NULL)
	RA::DebugBuffer("Secure_Channel::ImportKeyEnc(): Error:", "debugBuf=",
    		debugBuf);
      else
	RA::Debug("Secure_Channel::ImportKeyEnc(): Error:", "ReadObject for debugging returns none");
      */
	rc = -1;
	goto loser;
     }

    /*      XXX debugging
      debugBuf = ReadObject((BYTE*)objid, 0, 200);
      if (debugBuf != NULL)
	RA::DebugBuffer("Secure_Channel::ImportKeyEnc(): Success:", "debugBuf=",
		    debugBuf);
      else
	RA::Debug("Secure_Channel::ImportKeyEnc(): Sucess:", "ReadObject for debugging returns none");

    */

    rc = 1;
loser:
    if( mac != NULL ) {
        delete mac;
        mac = NULL;
    }
    if( token_pdu_request_msg != NULL ) {
        delete token_pdu_request_msg;
        token_pdu_request_msg = NULL;
    }
    if( token_pdu_response_msg != NULL ) {
        delete token_pdu_response_msg;
        token_pdu_response_msg = NULL;
    }

    return rc;
} /* ImportKeyEnc */


/**
 * Put Keys
 *
 * Global Platform Open Platform Card Specification 
 * Version 2.0.1 Page 9-19
 * Sample Data:
 *
 * _____________ CLA
 * |  __________ INS
 * |  |  _______ P1
 * |  |  |  ____ P2
 * |  |  |  |  _ Len
 * |  |  |  |  |
 * 84 D8 00 81 4B
 * 01 
 * 81 10 B4 BA A8 9A 8C D0 29 2B 45 21 0E    (AUTH KEY)
 * 1B C8 4B 1C 31 
 * 03 8B AF 47 
 * 81 10 B4 BA A8 9A 8C D0 29 2B 45 21 0E    (MAC KEY) 
 * 1B C8 4B 1C 31 
 * 03 8B AF 47 
 * 81 10 B4 BA A8 9A 8C D0 29 2B 45 21 0E    (KEK KEY)
 * 1B C8 4B 1C 31 
 * 03 8B AF 47 
 * 5E B8 64 3F 73 9D 7D 62
 *
 * Data:
 *
 * - New key set version
 * - key set data field (implicit key index P2+0)
 * - key set data field (implicit key index P2+1)
 * - key set data field (implicit key index P2+2)
 * 
 * Key Set Data:
 * 
 * Length    Meaning
 * ======    =========
 * 1         Algorithm ID of key
 * 1-n       Length of key
 * variable  Key data value
 * 0-n       Length of Key check value
 * variable  Key check value (if present)
 */
int Secure_Channel::PutKeys(RA_Session *session, BYTE key_version, 
                   BYTE key_index, Buffer *key_data)
{
    int rc = 0;
    APDU_Response *put_key_response = NULL;
    RA_Token_PDU_Request_Msg *put_key_request_msg = NULL;
    RA_Token_PDU_Response_Msg *put_key_response_msg = NULL;
    Put_Key_APDU *put_key_apdu = NULL;
    // Buffer *mac = NULL;
	const char *FN="Secure_Channel::PutKeys";

    RA::Debug(LL_PER_CONNECTION, FN,
        "RA_Processor::PutKey");

    //For certain keys that require the implicit keyset
    //00 00
    //
    if(key_version == 0xFF)
        key_version = 0;

    put_key_apdu = new Put_Key_APDU(key_version, 0x80 | key_index, 
             *key_data);
    rc = ComputeAPDU(put_key_apdu);
    if (rc == -1)
      goto loser;

    /*
    mac = ComputeAPDUMac(put_key_apdu);
    put_key_apdu->SetMAC(*mac);
    */
    put_key_request_msg =
        new RA_Token_PDU_Request_Msg(put_key_apdu);
    session->WriteMsg(put_key_request_msg);
    RA::Debug(LL_PER_CONNECTION, FN,
        "Sent put_key_request_msg");

    put_key_response_msg = (RA_Token_PDU_Response_Msg *)
        session->ReadMsg();
    if (put_key_response_msg == NULL)
    {
    	RA::Error(LL_PER_CONNECTION, FN,
            "No Token PDU Response Msg Received");
	rc = -1;
        goto loser;
    }
    if (put_key_response_msg->GetType() != MSG_TOKEN_PDU_RESPONSE) {
        RA::Error(LL_PER_CONNECTION, FN,
            "Invalid Msg Type");
	rc = -1;
        goto loser;
    }
    put_key_response =
        put_key_response_msg->GetResponse();
    if (put_key_response == NULL) {
        RA::Error(LL_PER_CONNECTION, FN,
            "No Response From Token");
	rc = -1;
        goto loser;
    }
    if (put_key_response->GetData().size() < 2) {
        RA::Error(LL_PER_CONNECTION, FN,
            "Invalid Response From Token");
	rc = -1;
        goto loser;
    }
    if (!(put_key_response->GetSW1() == 0x90 && 
	 	put_key_response->GetSW2() == 0x00)) {
           RA::Error(LL_PER_CONNECTION, FN,
                "Error Response %2x%2x", 
					put_key_response->GetSW1(),
					put_key_response->GetSW2());
		rc = -1;
           goto loser;
     }

    /* check error */
    rc = 0;

loser:
    if( put_key_request_msg != NULL ) {
        delete put_key_request_msg;
        put_key_request_msg = NULL;
    }
    if( put_key_response_msg != NULL ) {
        delete put_key_response_msg;
        put_key_response_msg = NULL;
    }

    return rc;
}

/**
 * Sets token's lifecycle state.
 */
int Secure_Channel::SetLifecycleState(BYTE flag)
{
    int rc = -1;
    Lifecycle_APDU *lifecycle_apdu = NULL;
    APDU_Response *response = NULL;
    RA_Token_PDU_Request_Msg *token_pdu_request_msg = NULL;
    RA_Token_PDU_Response_Msg *token_pdu_response_msg = NULL;
    Buffer *mac = NULL;
	const char *FN = "Secure_Channel::SetLifecycleState";

    RA::Debug(LL_PER_CONNECTION,FN,
        "Begin");
    lifecycle_apdu = new Lifecycle_APDU(flag);
    rc = ComputeAPDU(lifecycle_apdu);
    if (rc == -1)
      goto loser;

    /*
    mac = ComputeAPDUMac(lifecycle_apdu);
    lifecycle_apdu->SetMAC(*mac);
    */
    token_pdu_request_msg = new RA_Token_PDU_Request_Msg(
        lifecycle_apdu);
    m_session->WriteMsg(token_pdu_request_msg);
    RA::Debug(LL_PER_CONNECTION,FN,
        "Sent token_pdu_request_msg");

    token_pdu_response_msg = (RA_Token_PDU_Response_Msg *)
        m_session->ReadMsg();
    if (token_pdu_response_msg == NULL)
    {
        RA::Error(LL_PER_CONNECTION,FN,
            "No Token PDU Response Msg Received");
        rc = -1;
        goto loser;
    }
    if (token_pdu_response_msg->GetType() != MSG_TOKEN_PDU_RESPONSE)
    {
        RA::Error(LL_PER_CONNECTION,FN,
            "Invalid Msg Received");
        rc = -1;
        goto loser;
    }
    response = token_pdu_response_msg->GetResponse();
    if (response == NULL) {
        RA::Error(LL_PER_CONNECTION,FN,
            "No Response From Token");
	rc = -1;
        goto loser;
    }
    if (response->GetData().size() < 2) {
        RA::Error(LL_PER_CONNECTION,FN,
            "Invalid Response From Token");
	rc = -1;
        goto loser;
    }
    if (!(response->GetSW1() == 0x90 && 
	 	response->GetSW2() == 0x00)) {
           RA::Error(LL_PER_CONNECTION,FN,
                "Error Response from token: %2x%2x",
				response->GetSW1(),
				response->GetSW2());
	   rc = -1;
           goto loser;
     }

    rc = 0;

loser:
    if( mac != NULL ) {
        delete mac;
        mac = NULL;
    }
    if( token_pdu_request_msg != NULL ) {
        delete token_pdu_request_msg;
        token_pdu_request_msg = NULL;
    }
    if( token_pdu_response_msg != NULL ) {
        delete token_pdu_response_msg;
        token_pdu_response_msg = NULL;
    }

    return rc;
} /* SetLifecycleState */


char * Secure_Channel::getDrmWrappedDESKey()
{
    return PL_strdup(m_drm_wrapped_des_key_s);
}

char * Secure_Channel::getKekWrappedDESKey()
{
    return PL_strdup(m_kek_wrapped_des_key_s);
}

char * Secure_Channel::getKeycheck()
{
    return PL_strdup(m_keycheck_s);
}


/**
 * Requests token to generate key in buffer.
 */
int Secure_Channel::StartEnrollment(BYTE p1, BYTE p2, Buffer *wrapped_challenge, 
	Buffer *key_check, BYTE alg, int keysize, BYTE option)
{
    int rc = -1;
    Generate_Key_APDU *generate_key_apdu = NULL;
    Generate_Key_ECC_APDU *generate_key_ecc_apdu = NULL;

    APDU_Response *response = NULL;
    RA_Token_PDU_Request_Msg *token_pdu_request_msg = NULL;
    RA_Token_PDU_Response_Msg *token_pdu_response_msg = NULL;
    Buffer *mac = NULL;
    Buffer data;

    RA::Debug("Secure_Channel::GenerateKey",
        "Secure_Channel::GenerateKey");

    bool isECC = RA::isAlgorithmECC(alg);

    if (isECC) {
        generate_key_ecc_apdu = new Generate_Key_ECC_APDU(p1, p2, alg, keysize, option,
            alg, *wrapped_challenge, *key_check);
        rc = ComputeAPDU(generate_key_ecc_apdu);
    } else {
        generate_key_apdu = new Generate_Key_APDU(p1, p2, alg, keysize, option,
            alg, *wrapped_challenge, *key_check);
        rc = ComputeAPDU(generate_key_apdu);
    }

    if (rc == -1)
      goto loser;

    /*
    mac = ComputeAPDUMac(generate_key_apdu);
    generate_key_apdu->SetMAC(*mac);
    */

    if (generate_key_ecc_apdu != NULL ) {
        token_pdu_request_msg = new RA_Token_PDU_Request_Msg(
            generate_key_ecc_apdu);
    } else {
        token_pdu_request_msg = new RA_Token_PDU_Request_Msg(
            generate_key_apdu);
    }

    m_session->WriteMsg(token_pdu_request_msg);
    RA::Debug("Secure_Channel::GenerateKey",
        "Sent token_pdu_request_msg");

    token_pdu_response_msg = (RA_Token_PDU_Response_Msg *)
        m_session->ReadMsg();
    if (token_pdu_response_msg == NULL)
    {
        RA::Error("Secure_Channel::GenerateKey",
            "No Token PDU Response Msg Received");
	rc = -1;
        goto loser;
    }
    if (token_pdu_response_msg->GetType() != MSG_TOKEN_PDU_RESPONSE)
    {
        RA::Error("Secure_Channel::GenerateKey",
            "Invalid Msg Received");
	rc = -1;
        goto loser;
    }
    response = token_pdu_response_msg->GetResponse();
    if (response == NULL) {
	RA::Error("SecureChannel::GenerateKey", "No Response From Token");
	rc = -1;
        goto loser;
    }

    data = response->GetData();
    if (data.size() != 4) {
	RA::Error("SecureChannel::GenerateKey", "Token returned error");
	rc = -1;
        goto loser;
    }
    if (!(response->GetSW1() == 0x90 && 
	 	response->GetSW2() == 0x00)) {
           RA::Error("RA_Processor::GenerateKey",
                "Error Response from token %2x%2x",
				response->GetSW1(),
				response->GetSW2());
	rc = -1;
           goto loser;
     }

    /* key length */
    rc = ((BYTE*)data)[0] * 256 + ((BYTE*)data)[1];               

loser:
    if( mac != NULL ) {
        delete mac;
        mac = NULL;
    }
    if( token_pdu_request_msg != NULL ) {
        delete token_pdu_request_msg;
        token_pdu_request_msg = NULL;
    }
    if( token_pdu_response_msg != NULL ) {
        delete token_pdu_response_msg;
        token_pdu_response_msg = NULL;
    }

    return rc;
} /* GenerateKey */

/**
 * Reads data from token's buffer.
 */
int Secure_Channel::ReadBuffer(BYTE *buf, int buf_len)
{
    int rc = -1;
    Read_Buffer_APDU *read_buffer_apdu = NULL;
    APDU_Response *response = NULL;
    RA_Token_PDU_Request_Msg *token_pdu_request_msg = NULL;
    RA_Token_PDU_Response_Msg *token_pdu_response_msg = NULL;
    int offset = 0;
    int wanted = buf_len;
    int received = 0;
    int request = 0;
    int data_len;
    Buffer data;
    Buffer *mac = NULL;
	const char *FN="Secure_Channel::ReadBuffer";

#define MAX_READ_BUFFER_SIZE 0xd0
        RA::Debug("Secure_Channel::ReadBuffer",
            "Secure_Channel::ReadBuffer");

    while (1)
    {
        if (wanted > MAX_READ_BUFFER_SIZE)
        {
            request = MAX_READ_BUFFER_SIZE;
        }
        else
        {
            request = wanted;
        }
        read_buffer_apdu = new Read_Buffer_APDU(request,offset);
	rc = ComputeAPDU(read_buffer_apdu);
	if (rc == -1)
	  goto loser;

	/*
        mac = ComputeAPDUMac(read_buffer_apdu);
        read_buffer_apdu->SetMAC(*mac);
	*/
        token_pdu_request_msg = new RA_Token_PDU_Request_Msg(
            read_buffer_apdu);
        m_session->WriteMsg(token_pdu_request_msg);
        RA::Debug(LL_PER_CONNECTION, FN,
            "Sent token_pdu_request_msg");

        token_pdu_response_msg = (RA_Token_PDU_Response_Msg *)
            m_session->ReadMsg();
        if (token_pdu_response_msg == NULL)
        {
            RA::Error(LL_PER_CONNECTION, FN,
                "No Token PDU Response Msg Received");
            rc = -1;
            goto loser;
        }
        if (token_pdu_response_msg->GetType() != MSG_TOKEN_PDU_RESPONSE) {
            RA::Error(LL_PER_CONNECTION, FN,
            "Invalid Msg Type");
            rc = -1;
            goto loser;
        }
        response = token_pdu_response_msg->GetResponse();
        if (response == NULL)
        {
            RA::Error(LL_PER_CONNECTION, FN,
                "No Response From Token");
            rc = -1;
            goto loser;
        }
        if (!(response->GetSW1() == 0x90 && 
	 	response->GetSW2() == 0x00)) {
           RA::Error(LL_PER_CONNECTION, FN,
                "Error Response from token %2x%2x",
				response->GetSW1(),
				response->GetSW2());
            rc = -1;
           goto loser;
        }
        data = response->GetData();
        data_len = data.size() - 2;
        if (data_len == 0)
        {
            break;
        }

// copy data into buffer
        for (int i = 0; i < data_len; i++)
        {
            buf[offset+i] = ((BYTE*)data)[i];
        }

        received += data_len;
        wanted -= data_len;
        offset += data_len;

        if (wanted == 0)
        {
            break;
        }

        if( token_pdu_request_msg != NULL ) {
            delete token_pdu_request_msg;
            token_pdu_request_msg = NULL;
        }
        if( token_pdu_response_msg != NULL ) {
            delete token_pdu_response_msg;
            token_pdu_response_msg = NULL;
        }
    };

    rc = received;
loser:
    if( mac != NULL ) {
        delete mac;
        mac = NULL;
    }
    if( token_pdu_request_msg != NULL ) {
        delete token_pdu_request_msg;
        token_pdu_request_msg = NULL;
    }
    if( token_pdu_response_msg != NULL ) {
        delete token_pdu_response_msg;
        token_pdu_response_msg = NULL;
    }

    return rc;
} /* ReadBuffer */

/**
 * Writes object to token.
 */
int Secure_Channel::CreateObject(BYTE *object_id, BYTE *permissions, int len)
{
    int rc = -1;
    Create_Object_APDU *create_obj_apdu = NULL;
    APDU_Response *response = NULL;
    RA_Token_PDU_Request_Msg *token_pdu_request_msg = NULL;
    RA_Token_PDU_Response_Msg *token_pdu_response_msg = NULL;
    Buffer *mac = NULL;

    RA::Debug("Secure_Channel::CreateObject",
        "Secure_Channel::CreateObject");
    create_obj_apdu = new Create_Object_APDU(object_id, permissions, len);
    rc = ComputeAPDU(create_obj_apdu);
    if (rc == -1)
      goto loser;

    /*
    mac = ComputeAPDUMac(create_obj_apdu);
    create_obj_apdu->SetMAC(*mac);
    */
    token_pdu_request_msg = new RA_Token_PDU_Request_Msg(
        create_obj_apdu);
    m_session->WriteMsg(token_pdu_request_msg);
    RA::Debug("Secure_Channel::CreateObject",
        "Sent token_pdu_request_msg");

    token_pdu_response_msg = (RA_Token_PDU_Response_Msg *)
        m_session->ReadMsg();
    if (token_pdu_response_msg == NULL)
    {
        RA::Error("Secure_Channel::CreateObject",
            "No Token PDU Response Msg Received");
	rc = -1;
        goto loser;
    }

    if (token_pdu_response_msg->GetType() != MSG_TOKEN_PDU_RESPONSE) {
            RA::Error("Secure_Channel::CreateObject",
            "Invalid Msg Type");
	rc = -1;
            goto loser;
    }

    response = token_pdu_response_msg->GetResponse();
    if (response == NULL) {
        RA::Error("Secure_Channel::CreateObject",
            "No Response From Token");
	rc = -1;
        goto loser;
    }
    if (response->GetData().size() < 2) {
        RA::Error("Secure_Channel::CreateObject",
            "Invalid Response From Token");
	rc = -1;
        goto loser;
    }
    if (!(response->GetSW1() == 0x90 && 
	 	response->GetSW2() == 0x00)) {
           RA::Error("RA_Processor::CreateObject",
                "Error Response from token %2x%2x",
				response->GetSW1(),
				response->GetSW2());
	rc = -1;
           goto loser;
    }

    rc = 1;
loser:
    if( mac != NULL ) {
        delete mac;
        mac = NULL;
    }
    if( token_pdu_request_msg != NULL ) {
        delete token_pdu_request_msg;
        token_pdu_request_msg = NULL;
    }
    if( token_pdu_response_msg != NULL ) {
        delete token_pdu_response_msg;
        token_pdu_response_msg = NULL;
    }

    return rc;
} /* CreateObject */ 

Buffer *Secure_Channel::ReadObject(BYTE *object_id, int offset, int len)
{
    int rc = -1;
    Buffer data;
    Read_Object_APDU *read_obj_apdu = NULL;
    APDU_Response *response = NULL;
    RA_Token_PDU_Request_Msg *token_pdu_request_msg = NULL;
    RA_Token_PDU_Response_Msg *token_pdu_response_msg = NULL;
    Buffer *mac = NULL;
    Buffer *buf = NULL;
    Buffer result = Buffer();

    RA::Debug("Secure_Channel::ReadObject",
        "Secure_Channel::ReadObject");
    int cur_read = 0;
    int cur_offset = 0;
    int sum = 0;

#define MAX_READ_BUFFER_SIZE 0xd0

    if (len > MAX_READ_BUFFER_SIZE) {
        cur_offset = offset;
    	cur_read = MAX_READ_BUFFER_SIZE;
    } else {
        cur_offset = offset;
    	cur_read = len;
    }

    while (sum < len) {

        read_obj_apdu = new Read_Object_APDU(object_id, cur_offset, cur_read);
        rc = ComputeAPDU(read_obj_apdu);
        if (rc == -1)
          goto loser;

        token_pdu_request_msg = new RA_Token_PDU_Request_Msg(
        	read_obj_apdu);
        m_session->WriteMsg(token_pdu_request_msg);
        RA::Debug("Secure_Channel::ReadObject",
            "Sent token_pdu_request_msg");

        token_pdu_response_msg = (RA_Token_PDU_Response_Msg *)
           m_session->ReadMsg();
        if (token_pdu_response_msg == NULL)
        {
           RA::Error("Secure_Channel::ReadObject",
            "No Token PDU Response Msg Received");
  	   rc = -1;
           goto loser;
        }

        if (token_pdu_response_msg->GetType() != MSG_TOKEN_PDU_RESPONSE) 
	{
            RA::Error("Secure_Channel::ReadObject",
            "Invalid Msg Type");
  	    rc = -1;
            goto loser;
        }

        response = token_pdu_response_msg->GetResponse();
        if (response == NULL) {
            RA::Error("Secure_Channel::ReadObject",
            "No Response From Token");
	    rc = -1;
           goto loser;
        }

        if (response->GetData().size() < 2) {
            RA::Error("Secure_Channel::ReadObject",
            "Invalid Response From Token");
	    rc = -1;
            goto loser;
        }
        if (!(response->GetSW1() == 0x90 && 
	 	response->GetSW2() == 0x00)) {
           RA::Error("RA_Processor::ReadObject",
                "Error Response from token %2x%2x",
				response->GetSW1(),
				response->GetSW2());
    	   rc = -1;
           goto loser;
        }
        data = response->GetData();
        result += Buffer(data.substr(0, data.size() - 2));

	sum += (data.size() - 2);
	cur_offset += (data.size() - 2);

	if ((len - sum) < MAX_READ_BUFFER_SIZE) {
		cur_read = len - sum;
	} else {
		cur_read = MAX_READ_BUFFER_SIZE;
	}
        if (token_pdu_request_msg != NULL) {
            delete token_pdu_request_msg;
	    token_pdu_request_msg = NULL;
	}
        if (token_pdu_response_msg != NULL) {
            delete token_pdu_response_msg;
	    token_pdu_response_msg = NULL;
	}

    }

    buf = new Buffer((BYTE*)result, result.size());

loser:
    if (mac != NULL)
        delete mac;
    if (token_pdu_request_msg != NULL)
        delete token_pdu_request_msg;
    if (token_pdu_response_msg != NULL)
        delete token_pdu_response_msg;

    return buf;
}

/**
 * Writes data to token's buffer.
 */
int Secure_Channel::WriteObject(BYTE *objid, BYTE *buf, int buf_len)
{
    int rc = -1;
    int i;
    Write_Object_APDU *write_buffer_apdu = NULL;
    APDU_Response *response = NULL;
    RA_Token_PDU_Request_Msg *token_pdu_request_msg = NULL;
    RA_Token_PDU_Response_Msg *token_pdu_response_msg = NULL;
    int offset = 0;
    int len = 0;
    int to_send = buf_len;
    BYTE *data = buf;
#define MAX_WRITE_BUFFER_SIZE 0xd0
    Buffer *send_buf = NULL;
    Buffer *mac = NULL;

        RA::Debug("Secure_Channel::WriteObject",
            "Secure_Channel::WriteObject");
    while (1)
    {
        send_buf = new Buffer(MAX_WRITE_BUFFER_SIZE, (BYTE)0);
        mac = new Buffer(8, (BYTE)0);

        if (to_send > MAX_WRITE_BUFFER_SIZE)
        {
            len = MAX_WRITE_BUFFER_SIZE;
        }
        else
        {
            len = to_send;
        }
        RA::Debug("Secure_Channel::WriteObject",
            "Sent total=%d len=%d", buf_len, len);

        for (i = 0; i < len; i++)
        {
            ((BYTE*)*send_buf)[i] = ((BYTE*)data)[i];
        }
	Buffer x_buf = Buffer(*send_buf, len);

        write_buffer_apdu = new Write_Object_APDU(objid, offset, x_buf);
        rc = ComputeAPDU(write_buffer_apdu);
	if (rc == -1)
	  goto loser;

	/*
        mac = ComputeAPDUMac(write_buffer_apdu);
        write_buffer_apdu->SetMAC(*mac);
	*/
        token_pdu_request_msg = new RA_Token_PDU_Request_Msg(
            write_buffer_apdu);
        m_session->WriteMsg(token_pdu_request_msg);
        RA::Debug("Secure_Channel::WriteObject",
            "Sent token_pdu_request_msg");

        token_pdu_response_msg = (RA_Token_PDU_Response_Msg *)
            m_session->ReadMsg();
        if (token_pdu_response_msg == NULL)
        {
            RA::Error("Secure_Channel::WriteObject",
                "No Token PDU Response Msg Received");
	    rc = -1;
            goto loser;
        }

        if (token_pdu_response_msg->GetType() != MSG_TOKEN_PDU_RESPONSE) {
            RA::Error("Secure_Channel::WriteObject",
            "Invalid Msg Type");
	    rc = -1;
            goto loser;
        }
        response = token_pdu_response_msg->GetResponse();
        if (response == NULL) {
            RA::Error("Secure_Channel::WriteObject",
               "No Response From Token");
	    rc = -1;
            goto loser;
        }
        if (!(response->GetSW1() == 0x90 && 
	 	response->GetSW2() == 0x00)) {
           RA::Error("RA_Processor::WriteObject",
                "Error Response from token %2x%2x",
				response->GetSW1(),
				response->GetSW2());
	    rc = -1;
           goto loser;
        }
        data += len;
        to_send -= len;
        offset += len;

        if (to_send == 0)
            break;                                /* done */
        if( mac != NULL ) {
            delete mac;
            mac = NULL;
        }
        if( token_pdu_request_msg != NULL ) {
            delete token_pdu_request_msg;
            token_pdu_request_msg = NULL;
        }
        if( token_pdu_response_msg != NULL ) {
            delete token_pdu_response_msg;
            token_pdu_response_msg = NULL;
        }
        if( send_buf != NULL ) {
            delete send_buf;
            send_buf = NULL;
        }
    }

    rc = 1;
loser:
    if( mac != NULL ) {
        delete mac;
        mac = NULL;
    }
    if( token_pdu_request_msg != NULL ) {
        delete token_pdu_request_msg;
        token_pdu_request_msg = NULL;
    }
    if( token_pdu_response_msg != NULL ) {
        delete token_pdu_response_msg;
        token_pdu_response_msg = NULL;
    }
    if( send_buf != NULL ) {
        delete send_buf;
        send_buf = NULL;
    }

    return rc;
} /* WriteObject */ 

int Secure_Channel::CreatePin(BYTE pin_number,
                BYTE max_retries, const char *pin)
{
    int rc = -1;
    Create_Pin_APDU *create_pin_apdu = NULL;
    APDU_Response *response = NULL;
    RA_Token_PDU_Request_Msg *token_pdu_request_msg = NULL;
    RA_Token_PDU_Response_Msg *token_pdu_response_msg = NULL;
    Buffer *mac = NULL;

    RA::Debug("Secure_Channel::CreatePin",
        "Secure_Channel::CreatePin");
    Buffer pin_buffer = Buffer((BYTE*)pin, strlen(pin));
    create_pin_apdu = new Create_Pin_APDU(pin_number, max_retries,
                    pin_buffer);
    rc = ComputeAPDU(create_pin_apdu);
    if (rc == -1)
      goto loser;

    /*
    mac = ComputeAPDUMac(set_pin_apdu);
    set_pin_apdu->SetMAC(*mac);
    */
    token_pdu_request_msg = new RA_Token_PDU_Request_Msg(
        create_pin_apdu);
    m_session->WriteMsg(token_pdu_request_msg);
    RA::Debug("Secure_Channel::CreatePin",
        "Sent token_pdu_request_msg");

    token_pdu_response_msg = (RA_Token_PDU_Response_Msg *)
        m_session->ReadMsg();
    if (token_pdu_response_msg == NULL)
    {
        RA::Error("Secure_Channel::CreatePin",
            "No Token PDU Response Msg Received");
        rc = -1;
        goto loser;
    }
    if (token_pdu_response_msg->GetType() != MSG_TOKEN_PDU_RESPONSE) {
        RA::Error("Secure_Channel::CreatePin",
            "Invalid Msg Type");
        rc = -1;
        goto loser;
    }
    response = token_pdu_response_msg->GetResponse();
    if (response == NULL) {
        RA::Error("Secure_Channel::CreatePin",
            "No Response From Token");
        rc = -1;
        goto loser;
    }

    rc = 1;
loser:
    if( mac != NULL ) {
        delete mac;
        mac = NULL;
    }
    if( token_pdu_request_msg != NULL ) {
        delete token_pdu_request_msg;
        token_pdu_request_msg = NULL;
    }
    if( token_pdu_response_msg != NULL ) {
        delete token_pdu_response_msg;
        token_pdu_response_msg = NULL;
    }

    return rc;
}

APDU_Response *Secure_Channel::SendTokenAPU(APDU *apdu)
{
    int rc;
    APDU_Response *response = NULL;
    RA_Token_PDU_Request_Msg *token_pdu_request_msg = NULL;
    RA_Token_PDU_Response_Msg *token_pdu_response_msg = NULL;

    RA::Debug("Secure_Channel::SendTokenAPDU",
        "Secure_Channel::SendTokenAPDU");
    rc = ComputeAPDU(apdu);
    if (rc == -1)
      goto loser;

    token_pdu_request_msg = new RA_Token_PDU_Request_Msg(
        apdu);
    m_session->WriteMsg(token_pdu_request_msg);
    RA::Debug("Secure_Channel::SendTokenAPDU",
        "Sent token_pdu_request_msg");

    token_pdu_response_msg = (RA_Token_PDU_Response_Msg *)
        m_session->ReadMsg();
    if (token_pdu_response_msg == NULL)
    {
        RA::Error("Secure_Channel::SendTokenAPDU",
            "No Token PDU Response Msg Received");
        rc = -1;
        goto loser;
    }
    if (token_pdu_response_msg->GetType() != MSG_TOKEN_PDU_RESPONSE) {
        RA::Error("Secure_Channel::SendTokenAPDU",
            "Invalid Msg Type");
        rc = -1;
        goto loser;
    }
    response = token_pdu_response_msg->GetResponse();
    if (response == NULL) {
        RA::Error("Secure_Channel::SendTokenAPDU",
            "No Response From Token");
        rc = -1;
        goto loser;
    }

loser:
    if( token_pdu_request_msg != NULL ) {
        delete token_pdu_request_msg;
        token_pdu_request_msg = NULL;
    }
    if( token_pdu_response_msg != NULL ) {
        delete token_pdu_response_msg;
        token_pdu_response_msg = NULL;
    }

    return response;
}


static void AppendSHORTtoBuffer(Buffer &buf,unsigned short s)
{

    buf += s/256;
    buf += s%256;
}


static void AppendLONGtoBuffer(Buffer &buf, unsigned int l)
{
    buf += l>>24;
    buf += (l >> 16) & 0xFF;
    buf += (l >> 8) & 0xFF;
    buf += l & 0xFF;
}

static void AppendAttribute(Buffer &buf, unsigned int type, unsigned int length, BYTE *b)
{
    AppendLONGtoBuffer(buf, type);
    AppendSHORTtoBuffer(buf, length);
    buf += Buffer(b,length);
}

static void AppendKeyCapabilities(Buffer &b, const char *opType, const char *tokenType, const char *keyTypePrefix, const char *keyType) {
    char configname[256];

    bool bvalue = false;
        PR_snprintf((char *)configname, 256, "%s.%s.keyCapabilities.encrypt",
          keyTypePrefix, keyType);
        bvalue = RA::GetConfigStore()->GetConfigAsBool(configname);
        AppendAttribute(b,CKA_ENCRYPT, 1, Util::bool2byte(bvalue));
        PR_snprintf((char *)configname, 256, "%s.%s.keyCapabilities.sign",
          keyTypePrefix, keyType);
        bvalue = RA::GetConfigStore()->GetConfigAsBool(configname);
        AppendAttribute(b,CKA_SIGN, 1, Util::bool2byte(bvalue));
        PR_snprintf((char *)configname, 256, "%s.%s.keyCapabilities.signRecover",
          keyTypePrefix, keyType);
        bvalue = RA::GetConfigStore()->GetConfigAsBool(configname);
        AppendAttribute(b,CKA_SIGN_RECOVER, 1, Util::bool2byte(bvalue));
        PR_snprintf((char *)configname, 256, "%s.%s.keyCapabilities.decrypt",
          keyTypePrefix, keyType);
        bvalue = RA::GetConfigStore()->GetConfigAsBool(configname);
        AppendAttribute(b,CKA_DECRYPT, 1, Util::bool2byte(bvalue));
        PR_snprintf((char *)configname, 256, "%s.%s.keyCapabilities.derive",
          keyTypePrefix, keyType);
        bvalue = RA::GetConfigStore()->GetConfigAsBool(configname);
        AppendAttribute(b,CKA_DERIVE, 1, Util::bool2byte(bvalue));
        PR_snprintf((char *)configname, 256, "%s.%s.keyCapabilities.unwrap",
          keyTypePrefix, keyType);
        bvalue = RA::GetConfigStore()->GetConfigAsBool(configname);
        AppendAttribute(b,CKA_UNWRAP, 1, Util::bool2byte(bvalue));
        PR_snprintf((char *)configname, 256, "%s.%s.keyCapabilities.wrap",
          keyTypePrefix, keyType);
        bvalue = RA::GetConfigStore()->GetConfigAsBool(configname);
        AppendAttribute(b,CKA_WRAP, 1, Util::bool2byte(bvalue));
        PR_snprintf((char *)configname, 256, "%s.%s.keyCapabilities.verifyRecover",
          keyTypePrefix, keyType);
        bvalue = RA::GetConfigStore()->GetConfigAsBool(configname);
        AppendAttribute(b,CKA_VERIFY_RECOVER, 1, Util::bool2byte(bvalue));
        PR_snprintf((char *)configname, 256, "%s.%s.keyCapabilities.verify",
          keyTypePrefix, keyType);
        bvalue = RA::GetConfigStore()->GetConfigAsBool(configname);
        AppendAttribute(b,CKA_VERIFY, 1, Util::bool2byte(bvalue));
        PR_snprintf((char *)configname, 256, "%s.%s.keyCapabilities.sensitive",
          keyTypePrefix, keyType);
        bvalue = RA::GetConfigStore()->GetConfigAsBool(configname);
        AppendAttribute(b,CKA_SENSITIVE, 1, Util::bool2byte(bvalue));
        PR_snprintf((char *)configname, 256, "%s.%s.keyCapabilities.private",
          keyTypePrefix, keyType);
        bvalue = RA::GetConfigStore()->GetConfigAsBool(configname);
        AppendAttribute(b,CKA_PRIVATE, 1, Util::bool2byte(bvalue));
        PR_snprintf((char *)configname, 256, "%s.%s.keyCapabilities.token",
          keyTypePrefix, keyType);
        bvalue = RA::GetConfigStore()->GetConfigAsBool(configname);
        AppendAttribute(b,CKA_TOKEN, 1, Util::bool2byte(bvalue));
}

static void FinalizeBuffer(Buffer &b, const char* id)
{
        ((BYTE*)b)[0] = 0;
        ((BYTE*)b)[1] = id[0];
        ((BYTE*)b)[2] = id[1];
        ((BYTE*)b)[3] = 0;
        ((BYTE*)b)[4] = 0;
        ((BYTE*)b)[5] = (b.size()-7) / 256;
        ((BYTE*)b)[6] = (b.size()-7) % 256;
}

/**
 * Creates object on token.
 */
int Secure_Channel::CreateObject(BYTE *objid, BYTE *permissions, Buffer *obj)
{
    int rc = -1;
    rc = CreateObject(objid, permissions, obj->size());
    if (rc == -1)
        goto loser;
    rc = WriteObject(objid, (BYTE*)*obj, obj->size());
    if (rc == -1)
        goto loser;
    rc = 1;
loser:
    return rc;
} /* CreateObject */

int Secure_Channel::CreateCertificate(const char *id, Buffer *cert)
{
	BYTE perms[6];

	perms[0] = 0xff;
	perms[1] = 0xff;
	perms[2] = 0x40;
	perms[3] = 0x00;
	perms[4] = 0x40;
	perms[5] = 0x00;

    return CreateObject((BYTE*)id, perms, cert);
} /* CreateCertificate */

/*
Cert attrib object (c0):
CKA_LABEL(0x0003): cert nickname
CKA_ID (0x0102): 20 bytes same as public key
CKA_CERTIFICATE_TYPE(0x0080): 00 00 00 00 (CKC_X_509)
CKA_CLASS(0x0000): 01 00 00 00 (little-endian for CKO_CERTIFICATE)
CKA_TOKEN(0x0001): true

0000000 0063 3000 0000 6400 0000 0300 294a 616d   /Jam
0000020 6965 204e 6963 6f6c 736f 6e27 7320 416d   /ie Nicolson's Am
0000040 6572 6963 6120 4f6e 6c69 6e65 2049 6e63   /erica Online Inc
0000060 2049 4420 2332
                       0000 0102 0014 709b a306   /ID #2
0000100 3fc8 9ad4 23c6 a1b2 eb04 d8ff f7dd 3f55
0000120 0000 0080 0004 0000 0000 0000 0000 0004
0000140 0100 0000 0000 0001 0001 0100 0000 0000
0000160 0000 0000 0000 0000 0000 0000 0000 0000

mine: (no subject)


        0063 3000 0000 4500 0000 0300 0A74 6861
        7965 7330 3939 33
                       0000 0102 0014 206E 8B36
                03A5 568D 266D 51EC 40F0 E35B B55F 8BCC
                0000 0080 0004 0000 0000 0000 0000 0004
                0100 0000 0000 0001 0001 01

*/

Buffer Secure_Channel::CreatePKCS11CertAttrsBuffer(TokenKeyType key_type, const char *id, const char *label, Buffer *keyid)
{
    BYTE type[4] = { 0,0,0,0 };
    BYTE p11class[4] = { 1,0,0,0 };
    BYTE tokenflag[1] = { 1 };

    Buffer b(256);       // allocate some space
    b.resize(7);         // this keeps the allocated space around

    RA::Debug("Secure_Channel::CreatePKCS11CertAttrsBuffer", "id=%s", id);
  RA::Debug("Secure_Channel::CreatePKCS11CertAttrsBuffer", "label=%s", label);
  RA::DebugBuffer("Secure_Channel::CreatePKCS11CertAttrsBuffer", "keyid", keyid);
    AppendAttribute(b, CKA_LABEL, strlen(label), (BYTE*)label);
    // hash of pubk
    AppendAttribute(b, CKA_ID,  keyid->size(), (BYTE*)*keyid);
     // type of cert
    AppendAttribute(b, CKA_CERTIFICATE_TYPE, 4, type);
    AppendAttribute(b, CKA_CLASS, 4, p11class );  // type of object
    AppendAttribute(b, CKA_TOKEN, 1, tokenflag);
    FinalizeBuffer(b, id);

 RA::DebugBuffer("Secure_Channel::CreatePKCS11CertAttrsBuffer", "buffer", &b);

   return b;
}

int Secure_Channel::CreatePKCS11CertAttrs(TokenKeyType key_type, const char *id, const char *label, Buffer *keyid)
{
    BYTE type[4] = { 0,0,0,0 };
    BYTE p11class[4] = { 1,0,0,0 };
    BYTE tokenflag[1] = { 1 };

    Buffer b(256);       // allocate some space
    b.resize(7);         // this keeps the allocated space around

  RA::Debug("Secure_Channel::CreatePKCS11CertAttrs", "id=%s", id);
  RA::Debug("Secure_Channel::CreatePKCS11CertAttrs", "label=%s", label);
  RA::DebugBuffer("Secure_Channel::CreatePKCS11CertAttrs", "keyid", keyid);
    AppendAttribute(b, CKA_LABEL, strlen(label), (BYTE*)label);
    // hash of pubk
    AppendAttribute(b, CKA_ID,  keyid->size(), (BYTE*)*keyid);
     // type of cert
    AppendAttribute(b, CKA_CERTIFICATE_TYPE, 4, type);
    AppendAttribute(b, CKA_CLASS, 4, p11class );  // type of object
    AppendAttribute(b, CKA_TOKEN, 1, tokenflag);
    FinalizeBuffer(b, id);

 RA::DebugBuffer("Secure_Channel::CreatePKCS11CertAttrs", "buffer", &b);

	BYTE perms[6];

	perms[0] = 0xff;
	perms[1] = 0xff;
	perms[2] = 0x40;
	perms[3] = 0x00;
	perms[4] = 0x40;
	perms[5] = 0x00;

    return CreateObject((BYTE*)id, perms, &b);
} /* CreatePKCS11CertAttrs */

/*

Private Key: (k0)
CKA_SUBJECT (0x0101): subject name of cert
CKA_LABEL (0x0003): nickname of cert
CKA_MODULUS (0x0120)
   (sha1 hash of spki)
CKA_ID (0x0102): ?? (20 bytes, 70 9b a3 06 3f c8 9a d4 23 c6 a1 b2 eb 04 d8 ff f7 dd 3f 55)
CKA_SENSITIVE(0x0103): true
CKA_PRIVATE(0x0002): true
CKA_TOKEN(0x0001): true
CKA_KEY_TYPE(0x0100): 0x00000000 (CKK_RSA)
cKA_CLASS(0x0000): 03 00 00 00 (little-endian(!) for CKO_PRIVATE_KEY)


0000000 006b 3000 0001 8400 0001 0100 8630 8183
0000020 310b 3009 0603 5504 0613 0255 5331 1b30
0000040 1906 0355 040a 1312 416d 6572 6963 6120
0000060 4f6e 6c69 6e65 2049 6e63 3118 3016 060a 
0000100 0992 2689 93f2 2c64 0101 1308 6e69 636f
0000120 6c73 6f6e 3124 3022 0609 2a86 4886 f70d
0000140 0109 0116 156e 6963 6f6c 736f 6e40 6e65
0000160 7473 6361 7065 2e63 6f6d 3117 3015 0603
0000200 5504 0313 0e4a 616d 6965 204e 6963 6f6c
0000220 736f 6e00 00
        00 0300 294a 616d 6965 204e
0000240 6963 6f6c 736f 6e27 7320 416d 6572 6963
0000260 6120 4f6e 6c69 6e65 2049 6e63 2049 4420
0000300 2332 
             0000 0120 0080 a70e 07f4 3f51 86c7
0000320 4f8d 4b64 522d 8c4b 31ae 58f2 f04d a9fd
0000340 2701 637e 5245 bb48 23ec 2259 742b ddc4
0000360 e5da f571 78df 07ba b555 6d05 0de5 7329
0000400 f073 94e2 00a6 f846 d99d d01c 8b62 684c
0000420 5133 9b16 3c8f ee83 34fc 844d 829b 6fca
0000440 e694 c432 9532 6413 323c 8b81 bc64 ed30
0000460 6074 6926 aff5 6b7f cb43 0c40 c039 ba55
0000500 7d3a 365d bb82 0b49 0000 0102 0014 709b
0000520 a306 3fc8 9ad4 23c6 a1b2 eb04 d8ff f7dd
0000540 3f55 0000 0103 0001 0100 0000 0200 0101
0000560 0000 0001 0001 0100 0001 0000 0400 0000
0000600 0000 0000 0000 0403 0000 0000 0000 0000
0000620 0000 0000 0000 0000 0000 0000 0000 0000
0000640 0000 015e ffff ffff fffe 0002 0002 0002
0000660 014e 0000 0000 0000 0000 0000 0000 0000
0000700 0000 0000 0000 0000 0000 0000 0000 0000

mine:

        006B 3000 0000 D900 0000 0300 0A74 6861
        7965 7330 3939 33
             0000 0120 0080 DB1F EF
        9EEA 63EC F3A9 F831 EDB2 AC38 3957 1917
        186D 1CEB 782D 34BA B6DA 4F65 54A5 68B0
        A08F 7840 FDF8 E115 E8A4 1522 4706 B807
        572A 31D2 2BB9 DD9F AF0C 2E0B 8183 ADE2
        78C4 B13E 0ED6 92F1 9989 D872 1474 A7A6
        2205 7928 1977 075A 5A76 B24D 8FE0 99C1
        32BE AE72 5C5D A8FA 3E93 F815 0669 074A
        2FF5 99EE 4A29 EDC8 5B79 7B93 5D
                0000 0102 0014 206E 8B36 03A5 568D 266D
            51EC 40F0 E35B B55F 8BCC
        0000 0103 0001 0100 00
        00020001010000000100010100000100
        00040000000000000000000403000000

        H 00020001010000000100010100000100
                H 00040000000000000000000403000000

        M 00020001010000000100010100000100
        M 00040000000000000000000403000000
*/

Buffer Secure_Channel::CreatePKCS11PriKeyAttrsBuffer(TokenKeyType key_type, const char *id, const char *label, Buffer *keyid, 
                Buffer *modulus, const char *opType, const char *tokenType, const char *keyTypePrefix)
{
    // BYTE sensitiveflag[1] = { 1 };
    // BYTE privateflag[1] = { 1 };
    // BYTE token[1] = { 1 };
    BYTE keytype[4] = { 0,0,0,0 };
    BYTE p11class[4] = { 3,0,0,0 };
    // BYTE ZERO[1] = { 0 };
    // BYTE ONE[1] = { 1 };
    // char configname[256];

    Buffer b(256);               // allocate some space
    b.resize(7);                 // this keeps the allocated space around

  RA::Debug("Secure_Channel::CreatePKCS11PriAttrs", "label=%s", label);
  RA::DebugBuffer("Secure_Channel::CreatePKCS11PriAttrs", "keyid", keyid);
  RA::DebugBuffer("Secure_Channel::CreatePKCS11PriAttrs", "modulus", modulus);
  RA::Debug("Secure_Channel::CreatePKCS11PriAttrs", "id=%s",id);

//    AppendAttribute(b,CKA_LABEL, strlen(label), (BYTE*)label);
    AppendAttribute(b,CKA_MODULUS, modulus->size(), (BYTE*)*modulus);
    AppendAttribute(b,CKA_KEY_TYPE, 4, keytype);
    AppendAttribute(b,CKA_CLASS, 4, p11class );
    // hash of pubk
    AppendAttribute(b,CKA_ID, keyid->size(),   (BYTE*)*keyid);

    AppendKeyCapabilities(b, opType, tokenType, keyTypePrefix, "private");

    FinalizeBuffer(b, id);

 RA::DebugBuffer("Secure_Channel::CreatePKCS11PriAttrsBuffer", "buffer", &b);

    return b;

} /* CreatePKCS11PriKeyAttrs */

int Secure_Channel::CreatePKCS11PriKeyAttrs(TokenKeyType key_type, const char *id, const char *label, Buffer *keyid, 
                Buffer *modulus, const char *opType, const char *tokenType, const char *keyTypePrefix)
{
    // BYTE sensitiveflag[1] = { 1 };
    // BYTE privateflag[1] = { 1 };
    // BYTE token[1] = { 1 };
    BYTE keytype[4] = { 0,0,0,0 };
    BYTE p11class[4] = { 3,0,0,0 };
    // BYTE ZERO[1] = { 0 };
    // BYTE ONE[1] = { 1 };
    // char configname[256];

    Buffer b(256);               // allocate some space
    b.resize(7);                 // this keeps the allocated space around

  RA::Debug("Secure_Channel::CreatePKCS11PriAttrs", "label=%s", label);
  RA::DebugBuffer("Secure_Channel::CreatePKCS11PriAttrs", "keyid", keyid);
  RA::DebugBuffer("Secure_Channel::CreatePKCS11PriAttrs", "modulus", modulus);

//    AppendAttribute(b,CKA_LABEL, strlen(label), (BYTE*)label);
    AppendAttribute(b,CKA_MODULUS, modulus->size(), (BYTE*)*modulus);
    AppendAttribute(b,CKA_KEY_TYPE, 4, keytype);
    AppendAttribute(b,CKA_CLASS, 4, p11class );
    // hash of pubk
    AppendAttribute(b,CKA_ID, keyid->size(),   (BYTE*)*keyid);

    AppendKeyCapabilities(b, opType, tokenType, keyTypePrefix, "private");

    FinalizeBuffer(b, id);

 RA::DebugBuffer("Secure_Channel::CreatePKCS11PriAttrs", "buffer", &b);

	BYTE perms[6];

	perms[0] = 0xff;
	perms[1] = 0xff;
	perms[2] = 0x40;
	perms[3] = 0x00;
	perms[4] = 0x40;
	perms[5] = 0x00;

    return CreateObject((BYTE*)id, perms, &b);

} /* CreatePKCS11PriKeyAttrs */

Buffer Secure_Channel::CreatePKCS11ECCPriKeyAttrsBuffer(TokenKeyType type, const char *id, const char *label, Buffer *keyid,
                SECKEYECParams *ecParams, const char *opType, const char *tokenType, const char *keyTypePrefix)
{

    BYTE keytype[8] = { 0,0,0,3 };
    BYTE p11class[4] = { 3,0,0,0 };

    Buffer b(256);               // allocate some space
    b.resize(7);                 // this keeps the allocated space around

    if (label != NULL)
        RA::Debug("Secure_Channel::CreatePKCS11ECCPriKeyAttrsBuffer", "label=%s", label);
    if (keyid != NULL)
        RA::DebugBuffer("Secure_Channel::CreatePKCS11ECCPriKeyAttrsBuffer", "keyid", keyid);
    if (id != NULL)
        RA::Debug("Secure_Channel::CreatePKCS11ECCPriKeyAttrsBuffer", "id=%s",id);

    AppendAttribute(b,CKA_KEY_TYPE, 4, keytype);
    AppendAttribute(b,CKA_CLASS, 4, p11class );
    // hash of pubk
    AppendAttribute(b,CKA_ID, keyid->size(),   (BYTE*)*keyid);

    AppendAttribute(b,CKA_EC_PARAMS, ecParams->len, ecParams->data);
    AppendKeyCapabilities(b, opType, tokenType, keyTypePrefix, "private");

    FinalizeBuffer(b, id);

    RA::DebugBuffer("Secure_Channel::CreatePKCS11ECCPriKeyAttrsBuffer", "buffer", &b);

    return b;

}

/*
Public Key: (k1)
CKA_PUBLIC_EXPONENT(0x0122)
CKA_MODULUS(0x0120)
CKA_ID (0x0102): (20 bytes) same as private key
CKA_CLASS(0x0000): 02 00 00 00 (little-endian for CKO_PUBLIC_KEY)

0000000 006b 3100 0000 b300 0001 2200 0301 0001
0000020 0000 0120 0080 a70e 07f4 3f51 86c7 4f8d
0000040 4b64 522d 8c4b 31ae 58f2 f04d a9fd 2701
0000060 637e 5245 bb48 23ec 2259 742b ddc4 e5da 
0000100 f571 78df 07ba b555 6d05 0de5 7329 f073
0000120 94e2 00a6 f846 d99d d01c 8b62 684c 5133
0000140 9b16 3c8f ee83 34fc 844d 829b 6fca e694
0000160 c432 9532 6413 323c 8b81 bc64 ed30 6074
0000200 6926 aff5 6b7f cb43 0c40 c039 ba55 7d3a 
0000220 365d bb82 0b49 0000 0102 0014 709b a306
0000240 3fc8 9ad4 23c6 a1b2 eb04 d8ff f7dd 3f55
0000260 0000 0000 0004 0200 0000 0000 0000 0000
0000300 0000 0000 0000 0000 0000 0000 0000 0000
*   
0000400

mine:
        006B 3100 0000 B300 0001 2200 0301 0001
        0000 0120 0080 F3E1 1AF0 906D BD35 4792 
                348A CC4D 6147 CFAC 659A D018 34DD 4621
                AB57 75F5 B5E0 87D4 F6C2 2B89 3324 D980
                2926 4BF1 0F64 A6E5 4368 9DA5 2620 335E
                ADCD 7540 7CBA B1F9 4ACE EEF8 13FF 6524
                B76F C7B1 2D21 DD42 5342 EFC3 034E 39DD
                ACBC 5C43 AC14 974A 45D4 5E66 6FFA BB17
                1E98 C177 68CC B51B 1B7E 28C5 38AB 729D
                27FD 3077 8C39 0000 0102 0014 815B 6FFE
                9B2A 8515 9C76 0F92 4A4E 349F 61EA 521F
                0000 0000 0004 0200 0000


*/
Buffer Secure_Channel::CreatePKCS11PubKeyAttrsBuffer(TokenKeyType key_type, const char *id, const char *label, Buffer *keyid,
                Buffer *exponent, Buffer *modulus, const char *opType, const char *tokenType, const char *keyTypePrefix)
{
#if 0
    BYTE pubexp[3] =     // XXX should I really hardcode this!?
    {
        0x01,0x00,0x01
    };
#endif
    BYTE p11class[4] = { 2,0,0,0 };
    // BYTE ZERO[1] = { 0 };
    // BYTE ONE[1] = { 1 };
    // char configname[256];

    Buffer b(256);        // allocate some space
    b.resize(7);          // this keeps the allocated space around

  RA::Debug("Secure_Channel::CreatePKCS11PubAttrs", "label=%s", label);
  RA::DebugBuffer("Secure_Channel::CreatePKCS11PubAttrs", "keyid", keyid);
  RA::DebugBuffer("Secure_Channel::CreatePKCS11PubAttrs", "modulus", modulus);
  RA::DebugBuffer("Secure_Channel::CreatePKCS11PubAttrs", "exponent", exponent);

    AppendAttribute(b, CKA_PUBLIC_EXPONENT, exponent->size(),(BYTE*) *exponent);
    AppendAttribute(b,CKA_MODULUS, modulus->size(), (BYTE*)*modulus);
     // XXX TUES
    // hash of pubk
    AppendAttribute(b,CKA_ID,  keyid->size(), (BYTE*)*keyid);
    AppendAttribute(b, CKA_CLASS, 4, p11class );  // type of object

    AppendKeyCapabilities(b, opType, tokenType, keyTypePrefix, "public");


    FinalizeBuffer(b, id);

 RA::DebugBuffer("Secure_Channel::CreatePKCS11PubAttrsBuffer", "buffer", &b);

    return b;
} /* CreatePKCS11PubKeyAttrs */


Buffer Secure_Channel::CreatePKCS11ECCPubKeyAttrsBuffer(TokenKeyType key_type, const char *id, const char *label, Buffer *keyid,
                  SECKEYECPublicKey *publicKey, SECKEYECParams *ecParams, const char *opType, const char *tokenType, const char *keyTypePrefix)
{
    BYTE p11class[4] = { 2,0,0,0 };
    // BYTE ZERO[1] = { 0 };
    // BYTE ONE[1] = { 1 };
    // char configname[256];

    BYTE keytype[4] = { 0,0,0,3 };
    Buffer b(256);        // allocate some space
    b.resize(7);          // this keeps the allocated space around

    if (label != NULL)
        RA::Debug("Secure_Channel::CreatePKCS11ECCPubAttrsBuffer", "label=%s", label);
    if (keyid != NULL)
        RA::DebugBuffer("Secure_Channel::CreatePKCS11ECCPubAttrsBuffer", "keyid", keyid);

     // XXX TUES
    // hash of pubk
    AppendAttribute(b,CKA_ID,  keyid->size(), (BYTE*)*keyid);
    AppendAttribute(b, CKA_CLASS, 4, p11class );  // type of object
    AppendAttribute(b,CKA_KEY_TYPE, 4, keytype);  // CKK_EC key type
    AppendAttribute(b,CKA_EC_PARAMS, ecParams->len, (BYTE *) ecParams->data);
    AppendAttribute(b, CKA_EC_POINT, publicKey->publicValue.len, (BYTE *) publicKey->publicValue.data);

    AppendKeyCapabilities(b, opType, tokenType, keyTypePrefix, "public");

    FinalizeBuffer(b, id);

    RA::DebugBuffer("Secure_Channel::CreatePKCS11ECCPubAttrsBuffer", "buffer", &b);

    return b;
} /* CreatePKCS11ECCPubKeyAttrs */



int Secure_Channel::CreatePKCS11PubKeyAttrs(TokenKeyType key_type, const char *id, const char *label, Buffer *keyid,
                Buffer *exponent, Buffer *modulus, const char *opType, const char *tokenType, const char *keyTypePrefix)
{
#if 0
    BYTE pubexp[3] =     // XXX should I really hardcode this!?
    {
        0x01,0x00,0x01
    };
#endif
    BYTE p11class[4] = { 2,0,0,0 };
    // BYTE ZERO[1] = { 0 };
    // BYTE ONE[1] = { 1 };
    // char configname[256];

    Buffer b(256);        // allocate some space
    b.resize(7);          // this keeps the allocated space around

  RA::Debug("Secure_Channel::CreatePKCS11PubAttrs", "label=%s", label);
  RA::DebugBuffer("Secure_Channel::CreatePKCS11PubAttrs", "keyid", keyid);
  RA::DebugBuffer("Secure_Channel::CreatePKCS11PubAttrs", "modulus", modulus);
  RA::DebugBuffer("Secure_Channel::CreatePKCS11PubAttrs", "exponent", exponent);

    AppendAttribute(b, CKA_PUBLIC_EXPONENT, exponent->size(),(BYTE*) *exponent);
    AppendAttribute(b,CKA_MODULUS, modulus->size(), (BYTE*)*modulus);
     // XXX TUES
    // hash of pubk
    AppendAttribute(b,CKA_ID,  keyid->size(), (BYTE*)*keyid);
    AppendAttribute(b, CKA_CLASS, 4, p11class );  // type of object

    AppendKeyCapabilities(b, opType, tokenType, keyTypePrefix, "public");


    FinalizeBuffer(b, id);

 RA::DebugBuffer("Secure_Channel::CreatePKCS11PubAttrs", "buffer", &b);

	BYTE perms[6];

	perms[0] = 0xff;
	perms[1] = 0xff;
	perms[2] = 0x40;
	perms[3] = 0x00;
	perms[4] = 0x40;
	perms[5] = 0x00;

    return CreateObject((BYTE*)id, perms, &b);
} /* CreatePKCS11PubKeyAttrs */

Buffer &Secure_Channel::GetKeyDiversificationData()
{
    return m_key_diversification_data;
} /* GetKeyDiversificationData */

Buffer &Secure_Channel::GetKeyInfoData()
{
    return m_key_info_data;
} /* GetKeyInfoData */

Buffer &Secure_Channel::GetCardChallenge()
{
    return m_card_challenge;
} /* GetCardChallenge */

Buffer &Secure_Channel::GetCardCryptogram()
{
    return m_card_cryptogram;
} /* GetCardCryptogram */

Buffer &Secure_Channel::GetHostChallenge()
{
    return m_host_challenge;
} /* GetCardCryptogram */

Buffer &Secure_Channel::GetHostCryptogram()
{
    return m_host_cryptogram;
} /* GetHostCryptogram */

SecurityLevel Secure_Channel::GetSecurityLevel()
{
    return m_security_level;
}

void Secure_Channel::SetSecurityLevel(SecurityLevel level)
{
    m_security_level = level;
}
