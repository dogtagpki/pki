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

#include <string.h>
#include "prnetdb.h"
#include "prerror.h"
#include "prio.h"
#include "plstr.h"
#include "main/NameValueSet.h"
#include "main/Util.h"
#include "RA_Conn.h"
#include "apdu/APDU_Response.h"
#include "apdu/List_Objects_APDU.h"
#include "apdu/Create_Object_APDU.h"
#include "apdu/Generate_Key_APDU.h"
#include "apdu/Generate_Key_ECC_APDU.h"
#include "apdu/External_Authenticate_APDU.h"
#include "apdu/Initialize_Update_APDU.h"
#include "apdu/Lifecycle_APDU.h"
#include "apdu/Set_Pin_APDU.h"
#include "apdu/Get_Status_APDU.h"
#include "apdu/Get_Data_APDU.h"
#include "apdu/Format_Muscle_Applet_APDU.h"
#include "apdu/Load_File_APDU.h"
#include "apdu/Get_IssuerInfo_APDU.h"
#include "apdu/Set_IssuerInfo_APDU.h"
#include "apdu/Install_Applet_APDU.h"
#include "apdu/Install_Load_APDU.h"
#include "apdu/Import_Key_APDU.h"
#include "apdu/Import_Key_Enc_APDU.h"
#include "apdu/Install_Load_APDU.h"
#include "apdu/Create_Pin_APDU.h"
#include "apdu/Read_Buffer_APDU.h"
#include "apdu/List_Pins_APDU.h"
#include "apdu/Write_Object_APDU.h"
#include "apdu/Delete_File_APDU.h"
#include "apdu/Unblock_Pin_APDU.h"
#include "apdu/Select_APDU.h"
#include "apdu/Get_Version_APDU.h"
#include "apdu/Put_Key_APDU.h"
#include "msg/RA_Begin_Op_Msg.h"
#include "msg/RA_End_Op_Msg.h"
#include "msg/RA_Extended_Login_Request_Msg.h"
#include "msg/RA_Login_Request_Msg.h"
#include "msg/RA_SecureId_Request_Msg.h"
#include "msg/RA_ASQ_Request_Msg.h"
#include "msg/RA_New_Pin_Request_Msg.h"
#include "msg/RA_Status_Update_Request_Msg.h"
#include "msg/RA_Status_Update_Response_Msg.h"
#include "msg/RA_Token_PDU_Request_Msg.h"
#include "msg/RA_Login_Response_Msg.h"
#include "msg/RA_Extended_Login_Response_Msg.h"
#include "msg/RA_SecureId_Response_Msg.h"
#include "msg/RA_ASQ_Response_Msg.h"
#include "msg/RA_New_Pin_Response_Msg.h"
#include "msg/RA_Token_PDU_Response_Msg.h"
#include "engine/RA.h"

/**
 * http parameters used in the protocol 
 */
#define PARAM_MSG_TYPE                "msg_type"
#define PARAM_OPERATION               "operation"
#define PARAM_EXTENSIONS              "extensions"
#define PARAM_INVALID_PW              "invalid_pw"
#define PARAM_BLOCKED                 "blocked"
#define PARAM_SCREEN_NAME             "screen_name"
#define PARAM_PASSWORD                "password"
#define PARAM_PIN_REQUIRED            "pin_required"
#define PARAM_NEXT_VALUE              "next_value"
#define PARAM_VALUE                   "value"
#define PARAM_PIN                     "pin"
#define PARAM_QUESTION                "question"
#define PARAM_ANSWER                  "answer"
#define PARAM_MINIMUM_LENGTH          "minimum_length"
#define PARAM_MAXIMUM_LENGTH          "maximum_length"
#define PARAM_NEW_PIN                 "new_pin"
#define PARAM_PDU_SIZE                "pdu_size"
#define PARAM_PDU_DATA                "pdu_data"
#define PARAM_RESULT                  "result"
#define PARAM_MESSAGE                 "message"
#define PARAM_CURRENT_STATE           "current_state"
#define PARAM_NEXT_TASK_NAME          "next_task_name"

#define MAX_RA_MSG_SIZE               4096

/**
 * Constructs a RA connection.
 */
RA_Conn::RA_Conn (char *host, int port, char *uri)
{
  if (host == NULL)
    m_host = NULL;
  else
    m_host = PL_strdup (host);
  if (uri == NULL)
    m_uri = NULL;
  else
    m_uri = PL_strdup (uri);
  m_port = port;
  m_read_header = 0;
  m_fd = NULL;
}

/**
 * Destructs a RA connection.
 */
RA_Conn::~RA_Conn ()
{
  if (m_host != NULL)
    {
      PL_strfree (m_host);
      m_host = NULL;
    }
  if (m_uri != NULL)
    {
      PL_strfree (m_uri);
      m_uri = NULL;
    }
  if (m_fd != NULL)
    {
      PR_Close (m_fd);
      m_fd = NULL;
    }
}

static void
Output (const char *fmt, ...)
{
  va_list ap;
  va_start (ap, fmt);
  printf ("Output> ");
  vprintf (fmt, ap);
  printf ("\n");
  va_end (ap);
}


#ifdef VERBOSE
static void
printBuf (Buffer * buf)
{
  int sum = 0;

  BYTE *data = *buf;
  int i = 0;
  if (buf->size () > 255)
    {
      Output ("printBuf: TOO BIG to print");
      return;
    }
  Output ("Begin printing buffer =====");
  for (i = 0; i < (int) buf->size (); i++)
    {
      printf ("%02x ", (unsigned char) data[i]);
      sum++;
      if (sum == 10)
	{
	  printf ("\n");
	  sum = 0;
	}
    }
  Output ("End printing buffer =====");
}
#endif


static PRUint32
GetIPAddress (const char *hostName)
{
  const unsigned char *p;
  char buf[PR_NETDB_BUF_SIZE];
  PRStatus prStatus;
  PRUint32 rv = 0;
  PRHostEnt prHostEnt;

  prStatus = PR_GetHostByName (hostName, buf, sizeof buf, &prHostEnt);
  if (prStatus != PR_SUCCESS)
    return rv;

#undef  h_addr
#define h_addr  h_addr_list[0]	/* address, for backward compatibility */

  p = (const unsigned char *) (prHostEnt.h_addr);	/* in Network Byte order */
  rv = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
  return rv;
}

/**
 * Connects to the RA.
 */
int
RA_Conn::Connect ()
{
  PRStatus rc;
  char header[4096];

  sprintf (header, "POST %s HTTP/1.1\r\n"
	   "Host: %s:%d\r\n"
	   "Transfer-Encoding: chunked\r\n" "\r\n", m_uri, m_host, m_port);

  m_fd = PR_NewTCPSocket ();

  /*
   *  Rifle through the values for the host
   */

  PRAddrInfo *ai;
  void *iter;
  PRNetAddr addr;
  int family = PR_AF_INET;

  ai = PR_GetAddrInfoByName(m_host, PR_AF_UNSPEC, PR_AI_ADDRCONFIG);
  if (ai) {
      iter = NULL;
      while ((iter = PR_EnumerateAddrInfo(iter, ai, 0, &addr)) != NULL) {
          family = PR_NetAddrFamily(&addr);
          break;
      }
      PR_FreeAddrInfo(ai);
  }

  PR_SetNetAddr( PR_IpAddrNull, family, m_port, &addr );

  m_fd = PR_OpenTCPSocket( family );
  if( !m_fd ) {
      return 0;
  }

  rc = PR_Connect (m_fd, &addr, PR_INTERVAL_NO_TIMEOUT /* timeout */ );
  if (rc != PR_SUCCESS)
    return 0;

  /* Send header */

  PR_Send (m_fd, header, strlen (header), 0, 1000000);

  return 1;
}

static void
CreateChunkEntity (char *msg, char *chunk, int chunk_len)
{
  int chunk_size;
  int len;
  Output ("***** msg = %s  *****", msg);
  len = strlen (msg);
  sprintf (chunk, "s=%d&%s", len, msg);
  chunk_size = strlen (chunk);
  sprintf (chunk, "%x\r\ns=%d&%s\r\n", chunk_size, len, msg);
}

/**
 * Sends message to the RA.
 */
int
RA_Conn::SendMsg (RA_Msg * msg)
{
  char msgbuf[MAX_RA_MSG_SIZE];
  char chunk[MAX_RA_MSG_SIZE];

  /* send chunk size */
  if (msg->GetType () == MSG_BEGIN_OP)
    {
      RA_Begin_Op_Msg *begin = (RA_Begin_Op_Msg *) msg;
      sprintf (msgbuf, "%s=%d&%s=%d", PARAM_MSG_TYPE, MSG_BEGIN_OP,
	       PARAM_OPERATION, begin->GetOpType ());
      NameValueSet *exts = begin->GetExtensions ();
      if (exts != NULL)
	{
	  sprintf (msgbuf, "%s&%s=", msgbuf, PARAM_EXTENSIONS);
	  for (int i = 0; i < exts->Size (); i++)
	    {
	      if (i != 0)
		{
		  sprintf (msgbuf, "%s%%26", msgbuf);
		}
	      char *name = exts->GetNameAt (i);
	      sprintf (msgbuf, "%s%s=%s",
		       msgbuf, name, exts->GetValueAsString (name));
	    }
	}
      CreateChunkEntity (msgbuf, chunk, 4096);
    }
  else if (msg->GetType () == MSG_LOGIN_RESPONSE)
    {
      RA_Login_Response_Msg *resp = (RA_Login_Response_Msg *) msg;
      sprintf (msgbuf, "%s=%d&%s=%s&%s=%s",
	       PARAM_MSG_TYPE, MSG_LOGIN_RESPONSE,
	       PARAM_SCREEN_NAME, resp->GetUID (),
	       PARAM_PASSWORD, resp->GetPassword ());
      CreateChunkEntity (msgbuf, chunk, 4096);
    }
  else if (msg->GetType () == MSG_EXTENDED_LOGIN_RESPONSE)
    {
      RA_Extended_Login_Response_Msg *resp =
	(RA_Extended_Login_Response_Msg *) msg;
      AuthParams *auth = resp->GetAuthParams ();
      sprintf (msgbuf, "%s=%d&%s=%s&%s=%s",
	       PARAM_MSG_TYPE, MSG_EXTENDED_LOGIN_RESPONSE,
	       PARAM_SCREEN_NAME, auth->GetUID (),
	       PARAM_PASSWORD, auth->GetPassword ());
      CreateChunkEntity (msgbuf, chunk, 4096);
    }
  else if (msg->GetType () == MSG_STATUS_UPDATE_RESPONSE)
    {
      RA_Status_Update_Response_Msg *resp =
	(RA_Status_Update_Response_Msg *) msg;
      int status = resp->GetStatus ();
      sprintf (msgbuf, "%s=%d&%s=%d",
	       PARAM_MSG_TYPE, MSG_STATUS_UPDATE_RESPONSE,
	       PARAM_CURRENT_STATE, status);
      CreateChunkEntity (msgbuf, chunk, 4096);
    }
  else if (msg->GetType () == MSG_SECUREID_RESPONSE)
    {
      RA_SecureId_Response_Msg *resp = (RA_SecureId_Response_Msg *) msg;
      char *value = resp->GetValue ();
      char *pin = resp->GetPIN ();
      if (pin == NULL)
	{
	  pin = (char *) "";
	}
      sprintf (msgbuf, "%s=%d&%s=%s&%s=%s",
	       PARAM_MSG_TYPE, MSG_SECUREID_RESPONSE,
	       PARAM_VALUE, value, PARAM_PIN, pin);
      CreateChunkEntity (msgbuf, chunk, 4096);
    }
  else if (msg->GetType () == MSG_ASQ_RESPONSE)
    {
      RA_ASQ_Response_Msg *resp = (RA_ASQ_Response_Msg *) msg;
      sprintf (msgbuf, "%s=%d&%s=%s",
	       PARAM_MSG_TYPE, MSG_ASQ_RESPONSE,
	       PARAM_ANSWER, resp->GetAnswer ());
      CreateChunkEntity (msgbuf, chunk, 4096);
    }
  else if (msg->GetType () == MSG_NEW_PIN_RESPONSE)
    {
      RA_New_Pin_Response_Msg *resp = (RA_New_Pin_Response_Msg *) msg;
      sprintf (msgbuf, "%s=%d&%s=%s",
	       PARAM_MSG_TYPE, MSG_NEW_PIN_RESPONSE,
	       PARAM_NEW_PIN, resp->GetNewPIN ());
      CreateChunkEntity (msgbuf, chunk, 4096);
    }
  else if (msg->GetType () == MSG_TOKEN_PDU_RESPONSE)
    {
      RA_Token_PDU_Response_Msg *resp = (RA_Token_PDU_Response_Msg *) msg;
      APDU_Response *apdu_resp = resp->GetResponse ();
      Buffer pdu = apdu_resp->GetData ();
      char *pdu_encoded = Util::URLEncode (pdu);
      sprintf (msgbuf, "%s=%d&%s=%s&%s=%d",
	       PARAM_MSG_TYPE, MSG_TOKEN_PDU_RESPONSE,
	       PARAM_PDU_DATA, pdu_encoded, PARAM_PDU_SIZE, pdu.size ());
      if (pdu_encoded != NULL)
	{
	  PR_Free (pdu_encoded);
	  pdu_encoded = NULL;
	}
      CreateChunkEntity (msgbuf, chunk, 4096);
    }
  else
    {
      /* error */
    }

  /* send chunk */
  Output ("sending chunk -----  %s -----", chunk);
  PR_Send (m_fd, chunk, strlen (chunk), 0, 1000000);

  return 1;
}

static int
ReadResponseHeader (PRFileDesc * fd)
{
  char buf[1024];
  PRInt32 rc;
  char *cur = buf;
  int i;

  for (i = 0; i < 1024; i++)
    {
      buf[i] = 0;
    }
  while (1)
    {
      rc = PR_Recv (fd, cur, 1, 0, 1000000);
      if (buf[0] == '\r' &&
	  buf[1] == '\n' && buf[2] == '\r' && buf[3] == '\n')
	{
	  break;
	}
      if (*cur == '\r')
	{
	  cur++;
	}
      else if (*cur == '\n')
	{
	  cur++;
	}
      else
	{
	  cur = buf;
	}
    }
  return 1;
}

static int
GetChunkSize (PRFileDesc * fd)
{
  char buf[1024];
  char *cur = buf;
  PRInt32 rc;
  int i;
  int ret;

  for (i = 0; i < 1024; i++)
    {
      buf[i] = 0;
    }
  while (1)
    {
      rc = PR_Recv (fd, cur, 1, 0, 1000000);
      if (rc <= 0)
	{
	  return 0;
	}
      if (*cur == '\r')
	{
	  *cur = '\0';
	  /* read \n */
	  rc = PR_Recv (fd, cur, 1, 0, 1000000);
	  if (rc <= 0)
	    {
	      return 0;
	    }
	  *cur = '\0';
	  break;
	}
      cur++;
    }
  sscanf (buf, "%x", (unsigned int *) (&ret));
  return ret;
}

static int
GetChunk (PRFileDesc * fd, char *buf, int buflen)
{
  int rc = 0;
  int sum = 0;
  char *cur = buf;

  while (1)
    {
      rc = PR_Recv (fd, cur, buflen - sum, 0, 1000000);
      if (rc <= 0)
	{
	  return -1;
	}
      sum += rc;
      cur += rc;
      cur[sum] = '\0';
      if (sum == buflen)
	return sum;
    }
}

bool
RA_Conn::isEncrypted ()
{
  return m_encrypted_channel;
}

void
RA_Conn::setEncryption (bool encrypted)
{
  Output ("RA_Conn::setEncryption: setting encrypted channel: %d", encrypted);
  m_encrypted_channel = encrypted;
}

APDU *
RA_Conn::CreateAPDU (RA_Token * tok, Buffer & in_apdu_data, Buffer & mac)
{
  APDU *apdu = NULL;
  Buffer apdu_data;

  if (isEncrypted () && (((BYTE *) in_apdu_data)[0] == 0x84))
    {
      tok->decryptMsg (in_apdu_data, apdu_data);
    }
  else
    {
      apdu_data = in_apdu_data;
    }

  if (((BYTE *) apdu_data)[1] == 0x5a)
    {
      /* Create_Object_APDU */
      mac = Buffer (apdu_data.substr (apdu_data.size () - 8, 8));
      BYTE object_id[4];
      object_id[0] = ((BYTE *) apdu_data)[5];
      object_id[1] = ((BYTE *) apdu_data)[6];
      object_id[2] = ((BYTE *) apdu_data)[7];
      object_id[3] = ((BYTE *) apdu_data)[8];
      BYTE permissions[6];
      permissions[0] = ((BYTE *) apdu_data)[13];
      permissions[1] = ((BYTE *) apdu_data)[14];
      permissions[2] = ((BYTE *) apdu_data)[15];
      permissions[3] = ((BYTE *) apdu_data)[16];
      permissions[4] = ((BYTE *) apdu_data)[17];
      permissions[5] = ((BYTE *) apdu_data)[18];
      int len =
	(((BYTE *) apdu_data)[9] << 24) + (((BYTE *) apdu_data)[10] << 16) +
	(((BYTE *) apdu_data)[11] << 8) + ((BYTE *) apdu_data)[12];
      apdu = new Create_Object_APDU (object_id, permissions, len);
      apdu->SetMAC (mac);
    }
  else if (((BYTE *) apdu_data)[1] == 0x82)
    {
      /* External_Authenticate_APDU */
      BYTE encryption = ((BYTE *) apdu_data)[2];	// P1 is sec level
      if (encryption == (BYTE) 0x03)
	{
	  setEncryption (true);
	}
      else
	{
	  Output ("RA_Conn::CreateAPDU(): not encrypted");
	}

      // mac is last 8 bytes
      mac = Buffer (apdu_data.substr (apdu_data.size () - 8, 8));
      Buffer *data = new Buffer (apdu_data.substr (5, 8));

      if (isEncrypted () == true)
	{
	  apdu = new External_Authenticate_APDU (*data, SECURE_MSG_MAC_ENC);
	}
      else
	{
	  apdu = new External_Authenticate_APDU (*data, SECURE_MSG_ANY);
	}
      if (data != NULL)
	{
	  delete data;
	  data = NULL;
	}
      apdu->SetMAC (mac);
    }
  else if (((BYTE *) apdu_data)[1] == 0x0A)
    {
      /* ImportKeyEnc APDU */
      mac = Buffer (apdu_data.substr (apdu_data.size () - 8, 8));
      BYTE p[2];
      p[0] = ((BYTE *) apdu_data)[2];	/* p1 */
      p[1] = ((BYTE *) apdu_data)[3];	/* p2 */
      Buffer *data =
	new Buffer (apdu_data.substr (5, apdu_data.size () - 8 - 5));
      Buffer a;
      apdu = new Import_Key_Enc_APDU ((BYTE) p[0], (BYTE) p[1], *data);
      apdu->SetMAC (mac);
      if (data != NULL)
	{
	  delete data;
	  data = NULL;
	}

    }
  else if ((((BYTE *) apdu_data)[1] == 0x0C) || (((BYTE *) apdu_data)[1] == 0x0D)) // for both RSA (0x0C) and ECC (0x0D)
    {
      /* Generate_Key_APDU */
      BYTE p[2];
      p[0] = ((BYTE *) apdu_data)[2];	/* p1 */
      p[1] = ((BYTE *) apdu_data)[3];	/* p2 */
      mac = Buffer (apdu_data.substr (apdu_data.size () - 8, 8));
      BYTE alg = ((BYTE *) apdu_data)[5];
      int keysize = (((BYTE *) apdu_data)[6] << 8) + ((BYTE *) apdu_data)[7];
      BYTE option = ((BYTE *) apdu_data)[8];
      BYTE type = ((BYTE *) apdu_data)[9];
      unsigned int wc_len = (unsigned int) ((BYTE *) apdu_data)[10];
      Buffer *wrapped_challenge = new Buffer ((BYTE *) &
					      ((BYTE *) apdu_data)[11],
					      wc_len);
      Buffer *key_check = new Buffer ((BYTE *) &
				      ((BYTE *) apdu_data)[11 + wc_len + 1],
				      (unsigned int) ((BYTE *) apdu_data)[11 +
									  wc_len]);
      if (((BYTE *) apdu_data)[1] == 0x0D) {
          apdu =
	          new Generate_Key_ECC_APDU (p[0], p[1], alg, keysize, option, type,
			       *wrapped_challenge, *key_check);
      } else {
          apdu =
          	  new Generate_Key_APDU (p[0], p[1], alg, keysize, option, type,
			       *wrapped_challenge, *key_check);
      }

      if (wrapped_challenge != NULL)
	{
	  delete wrapped_challenge;
	  wrapped_challenge = NULL;
	}
      if (key_check != NULL)
	{
	  delete key_check;
	  key_check = NULL;
	}
      apdu->SetMAC (mac);
    }
  else if (((BYTE *) apdu_data)[1] == 0x50)
    {
      /* Initialize_Update_APDU */

      setEncryption (false);
      BYTE p[2];
      p[0] = ((BYTE *) apdu_data)[2];	/* p1 */
      p[1] = ((BYTE *) apdu_data)[3];	/* p2 */
      Buffer *data = new Buffer (apdu_data.substr (5, 8));
      apdu = new Initialize_Update_APDU (p[0], p[1], *data);
      if (data != NULL)
	{
	  delete data;
	  data = NULL;
	}
    }
  else if (((BYTE *) apdu_data)[1] == 0x56)
    {				/* Read Objects */
      BYTE p[4];
      int offset = 0;
      int size = 0;
      p[0] = ((BYTE *) apdu_data)[5];
      p[1] = ((BYTE *) apdu_data)[6];
      p[2] = ((BYTE *) apdu_data)[7];
      p[3] = ((BYTE *) apdu_data)[8];
      offset = (((BYTE *) apdu_data)[9] << 24) +
	(((BYTE *) apdu_data)[10] << 16) +
	(((BYTE *) apdu_data)[11] << 8) + ((BYTE *) apdu_data)[12];
      size = ((BYTE *) apdu_data)[13];	/* p2 */
      apdu = new Read_Object_APDU (p, offset, size);
      mac = Buffer (apdu_data.substr (apdu_data.size () - 8, 8));
      apdu->SetMAC (mac);
    }
  else if (((BYTE *) apdu_data)[1] == 0x58)
    {				/* List Objects */
      apdu = new List_Objects_APDU (((BYTE *) apdu_data)[2]);
    }
  else if (((BYTE *) apdu_data)[1] == 0xf0)
    {
      /* Lifecycle_APDU */
      mac = Buffer (apdu_data.substr (apdu_data.size () - 8, 8));
      apdu = new Lifecycle_APDU (((BYTE *) apdu_data)[2]);
      apdu->SetMAC (mac);
    }
  else if (((BYTE *) apdu_data)[1] == 0x08)
    {
      /* Read_BufferAPDU */
      mac = Buffer (apdu_data.substr (apdu_data.size () - 8, 8));
      int len = ((BYTE *) apdu_data)[2];
      int offset = (((BYTE *) apdu_data)[5] << 8) + ((BYTE *) apdu_data)[6];
      apdu = new Read_Buffer_APDU (len, offset);
      apdu->SetMAC (mac);
    }
  else if (((BYTE *) apdu_data)[1] == 0x04)
    {
      /* Set_Pin_APDU */
      BYTE p[2];
      p[0] = ((BYTE *) apdu_data)[2];	/* p1 */
      p[1] = ((BYTE *) apdu_data)[3];	/* p2 */
      mac = Buffer (apdu_data.substr (apdu_data.size () - 8, 8));
      Buffer *data =
	new Buffer (apdu_data.substr (5, apdu_data.size () - 8 - 5));
      apdu = new Set_Pin_APDU (p[0], p[1], *data);
      if (data != NULL)
	{
	  delete data;
	  data = NULL;
	}
      apdu->SetMAC (mac);
    }
  else if (((BYTE *) apdu_data)[1] == 0x2a)
    {
      Buffer dummy;
      apdu = new Format_Muscle_Applet_APDU (0,
					    dummy, 0,
					    dummy, 0,
					    dummy, 0, dummy, 0, 0, 0, 0);
    }
  else if (((BYTE *) apdu_data)[1] == 0xe6)
    {
      BYTE p1 = ((BYTE *) apdu_data)[2];	/* p1 */
      mac = Buffer (apdu_data.substr (apdu_data.size () - 8, 8));
/* Why was it ignored?
	 	Buffer dummy;		
		if (p1 == 0x02) {
		    apdu = new Install_Load_APDU(dummy, dummy, 0);
		} else {
		    apdu = new Install_Applet_APDU(dummy, dummy, 0,0);
		}
*/
      Buffer *data =
	new Buffer (apdu_data.substr (5, apdu_data.size () - 8 - 5));
      if (p1 == 0x02)
	{
	  apdu = new Install_Load_APDU (*data);
	}
      else
	{
	  apdu = new Install_Applet_APDU (*data);
	}
      apdu->SetMAC (mac);
      if (data != NULL)
	{
	  delete data;
	  data = NULL;
	}
    }
  else if (((BYTE *) apdu_data)[1] == 0xe8)
    {
      BYTE p[2];
      p[0] = ((BYTE *) apdu_data)[2];	/* p1 */
      p[1] = ((BYTE *) apdu_data)[3];	/* p2 */
      mac = Buffer (apdu_data.substr (apdu_data.size () - 8, 8));
      Buffer *data =
	new Buffer (apdu_data.substr (5, apdu_data.size () - 8 - 5));
      apdu = new Load_File_APDU (p[0], p[1], *data);
      if (data != NULL)
	{
	  delete data;
	  data = NULL;
	}
      apdu->SetMAC (mac);
    }
  else if (((BYTE *) apdu_data)[1] == 0xe4)
    {
      mac = Buffer (apdu_data.substr (apdu_data.size () - 8, 8));
      // Delete File apdu has two extra bytes after header
      // remove before proceed
      Buffer *data =
	new Buffer (apdu_data.substr (7, apdu_data.size () - 8 - 5 - 2));
      apdu = new Delete_File_APDU (*data);
      if (data != NULL)
	{
	  delete data;
	  data = NULL;
	}
      apdu->SetMAC (mac);
    }
  else if (((BYTE *) apdu_data)[1] == 0x02)
    {
      /* Unblock_Pin_APDU */
      mac = Buffer (apdu_data.substr (apdu_data.size () - 8, 8));
      apdu = new Unblock_Pin_APDU ();
      apdu->SetMAC (mac);
    }
  else if (((BYTE *) apdu_data)[1] == 0xa4)
    {				/* Select */
      BYTE p[2];
      p[0] = ((BYTE *) apdu_data)[2];	/* p1 */
      p[1] = ((BYTE *) apdu_data)[3];	/* p2 */
      Buffer *data = NULL;
      if (apdu_data.size () == 5)
	{
	  data = new Buffer ();
	}
      else
	{
	  data = new Buffer (apdu_data.substr (5, apdu_data.size () - 5));
	}
      apdu = new Select_APDU (p[0], p[1], *data);
      if (data != NULL)
	{
	  delete data;
	  data = NULL;
	}
    }
  else if (((BYTE *) apdu_data)[1] == 0x3C)
    {				/* Get Status */
      apdu = new Get_Status_APDU ();
    }
  else if (((BYTE *) apdu_data)[1] == 0x70)
    {				/* Get Version */
      apdu = new Get_Version_APDU ();
    }
  else if (((BYTE *) apdu_data)[1] == 0x48)
    {
      apdu = new List_Pins_APDU (0x02);
    }
  else if (((BYTE *) apdu_data)[1] == 0x40)
    {				/* Put Key */
      BYTE p[2];
      p[0] = ((BYTE *) apdu_data)[2];	/* p1 */
      p[1] = ((BYTE *) apdu_data)[3];	/* p2 */
      mac = Buffer (apdu_data.substr (apdu_data.size () - 8, 8));
      Buffer *data =
	new Buffer (apdu_data.substr (5, apdu_data.size () - 8 - 5));
      apdu = new Create_Pin_APDU (p[0], p[1], *data);
      apdu->SetMAC (mac);
      if (data != NULL)
	{
	  delete data;
	  data = NULL;
	}
    }
  else if (((BYTE *) apdu_data)[1] == 0xca)
    {				/* Get Data */
      apdu = new Get_Data_APDU ();
    }
  else if (((BYTE *) apdu_data)[1] == 0xf6)
    {				/* Get_IssuerInfo */
      apdu = new Get_IssuerInfo_APDU ();
    }
  else if (((BYTE *) apdu_data)[1] == 0xf4)
    {				/* Set_IssuerInfo */
      BYTE p[2];
      p[0] = ((BYTE *) apdu_data)[2];	/* p1 */
      p[1] = ((BYTE *) apdu_data)[3];	/* p2 */
      mac = Buffer (apdu_data.substr (apdu_data.size () - 8, 8));
      Buffer *data =
	new Buffer (apdu_data.substr (5, apdu_data.size () - 8 - 5));
      apdu = new Set_IssuerInfo_APDU (p[0], p[1], *data);
      apdu->SetMAC (mac);
      if (data != NULL)
	{
	  delete data;
	  data = NULL;
	}
    }
  else if (((BYTE *) apdu_data)[1] == 0xd8)
    {				/* Put Key */
      BYTE p[2];
      p[0] = ((BYTE *) apdu_data)[2];	/* p1 */
      p[1] = ((BYTE *) apdu_data)[3];	/* p2 */
      mac = Buffer (apdu_data.substr (apdu_data.size () - 8, 8));
      Buffer *data =
	new Buffer (apdu_data.substr (5, apdu_data.size () - 8 - 5));
      apdu = new Put_Key_APDU (p[0], p[1], *data);
      apdu->SetMAC (mac);
      if (data != NULL)
	{
	  delete data;
	  data = NULL;
	}
    }
  else if (((BYTE *) apdu_data)[1] == 0x54)
    {
      /* Write_Object_APDU */
      BYTE object_id[4];
      object_id[0] = ((BYTE *) apdu_data)[5];
      object_id[1] = ((BYTE *) apdu_data)[6];
      object_id[2] = ((BYTE *) apdu_data)[7];
      object_id[3] = ((BYTE *) apdu_data)[8];
      mac = Buffer (apdu_data.substr (apdu_data.size () - 8, 8));
      int offset =
	(((BYTE *) apdu_data)[9] << 24) + (((BYTE *) apdu_data)[10] << 16) +
	(((BYTE *) apdu_data)[11] << 8) + ((BYTE *) apdu_data)[12];
      Buffer *data =
	new Buffer (apdu_data.substr (14, apdu_data.size () - 8 - 11 - 3));
      apdu = new Write_Object_APDU (object_id, offset, *data);
      apdu->SetMAC (mac);
      if (data != NULL)
	{
	  delete data;
	  data = NULL;
	}
    }
  else
    {
      /* error */
    }
  return apdu;
}

/**
 * Retrieves message from the RA.
 */
RA_Msg *
RA_Conn::ReadMsg (RA_Token * token)
{
  int len = 0;
  char buf[4096];
  PRInt32 rc;
  int i;
  char *msg_type_s = NULL;
  int msg_type;
  RA_Msg *msg = NULL;

  if (!m_read_header)
    {
      ReadResponseHeader (m_fd);
      m_read_header = 1;
    }

  /* read chunk size */
  len = GetChunkSize (m_fd);
  if (len <= 0)
    {
      return NULL;
    }

  for (i = 0; i < 4096; i++)
    {
      buf[i] = 0;
    }

  /* read chunk */
  rc = GetChunk (m_fd, buf, len + 2);
  if (rc <= 0)
    {
      return NULL;
    }
  buf[len] = '\0';

  /* parse name value pair */
  NameValueSet *params = NameValueSet::Parse (buf, "&");
  if (params == NULL)
    return NULL;
  msg_type_s = params->GetValue (PARAM_MSG_TYPE);
  if (msg_type_s == NULL)
    {
      if (params != NULL)
	{
	  delete params;
	  params = NULL;
	}
      return NULL;
    }
  msg_type = atoi (msg_type_s);

  if (msg_type == MSG_LOGIN_REQUEST)
    {
      msg =
	new RA_Login_Request_Msg (atoi (params->GetValue (PARAM_INVALID_PW)),
				  atoi (params->GetValue (PARAM_BLOCKED)));
    }
  else if (msg_type == MSG_EXTENDED_LOGIN_REQUEST)
    {
      msg = new RA_Extended_Login_Request_Msg (0, 0, NULL, 0, NULL, NULL);
    }
  else if (msg_type == MSG_END_OP)
    {
      msg = new RA_End_Op_Msg ((RA_Op_Type)
			       atoi (params->GetValue (PARAM_OPERATION)),
			       atoi (params->GetValue (PARAM_RESULT)),
			       atoi (params->GetValue (PARAM_MESSAGE)));
    }
  else if (msg_type == MSG_SECUREID_REQUEST)
    {
      msg =
	new
	RA_SecureId_Request_Msg (atoi (params->GetValue (PARAM_PIN_REQUIRED)),
				 atoi (params->GetValue (PARAM_NEXT_VALUE)));
    }
  else if (msg_type == MSG_STATUS_UPDATE_REQUEST)
    {
      msg =
	new
	RA_Status_Update_Request_Msg (atoi
				      (params->
				       GetValue (PARAM_CURRENT_STATE)),
				      params->
				      GetValue (PARAM_NEXT_TASK_NAME));
    }
  else if (msg_type == MSG_ASQ_REQUEST)
    {
      msg = new RA_ASQ_Request_Msg (params->GetValue (PARAM_QUESTION));
    }
  else if (msg_type == MSG_NEW_PIN_REQUEST)
    {
      msg =
	new
	RA_New_Pin_Request_Msg (atoi
				(params->GetValue (PARAM_MINIMUM_LENGTH)),
				atoi (params->
				      GetValue (PARAM_MAXIMUM_LENGTH)));
    }
  else if (msg_type == MSG_TOKEN_PDU_REQUEST)
    {
      char *pdu_encoded = params->GetValue (PARAM_PDU_DATA);
      Buffer *apdu_data = Util::URLDecode (pdu_encoded);

#ifdef VERBOSE
      Output ("ReadMsg: URLDecoded apdu = ");
      printBuf (apdu_data);
#endif

      Buffer mac;
      APDU *apdu = CreateAPDU (token, *apdu_data, mac);
      msg = new RA_Token_PDU_Request_Msg (apdu);
      if (apdu_data != NULL)
	{
	  delete apdu_data;
	  apdu_data = NULL;
	}
    }
  else
    {
      /* error */
      if (params != NULL)
	{
	  delete params;
	  params = NULL;
	}
      return NULL;
    }

  if (params != NULL)
    {
      delete params;
      params = NULL;
    }

  return msg;
}

/**
 * Terminates this connection.
 */
int
RA_Conn::Close ()
{
  if (m_fd != NULL)
    {
      PR_Close (m_fd);
      m_fd = NULL;
    }
  return 1;
}
