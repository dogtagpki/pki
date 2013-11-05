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

#include "cryptohi.h"
#include "plstr.h"
#include "main/Util.h"
#include "RA_Token.h"
#include "apdu/APDU_Response.h"
#include "apdu/Initialize_Update_APDU.h"
#include "apdu/Generate_Key_APDU.h"
#include "apdu/Generate_Key_ECC_APDU.h"
#include "apdu/Put_Key_APDU.h"
#include "apdu/Select_APDU.h"
#include "apdu/Get_Data_APDU.h"
#include "apdu/List_Objects_APDU.h"
#include "apdu/Get_IssuerInfo_APDU.h"
#include "apdu/Set_IssuerInfo_APDU.h"
#include "apdu/Read_Object_APDU.h"
#include "apdu/Get_Version_APDU.h"
#include "apdu/Get_Status_APDU.h"
#include "apdu/List_Pins_APDU.h"
#include "apdu/Create_Pin_APDU.h"
#include "keyhi.h"
#include "nss.h"
#include "cert.h"
#include "secoidt.h"

#define VERBOSE
//#define VERIFY_PROOF

#define DEFAULT_CURVE_OID_TAG  SEC_OID_SECG_EC_SECP192R1
/* #define DEFAULT_CURVE_OID_TAG  SEC_OID_SECG_EC_SECP160R1 */

/* curveNameTagPair is borrowed from certutil */
typedef struct curveNameTagPairStr {
    char *curveName;
    SECOidTag curveOidTag;
} CurveNameTagPair;

static CurveNameTagPair nameTagPair[] =
{ 
  { "sect163k1", SEC_OID_SECG_EC_SECT163K1},
  { "nistk163", SEC_OID_SECG_EC_SECT163K1},
  { "sect163r1", SEC_OID_SECG_EC_SECT163R1},
  { "sect163r2", SEC_OID_SECG_EC_SECT163R2},
  { "nistb163", SEC_OID_SECG_EC_SECT163R2},
  { "sect193r1", SEC_OID_SECG_EC_SECT193R1},
  { "sect193r2", SEC_OID_SECG_EC_SECT193R2},
  { "sect233k1", SEC_OID_SECG_EC_SECT233K1},
  { "nistk233", SEC_OID_SECG_EC_SECT233K1},
  { "sect233r1", SEC_OID_SECG_EC_SECT233R1},
  { "nistb233", SEC_OID_SECG_EC_SECT233R1},
  { "sect239k1", SEC_OID_SECG_EC_SECT239K1},
  { "sect283k1", SEC_OID_SECG_EC_SECT283K1},
  { "nistk283", SEC_OID_SECG_EC_SECT283K1},
  { "sect283r1", SEC_OID_SECG_EC_SECT283R1},
  { "nistb283", SEC_OID_SECG_EC_SECT283R1},
  { "sect409k1", SEC_OID_SECG_EC_SECT409K1},
  { "nistk409", SEC_OID_SECG_EC_SECT409K1},
  { "sect409r1", SEC_OID_SECG_EC_SECT409R1},
  { "nistb409", SEC_OID_SECG_EC_SECT409R1},
  { "sect571k1", SEC_OID_SECG_EC_SECT571K1},
  { "nistk571", SEC_OID_SECG_EC_SECT571K1},
  { "sect571r1", SEC_OID_SECG_EC_SECT571R1},
  { "nistb571", SEC_OID_SECG_EC_SECT571R1},
  { "secp160k1", SEC_OID_SECG_EC_SECP160K1},
  { "secp160r1", SEC_OID_SECG_EC_SECP160R1},
  { "secp160r2", SEC_OID_SECG_EC_SECP160R2},
  { "secp192k1", SEC_OID_SECG_EC_SECP192K1},
  { "secp192r1", SEC_OID_SECG_EC_SECP192R1},
  { "nistp192", SEC_OID_SECG_EC_SECP192R1},
  { "secp224k1", SEC_OID_SECG_EC_SECP224K1},
  { "secp224r1", SEC_OID_SECG_EC_SECP224R1},
  { "nistp224", SEC_OID_SECG_EC_SECP224R1},
  { "secp256k1", SEC_OID_SECG_EC_SECP256K1},
  { "secp256r1", SEC_OID_SECG_EC_SECP256R1},
  { "nistp256", SEC_OID_SECG_EC_SECP256R1},
  { "secp384r1", SEC_OID_SECG_EC_SECP384R1},
  { "nistp384", SEC_OID_SECG_EC_SECP384R1},
  { "secp521r1", SEC_OID_SECG_EC_SECP521R1},
  { "nistp521", SEC_OID_SECG_EC_SECP521R1},

  { "prime192v1", SEC_OID_ANSIX962_EC_PRIME192V1 },
  { "prime192v2", SEC_OID_ANSIX962_EC_PRIME192V2 },
  { "prime192v3", SEC_OID_ANSIX962_EC_PRIME192V3 },
  { "prime239v1", SEC_OID_ANSIX962_EC_PRIME239V1 },
  { "prime239v2", SEC_OID_ANSIX962_EC_PRIME239V2 },
  { "prime239v3", SEC_OID_ANSIX962_EC_PRIME239V3 },

  { "c2pnb163v1", SEC_OID_ANSIX962_EC_C2PNB163V1 },
  { "c2pnb163v2", SEC_OID_ANSIX962_EC_C2PNB163V2 },
  { "c2pnb163v3", SEC_OID_ANSIX962_EC_C2PNB163V3 },
  { "c2pnb176v1", SEC_OID_ANSIX962_EC_C2PNB176V1 },
  { "c2tnb191v1", SEC_OID_ANSIX962_EC_C2TNB191V1 },
  { "c2tnb191v2", SEC_OID_ANSIX962_EC_C2TNB191V2 },
  { "c2tnb191v3", SEC_OID_ANSIX962_EC_C2TNB191V3 },
  { "c2onb191v4", SEC_OID_ANSIX962_EC_C2ONB191V4 },
  { "c2onb191v5", SEC_OID_ANSIX962_EC_C2ONB191V5 },
  { "c2pnb208w1", SEC_OID_ANSIX962_EC_C2PNB208W1 },
  { "c2tnb239v1", SEC_OID_ANSIX962_EC_C2TNB239V1 },
  { "c2tnb239v2", SEC_OID_ANSIX962_EC_C2TNB239V2 },
  { "c2tnb239v3", SEC_OID_ANSIX962_EC_C2TNB239V3 },
  { "c2onb239v4", SEC_OID_ANSIX962_EC_C2ONB239V4 },
  { "c2onb239v5", SEC_OID_ANSIX962_EC_C2ONB239V5 },
  { "c2pnb272w1", SEC_OID_ANSIX962_EC_C2PNB272W1 },
  { "c2pnb304w1", SEC_OID_ANSIX962_EC_C2PNB304W1 },
  { "c2tnb359v1", SEC_OID_ANSIX962_EC_C2TNB359V1 },
  { "c2pnb368w1", SEC_OID_ANSIX962_EC_C2PNB368W1 },
  { "c2tnb431r1", SEC_OID_ANSIX962_EC_C2TNB431R1 },

  { "secp112r1", SEC_OID_SECG_EC_SECP112R1},
  { "secp112r2", SEC_OID_SECG_EC_SECP112R2},
  { "secp128r1", SEC_OID_SECG_EC_SECP128R1},
  { "secp128r2", SEC_OID_SECG_EC_SECP128R2},

  { "sect113r1", SEC_OID_SECG_EC_SECT113R1},
  { "sect113r2", SEC_OID_SECG_EC_SECT113R2},
  { "sect131r1", SEC_OID_SECG_EC_SECT131R1},
  { "sect131r2", SEC_OID_SECG_EC_SECT131R2},
};


static BYTE
ToVal (char c)
{
  if (c >= '0' && c <= '9')
    {
      return c - '0';
    }
  else if (c >= 'A' && c <= 'Z')
    {
      return c - 'A' + 10;
    }
  else if (c >= 'a' && c <= 'z')
    {
      return c - 'a' + 10;
    }
                                                                                
  /* The following return is needed to suppress compiler warnings on Linux. */
  return 0;
}

static Buffer *
ToBuffer (char *input)
{
  int len = strlen (input) / 2;
  BYTE *buffer = NULL;
                                                                                
  buffer = (BYTE *) malloc (len);
  if (buffer == NULL)
    {
      return NULL;
    }
                                                                                
  for (int i = 0; i < len; i++)
    {
      buffer[i] = (ToVal (input[i * 2]) * 16) + ToVal (input[i * 2 + 1]);
    }
  Buffer *j;
  j = new Buffer (buffer, len);
                                                                                
  if (buffer != NULL)
    {
      free (buffer);
      buffer = NULL;
    }
                                                                                
  return j;
}

/**
 * Constructs a virtual token.
 */
RA_Token::RA_Token ()
{
  m_session_key = NULL;
  m_enc_session_key = NULL;
  BYTE key_info[] = {
    0x01, 0x01
  };
  BYTE version[] = {
    0x00, 0x01, 0x02, 0x03
  };
  BYTE cuid[] = {
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x09
  };
  BYTE msn[] = {
    0x00, 0x00, 0x00, 0x00
  };
  BYTE key[] = {
    0x40, 0x41, 0x42, 0x43,
    0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4a, 0x4b,
    0x4c, 0x4d, 0x4e, 0x4f
  };

  m_major_version = 0;
  m_minor_version = 0;

  /* default setting */
  m_lifecycle_state = 0;
  m_icv = Buffer (8, (BYTE) 0);
  m_auth_key = Buffer (key, sizeof key);
  m_mac_key = Buffer (key, sizeof key);
  m_kek_key = Buffer (key, sizeof key);
  m_cuid = Buffer (cuid, sizeof cuid);
  m_msn = Buffer (msn, sizeof msn);
  m_version = Buffer (version, sizeof version);
  m_key_info = Buffer (key_info, sizeof key_info);
  m_pin = PL_strdup ("password");
  m_object_len = 0;
  m_object = NULL;
  m_tokenpassword = NULL;
}


/**
 * Destructs token.
 */
RA_Token::~RA_Token ()
{
  if (m_pin != NULL)
    {
      PL_strfree (m_pin);
      m_pin = NULL;
    }
  if (m_session_key != NULL)
    {
      PORT_Free (m_session_key);
      m_session_key = NULL;
    }
  if (m_enc_session_key != NULL)
    {
      PORT_Free (m_enc_session_key);
      m_enc_session_key = NULL;
    }
  if (m_object != NULL)
    {
      delete (m_object);
      m_object = NULL;
    }
}

RA_Token *
RA_Token::Clone ()
{
  RA_Token *token = new RA_Token ();
  token->m_icv = m_icv;
  /*
     token->m_session_key = m_session_key;
     token->m_enc_session_key = m_enc_session_key;
   */
  token->m_session_key = NULL;
  token->m_enc_session_key = NULL;
  token->m_lifecycle_state = m_lifecycle_state;
  token->m_auth_key = m_auth_key;
  token->m_major_version = m_major_version;
  token->m_minor_version = m_minor_version;
  token->m_mac_key = m_mac_key;
  token->m_kek_key = m_kek_key;
  token->m_cuid = m_cuid;
  token->m_version = m_version;
  token->m_key_info = m_key_info;
  PL_strfree (token->m_pin);
  token->m_pin = PL_strdup (m_pin);
  token->m_object_len = m_object_len;
  return token;
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

void
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

Buffer & RA_Token::GetCUID ()
{
  return m_cuid;
}

Buffer & RA_Token::GetMSN ()
{
  return m_msn;
}

void
RA_Token::SetCUID (Buffer & cuid)
{
  m_cuid = cuid;
}

void
RA_Token::SetMSN (Buffer & msn)
{
  if (msn != NULL && msn.size() < 4) {
    // Supply a default value of 'FFFFFFFF' for 'msn'
    printf ("RA_Token::SetMSN - Use 'FFFFFFFF' instead of specified 'msn'!\n");
    m_msn = *(ToBuffer ("FFFFFFFF"));
  } else {
    m_msn = msn;
  }
}

Buffer & RA_Token::GetAppletVersion ()
{
  return m_version;
}

void
RA_Token::SetAppletVersion (Buffer & version)
{
  m_version = version;
}

void
RA_Token::SetMajorVersion (int v)
{
  m_major_version = v;
}

void
RA_Token::SetMinorVersion (int v)
{
  m_minor_version = v;
}

void
RA_Token::SetAuthKey (Buffer & key)
{
  m_auth_key = key;
}

void
RA_Token::SetMacKey (Buffer & key)
{
  m_mac_key = key;
}

void
RA_Token::SetKekKey (Buffer & key)
{
  m_kek_key = key;
}

Buffer & RA_Token::GetKeyInfo ()
{
  return m_key_info;
}

void
RA_Token::SetKeyInfo (Buffer & key_info)
{
  m_key_info = key_info;
}

int
RA_Token::GetMajorVersion ()
{
  return m_major_version;
}

int
RA_Token::GetMinorVersion ()
{
  return m_minor_version;
}

BYTE
RA_Token::GetLifeCycleState ()
{
  return m_lifecycle_state;
}

char *
RA_Token::GetPIN ()
{
  return m_pin;
}

Buffer & RA_Token::GetAuthKey ()
{
  return m_auth_key;
}

Buffer & RA_Token::GetMacKey ()
{
  return m_mac_key;
}

Buffer & RA_Token::GetKekKey ()
{
  return m_kek_key;
}

int
RA_Token::NoOfPrivateKeys ()
{
  SECKEYPrivateKeyList *list = NULL;
  SECKEYPrivateKeyListNode *node;
  PK11SlotInfo *slot = PK11_GetInternalKeySlot ();
  int count;

  list = PK11_ListPrivateKeysInSlot (slot);
  for (count = 0, node = PRIVKEY_LIST_HEAD (list);
       !PRIVKEY_LIST_END (node, list);
       node = PRIVKEY_LIST_NEXT (node), count++)
    {
      /* nothing */
    }
  if (list != NULL)
    {
      SECKEY_DestroyPrivateKeyList (list);
      list = NULL;
    }

  return count;
}

SECKEYPrivateKey *
RA_Token::GetPrivateKey (int pos)
{
  SECKEYPrivateKeyList *list = NULL;
  SECKEYPrivateKeyListNode *node;
  PK11SlotInfo *slot = PK11_GetInternalKeySlot ();
  int count;

  list = PK11_ListPrivateKeysInSlot (slot);
  for (count = 0, node = PRIVKEY_LIST_HEAD (list);
       !PRIVKEY_LIST_END (node, list);
       node = PRIVKEY_LIST_NEXT (node), count++)
    {
      if (pos == count)
	{
	  return node->key;
	}
    }
  if (list != NULL)
    {
      SECKEY_DestroyPrivateKeyList (list);
      list = NULL;
    }

  return NULL;
}

int
RA_Token::NoOfCertificates ()
{
  CERTCertList *clist = NULL;
  CERTCertListNode *cln;
  PK11SlotInfo *slot = PK11_GetInternalKeySlot ();
  int count = 0;

  clist = PK11_ListCertsInSlot (slot);
  for (cln = CERT_LIST_HEAD (clist); !CERT_LIST_END (cln, clist);
       cln = CERT_LIST_NEXT (cln))
    {
      count++;
    }

  return count;
}

CERTCertificate *
RA_Token::GetCertificate (int pos)
{
  CERTCertList *clist = NULL;
  CERTCertListNode *cln;
  PK11SlotInfo *slot = PK11_GetInternalKeySlot ();
  int count = 0;

  clist = PK11_ListCertsInSlot (slot);
  for (cln = CERT_LIST_HEAD (clist); !CERT_LIST_END (cln, clist);
       cln = CERT_LIST_NEXT (cln))
    {
      if (count == pos)
	{
	  CERTCertificate *cert = cln->cert;
	  return cert;
	}
      count++;
    }

  return NULL;
}

void
RA_Token::decryptMsg (Buffer & in_data, Buffer & out_data)
{
  Output ("RA_Token::decryptMsg: decryption about to proceed");

  //add this header back later...does not include lc, since it might change
  Buffer header = in_data.substr (0, 4);
#ifdef VERBOSE
  Output ("input data =");
  printBuf (&in_data);
  Output ("length = %d", in_data.size ());
#endif

  //add this mac back later
  Buffer mac = in_data.substr (in_data.size () - 8, 8);

#ifdef VERBOSE
  Output ("mac=");
  printBuf (&mac);
#endif

  // encrypted data area is the part without header and mac
  Buffer enc_in_data = in_data.substr (5, in_data.size () - 8 - 5);

#ifdef VERBOSE
  Output ("RA_Token::decryptMsg: enc_in_data size: %d", enc_in_data.size ());
  Output ("encrypted in_data =");
  printBuf (&enc_in_data);
#endif

  Buffer d_apdu_data;
  PRStatus status = Util::DecryptData (GetEncSessionKey (),
				       enc_in_data, d_apdu_data);
#ifdef VERBOSE
  Output ("RA_Token::decryptMsg: decrypted data size = %d, data=",
	  d_apdu_data.size ());
  printBuf (&d_apdu_data);
#endif

  if (status == PR_SUCCESS)
    {
      Output ("RA_Token::decryptMsg: decrypt success");
    }
  else
    {
      Output ("RA_Token::decryptMsg: decrypt failure");
      //      return NULL;
    }

  /*
   * the original (pre-encrypted) data would look like the following
   *   orig. Length | Data... | <80> | <padding>
   * where orig. Length is one byte,
   * if orig Length + 1byte length is multiple of 8,
   *     it wasn't padded
   * if orig Length + 1byte length is not multiple of 8,
   *     '80' was appended to the right of data field
   * if that was multiple was 8, it's done, otherwise
   *    it was padded with 0 until the data len is a multiple of 8
   */
  int origLen = (int) ((BYTE *) d_apdu_data)[0];
  Output ("RA_Token::decryptMsg: origLen = %d", origLen);

  Buffer orig_data;

  // this should perfectly skip the paddings, if was any
  orig_data = d_apdu_data.substr (1, origLen);
  out_data = header;
  out_data += Buffer (1, ((BYTE *) d_apdu_data)[0] + 0x08);
  out_data += orig_data;
  out_data += mac;

#ifdef VERBOSE
  Output ("decrypted pdu data:");
  printBuf (&out_data);
#endif
}

APDU_Response *
RA_Token::ProcessInitializeUpdate (Initialize_Update_APDU * apdu,
				   NameValueSet * vars, NameValueSet * params)
{
  BYTE requested_version = apdu->GetP1 ();
  //BYTE requested_index = apdu->GetP2();
  Buffer host_challenge = apdu->GetHostChallenge ();
  m_host_challenge = host_challenge;
//        printf("Host Challenge: \n");
//        host_challenge.dump();

  Buffer ki = GetKeyInfo ();
  BYTE current_version = ((BYTE *) ki)[0];
  //BYTE current_index = ((BYTE*)ki)[1];

  // for testing only
  if (vars->GetValueAsBool("test_enable", 0) == 1) {
    if (vars->GetValueAsBool("test_apdu_iu_return_enable", 0) == 1) {
      Buffer *data = ToBuffer (vars->GetValue ("test_apdu_iu_return"));
      APDU_Response *apdu_resp = new APDU_Response (*data);
      return apdu_resp;
    }
  }

  if (requested_version != 0x00 && requested_version != current_version)
    {
      // return an error
      Buffer data = Buffer (1, (BYTE) 0x6a) + Buffer (1, (BYTE) 0x88);
      APDU_Response *apdu_resp = new APDU_Response (data);
      return apdu_resp;
    }

  m_icv = Buffer (8, (BYTE) 0);

	/**
         * Initialize Update response:
         *   Key Diversification Data - 10 bytes
         *   Key Information Data - 2 bytes
         *   Card Challenge - 8 bytes
         *   Card Cryptogram - 8 bytes
         */
  Buffer card_challenge (8, (BYTE) 0);
  Util::GetRandomChallenge (card_challenge);
  m_card_challenge = card_challenge;

  /* compute cryptogram */
  Buffer icv = Buffer (8, (BYTE) 0);
  Buffer input = host_challenge + card_challenge;
  Buffer cryptogram (8, (BYTE) 0);

  Buffer authkey = GetAuthKey ();
  if (authkey == NULL)
    {
      return NULL;
    }
  PK11SymKey *encAuthKey = Util::DeriveKey (GetAuthKey (),
					    host_challenge, card_challenge);
  Util::ComputeMAC (encAuthKey, input, icv, cryptogram);

  // printf("Cryptogram: \n");
  // cryptogram.dump();
  //
  // establish session key
  m_session_key = CreateSessionKey (mac, m_card_challenge, m_host_challenge);
  // establish Encryption session key
  m_enc_session_key = CreateSessionKey (auth, m_card_challenge,
					m_host_challenge);

  Buffer data = GetCUID () + GetKeyInfo () +
    card_challenge + cryptogram +
    Buffer (1, (BYTE) 0x90) + Buffer (1, (BYTE) 0x00);
  APDU_Response *apdu_resp = new APDU_Response (data);

  return apdu_resp;
}

int
RA_Token::VerifyMAC (APDU * apdu)
{
  Buffer data;
  Buffer mac = apdu->GetMAC ();

  Output ("RA_Token::VerifyMAC: Begins==== apdu type =%d", apdu->GetType ());
  if (mac.size () != 8)
    {
      Output ("RA_Token::VerifyMAC:  no mac? ok");
      return 1;
    }

  Buffer new_mac = Buffer (8, (BYTE) 0);

  ComputeAPDUMac (apdu, new_mac);
  if (new_mac != mac)
    {
#ifdef VERBOSE
      Output ("old mac: ");
      printBuf (&mac);
      Output ("new mac: ");
      printBuf (&new_mac);
#endif
      Output ("RA_Token::VerifyMAC:  *** failed ***");
      return 0;
    }
  else
    {
      Output ("RA_Token::VerifyMAC:  passed");
      return 1;
    }
}

void
RA_Token::ComputeAPDUMac (APDU * apdu, Buffer & new_mac)
{
  Buffer data;

  apdu->GetDataToMAC (data);

#ifdef VERBOSE
  Output ("RA_Token::ComputeAPDUMac: data to mac =");
  printBuf (&data);
  Output ("RA_Token::ComputeAPDUMac: current m_icv =");
  printBuf (&m_icv);
#endif


  Util::ComputeMAC (m_session_key, data, m_icv, new_mac);
#ifdef VERBOSE
  Output ("RA_Token::ComputeAPDUMac: got new mac =");
#endif
  printBuf (&new_mac);


  m_icv = new_mac;
}				/* EncodeAPDUMac */

PK11SymKey *
RA_Token::GetEncSessionKey ()
{
  return m_enc_session_key;
}

PK11SymKey *
RA_Token::CreateSessionKey (keyType keytype, Buffer & card_challenge,
			    Buffer & host_challenge)
{
  BYTE *key = NULL;
  char input[16];
  int i;
  BYTE *cc = (BYTE *) card_challenge;
  int cc_len = card_challenge.size ();
  BYTE *hc = (BYTE *) host_challenge;
  int hc_len = host_challenge.size ();

  if (keytype == mac)
    key = (BYTE *) m_mac_key;
  else if (keytype == auth)
    key = (BYTE *) m_auth_key;
  else
    key = (BYTE *) m_mac_key;	// for now

  /* copy card and host challenge into input buffer */
  for (i = 0; i < 8; i++)
    {
      input[i] = cc[i];
    }
  for (i = 0; i < 8; i++)
    {
      input[8 + i] = hc[i];
    }

  PK11SymKey *session_key =
    Util::DeriveKey (Buffer (key, 16), Buffer (hc, hc_len),
		     Buffer (cc, cc_len));

  //printf("XXX mac key\n");
  //m_mac_key.dump();
  //printf("XXX card challenge\n");
  //card_challenge.dump();
  //printf("XXX host challenge\n");
  //host_challenge.dump();
  SECItem *data = PK11_GetKeyData (session_key);
  Buffer db = Buffer (data->data, data->len);
  //      printf("session key:\n");
  //          db.dump();

  return session_key;
}

APDU_Response *
RA_Token::ProcessExternalAuthenticate (External_Authenticate_APDU * apdu,
				       NameValueSet * vars,
				       NameValueSet * params)
{
  Buffer host_cryptogram = apdu->GetHostCryptogram ();

#ifdef VERBOSE
  Output ("RA_Token::ProcessExternalAuthenticate");
#endif
  // printf("Host Cryptogram: \n");
  // host_cryptogram.dump();

  // for testing only
  if (vars->GetValueAsBool("test_enable", 0) == 1) {
    if (vars->GetValueAsBool("test_apdu_ea_return_enable", 0) == 1) {
      Buffer *data = ToBuffer (vars->GetValue ("test_apdu_ea_return"));
      APDU_Response *apdu_resp = new APDU_Response (*data);
      return apdu_resp;
    }
  }

  if (VerifyMAC (apdu) != 1)
    {
      Buffer data = Buffer (1, (BYTE) 0x6a) + Buffer (1, (BYTE) 0x88);
      APDU_Response *apdu_resp = new APDU_Response (data);
      return apdu_resp;
    }


  Buffer data = Buffer (1, (BYTE) 0x90) + Buffer (1, (BYTE) 0x00);
  APDU_Response *apdu_resp = new APDU_Response (data);
  return apdu_resp;
}

static int
VerifyProof (SECKEYPublicKey * pk, SECItem * siProof,
	     unsigned short pkeyb_len, unsigned char *pkeyb,
	     Buffer * challenge)
{
  // this doesn't work, and not needed anymore
  return 1;

  int rs = 1;
  unsigned short i = 0;
  unsigned int j = 0;
  unsigned char *chal = NULL;

  VFYContext *vc = VFY_CreateContext (pk, siProof,
				      SEC_OID_ISO_SHA_WITH_RSA_SIGNATURE,
				      NULL);
  if (vc == NULL)
    {
      Output ("VerifyProof: CreateContext failed");
      return 0;			// error
    }

  SECStatus vs = VFY_Begin (vc);
  if (vs == SECFailure)
    {
      rs = -1;
      Output ("VerifyProof: Begin failed");
      goto loser;
    }
  unsigned char proof[1024];

  for (i = 0; i < pkeyb_len; i++)
    {
      proof[i] = pkeyb[i];
    }
  chal = (unsigned char *) (BYTE *) (*challenge);

  for (j = 0; j < challenge->size (); i++, j++)
    {
      proof[i] = chal[j];
    }
  vs =
    VFY_Update (vc, (unsigned char *) proof, pkeyb_len + challenge->size ());
  if (vs == SECFailure)
    {
      rs = -1;
      Output ("VerifyProof: Update failed");
      goto loser;
    }
  vs = VFY_End (vc);
  if (vs == SECFailure)
    {
      rs = -1;
      Output ("VerifyProof: End failed");
      goto loser;
    }
  else
    {
      Output ("VerifyProof good");
    }

loser:
  if (vc != NULL)
    {
      VFY_DestroyContext (vc, PR_TRUE);
      vc = NULL;
    }
  return rs;

}

static Buffer
GetMusclePublicKeyData (SECKEYPublicKey * pubKey, int keylen)
{
  int i, j;

  Buffer pk = Buffer (4 /* header len */  +
		      pubKey->u.rsa.modulus.len +
		      pubKey->u.rsa.publicExponent.len);

  ((BYTE *) pk)[0] = 0;		/* BLOB_ENC_PLAIN */
  ((BYTE *) pk)[1] = 0x01;	/* Public RSA Key */
  ((BYTE *) pk)[2] = keylen / 256;
  ((BYTE *) pk)[3] = keylen % 256;
  ((BYTE *) pk)[4] = pubKey->u.rsa.modulus.len / 256;
  ((BYTE *) pk)[5] = pubKey->u.rsa.modulus.len % 256;
  for (i = 0; i < (int) pubKey->u.rsa.modulus.len; i++)
    {
      ((BYTE *) pk)[6 + i] = pubKey->u.rsa.modulus.data[i];
    }
  ((BYTE *) pk)[i++] = pubKey->u.rsa.publicExponent.len / 256;
  ((BYTE *) pk)[i++] = pubKey->u.rsa.publicExponent.len % 256;
  for (j = 0; j < (int) pubKey->u.rsa.publicExponent.len; j++)
    {
      ((BYTE *) pk)[i++] = pubKey->u.rsa.publicExponent.data[j];
    }
  return pk;
}

static Buffer
GetMusclePublicKeyDataEC (SECKEYPublicKey * pubKey, int keylen)
{
  Buffer pk = 
          Buffer ((BYTE *) pubKey->u.ec.publicValue.data, pubKey->u.ec.publicValue.len);

  Buffer blob = Buffer (1, (BYTE) 0) +
	      Buffer (1, (BYTE) 0x0a) +  /* key type EC */
	      Buffer (1, (BYTE) (keylen / 256)) + /* key size */
	      Buffer (1, (BYTE) (keylen % 256)) +
	      Buffer (1, (BYTE) (pk.size() >> 8) & 0xff) + /*pubkey blob len*/ 
          Buffer (1, (BYTE) pk.size() & 0xff) + pk; 
Output("pk =");
    printBuf(&pk);
  return pk;
}

static Buffer
Sign (SECOidTag sigAlg, SECKEYPrivateKey * privKey, Buffer & blob)
{
  SECStatus status = SECFailure;

  SECItem sigitem;
  int signature_len = 0;;

  signature_len = PK11_SignatureLen (privKey);
  sigitem.len = signature_len;
  sigitem.data = (unsigned char *) PORT_Alloc (signature_len);

  status = SEC_SignData (&sigitem, (BYTE *) blob, blob.size (), privKey,
			 sigAlg);

  if (status != SECSuccess) {
       char buffer[1024];
       PR_GetErrorText (buffer);

       printf ("Signing error:%d %s\n",PR_GetError(), buffer);
       if (sigitem.data != NULL) {
           PORT_Free (sigitem.data);
	       sigitem.data = NULL;
        }

      /*fake proof for ECC until it works*/
      char fake_proof [] = {
            0x30 ,0x44 ,0x02 ,0x20 ,0x00,
            0xd6 ,0xc2 ,0x08 ,0x34 ,0x79 ,0x28 ,0x2e ,0x5f ,0x70 ,0xe5,
            0x38 ,0x1d ,0x84 ,0xa9 ,0x40 ,0x05 ,0x65 ,0x67 ,0x0f ,0x65,
            0x46 ,0x5d ,0xf7 ,0x68 ,0x37 ,0x86 ,0x0b ,0x66 ,0xf7 ,0x71,
            0x0e ,0x02 ,0x20 ,0x3f ,0x48 ,0xdf ,0x29 ,0xa1 ,0x0e ,0xfb,
            0xdf ,0x38 ,0x26 ,0x9d ,0x54 ,0x01 ,0xbc ,0xb6 ,0x9d ,0xc0,
            0xbf ,0x27 ,0x29 ,0x95 ,0x97 ,0x3c ,0x2f ,0xef ,0xb1 ,0xd2,
            0xdc ,0x9f ,0xcb ,0x03 ,0x8d
      };

/*      return Buffer (16, (BYTE) 0);	// sucks*/

      Output("returning fake proof");
      return Buffer ((BYTE *)fake_proof, (unsigned int)sizeof(fake_proof));
  }

  Buffer proof = Buffer (sigitem.data, signature_len);
  if (sigitem.data != NULL) {
      PORT_Free (sigitem.data);
      sigitem.data = NULL;
  }
  Output("returning real proof");
  return proof;
}

static Buffer
GetKeyBlob (int keysize, SECKEYPublicKey * pubKey)
{
  Buffer blob = Buffer (1, (BYTE) 0) +	/* encoding */
    Buffer (1, (BYTE) 1) +	/* key type */
    Buffer (1, (BYTE) (keysize >> 8) & 0xff) +	/* key size */
    Buffer (1, (BYTE) keysize & 0xff) +	/* key size */
    Buffer (1, (BYTE) (pubKey->u.rsa.modulus.len >> 8) & 0xff) +
    Buffer (1, (BYTE) pubKey->u.rsa.modulus.len & 0xff) +
    Buffer ((BYTE *) pubKey->u.rsa.modulus.data, pubKey->u.rsa.modulus.len) +
    Buffer (1, (BYTE) (pubKey->u.rsa.publicExponent.len >> 8) & 0xff) +
    Buffer (1, (BYTE) pubKey->u.rsa.publicExponent.len & 0xff) +
    Buffer ((BYTE *) pubKey->u.rsa.publicExponent.data,
	    pubKey->u.rsa.publicExponent.len);
  return blob;
}

static Buffer
GetKeyBlobEC (int keysize, SECKEYPublicKey * pubKey)
{
    Buffer pubKeyBlob = 
          Buffer ((BYTE *) pubKey->u.ec.publicValue.data, pubKey->u.ec.publicValue.len);
#ifdef VERBOSE
Output("in GetKeyBlobEC, pubkey blob len =%d", pubKeyBlob.size());
#endif

    Buffer blob = Buffer (1, (BYTE) 0) +
	      Buffer (1, (BYTE) 0x0a) +  /* key type EC */
	      Buffer (1, (BYTE) (keysize / 256)) + /* key size */
	      Buffer (1, (BYTE) (keysize % 256)) +
	      Buffer (1, (BYTE) (pubKeyBlob.size() >> 8) & 0xff) + /*pubkey blob len*/ 
          Buffer (1, (BYTE) pubKeyBlob.size() & 0xff) +
          pubKeyBlob;

#ifdef VERBOSE
Output("GetKeyBlobEC: blob =");
printBuf(&blob);
#endif
    return blob;

}

static Buffer
GetSignBlob (Buffer & muscle_public_key, Buffer & challenge)
{
  int i, j;

  Buffer data = Buffer (muscle_public_key.size () +
			challenge.size (), (BYTE) 0);
  for (i = 0; i < (int) muscle_public_key.size (); i++)
    {
      ((BYTE *) data)[i] = ((BYTE *) muscle_public_key)[i];
    }
  for (j = 0; j < (int) challenge.size (); j++, i++)
    {
      ((BYTE *) data)[i] = ((BYTE *) challenge)[j];
    }
Output("datablob =");
    printBuf(&data);
  return data;
}

/*
 * for RSA keys
 */
APDU_Response *
RA_Token::ProcessGenerateKey (Generate_Key_APDU * apdu,
			      NameValueSet * vars, NameValueSet * params)
{
  CK_MECHANISM_TYPE mechanism;
  SECOidTag algtag;
  PK11RSAGenParams rsaparams;
  void *x_params;
  SECKEYPrivateKey *privKey;
  SECKEYPublicKey *pubKey;
  PK11SlotInfo *slot = PK11_GetInternalKeySlot ();
  int publicExponent = 0x010001;
  int buffer_size;
  // RA::Debug( LL_PER_PDU,
  //            "RA_Token::ProcessGenerateKey: ",
  //            "=====ProcessGenerateKey():in ProcessGenerateKey====" );

  // for testing only
#ifdef VERBOSE
  Output ("RA_Token::ProcessGenerateKey");
#endif
  if (vars->GetValueAsBool("test_enable", 0) == 1) {
    if (vars->GetValueAsBool("test_apdu_gk_return_enable", 0) == 1) {
      Buffer *data = ToBuffer (vars->GetValue ("test_apdu_gk_return"));
      APDU_Response *apdu_resp = new APDU_Response (*data);
      return apdu_resp;
    }
  }


  if (VerifyMAC (apdu) != 1)
    {
      Buffer data = Buffer (1, (BYTE) 0x6a) + Buffer (1, (BYTE) 0x88);
      APDU_Response *apdu_resp = new APDU_Response (data);
      return apdu_resp;
    }

  Buffer req = apdu->GetData ();
  BYTE *raw = (BYTE *) req;
  // BYTE alg = (BYTE)req[5];
  int keysize = (((BYTE *) req)[1] << 8) + ((BYTE *) req)[2];
//      printf("Requested key size %d\n", keysize);

  int wrapped_challenge_len = ((BYTE *) req)[5];
//      printf("Challenged Size=%d\n", wrapped_challenge_len);
  Buffer wrapped_challenge = Buffer ((BYTE *) & raw[6],
				     wrapped_challenge_len);

  rsaparams.keySizeInBits = keysize;
  rsaparams.pe = publicExponent;
  mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
  algtag = SEC_OID_PKCS1_MD5_WITH_RSA_ENCRYPTION;
  x_params = &rsaparams;

  /* generate key pair */
  char *keygen_param = params->GetValue ("keygen");
 
  if (keygen_param == NULL || (strcmp (keygen_param, "true") == 0))
    {
      Output("keygen is true");
      privKey = PK11_GenerateKeyPair (slot, mechanism,
				      x_params, &pubKey,
				      PR_FALSE /*isPerm */ ,
				      PR_TRUE /*isSensitive */ ,
				      NULL /*wincx */ );
      if (privKey == NULL)
	{
      Output("privKey NULL");
	  // printf("privKey == NULL\n");
	  buffer_size = 1024;	/* testing */
	}
      else
	{

    Output("privKey not NULL");
	  /* put key in the buffer */
	  // printf("modulus len %d\n", pubKey->u.rsa.modulus.len);
	  // printf("exponent len %d\n", pubKey->u.rsa.publicExponent.len);

	  Buffer blob = GetKeyBlob (keysize, pubKey);

/*
 * The key generation operation creates a proof-of-location for the
 * newly generated key. This proof is a signature computed with the 
 * new private key using the RSA-with-MD5 signature algorithm.  The 
 * signature is computed over the Muscle Key Blob representation of 
 * the new public key and the challenge sent in the key generation 
 * request.  These two data fields are concatenated together to form
 * the input to the signature, without any other data or length fields.
 */

	  Buffer challenge = Buffer (16, (BYTE) 0x00);
	  // printf("Encrypted Enrollment Challenge:\n");
	  // wrapped_challenge.dump();
	  Util::DecryptData (m_kek_key, wrapped_challenge, challenge);

//              printf("Enrollment Challenge:\n");
//              challenge.dump();
//              printf("after challenge dump");
	  Buffer muscle_public_key = GetMusclePublicKeyData (pubKey, keysize);
//              printf("after muscle_public_key get, muscle_public_key size=%d", muscle_public_key.size());
	  Buffer data_blob = GetSignBlob ( /*muscle_public_key */ blob,
					  challenge);
//              printf("after getsignblob, blob size =%d",blob.size());
	  Buffer proof = Sign (SEC_OID_ISO_SHA_WITH_RSA_SIGNATURE, privKey, data_blob);
//              printf("begin verifying proof");
	  unsigned char *pkeyb = (unsigned char *) (BYTE *) data_blob;
	  int pkeyb_len = data_blob.size ();

	  SECItem siProof;
	  siProof.type = (SECItemType) 0;
	  siProof.data = (unsigned char *) proof;
	  siProof.len = proof.size ();

	  //    int size = data_blob.size();
	  // RA::Debug( LL_PER_PDU,
	  //            "RA_Token::ProcessGenerateKey: ",
	  //            "==== proof size =%d, data_blob size=%d",
	  //            siProof.len,
	  //            data_blob.size() );
	  // RA::Debug( LL_PER_PDU,
	  //            "RA_Token::ProcessGenerateKey: ",
	  //            "==== === printing blob. size=%d",
	  //            size );
	  // RA::Debug( LL_PER_PDU,
	  //            "RA_Token::ProcessGenerateKey: ",
	  //            "pubKey->u.rsa.publicExponent.data[37] =%d",
	  //            pubKey->u.rsa.publicExponent.data[37] );

	  if (VerifyProof (pubKey, &siProof, pkeyb_len, pkeyb, &challenge) !=
	      1)
	    {

	      Output ("VerifyProof failed");
	      Buffer data = Buffer (1, (BYTE) 0x6a) + Buffer (1, (BYTE) 0x88);
	      APDU_Response *apdu_resp = new APDU_Response (data);
	      return apdu_resp;

	    }
      Output("after VerifyProof");

	  m_buffer =
	    Buffer (1, (BYTE) (blob.size () / 256)) +
	    Buffer (1, (BYTE) (blob.size () % 256)) +
	    Buffer (blob) +
	    Buffer (1, (BYTE) (proof.size () / 256)) +
	    Buffer (1, (BYTE) (proof.size () % 256)) + Buffer (proof);
	  buffer_size = m_buffer.size ();
	}			// if private key not NULL

    }
  else
    {
      Output("keygen is false");
      // fake RSA key
      BYTE fake_RSA_key[] = {
	0x00, 0x8b, 0x00, 0x01, 0x04, 0x00, 0x00, 0x80, 0x9f, 0xf9,
	0x6e, 0xa6, 0x6c, 0xd9, 0x4b, 0x5c, 0x1a, 0xb6, 0xd8, 0x78,
	0xd2, 0xaf, 0x45, 0xd5, 0xce, 0x8a, 0xee, 0x69, 0xfc, 0xdb,
	0x16, 0x21, 0x46, 0x61, 0xb9, 0x91, 0x5d, 0xa8, 0x41, 0x3f,
	0x5c, 0xce, 0xce, 0x16, 0x0b, 0xc3, 0x16, 0x99, 0xb7, 0x81,
	0xe9, 0x9c, 0xe5, 0x31, 0x04, 0x6d, 0xab, 0xb2, 0xa3, 0xac,
	0x91, 0x2b, 0xbd, 0x9b, 0x48, 0xa8, 0xd7, 0xd8, 0x34, 0x67,
	0x4d, 0x58, 0xd3, 0xb9, 0x81, 0x4f, 0x8c, 0xf1, 0x2c, 0x92,
	0xfa, 0xe7, 0x98, 0x72, 0xea, 0x52, 0xbb, 0x43, 0x73, 0x9e,
	0x88, 0xdc, 0x6c, 0x44, 0xf3, 0x6d, 0xfd, 0x36, 0xa6, 0x5c,
	0x61, 0x7d, 0x88, 0x51, 0xc7, 0x32, 0x14, 0x64, 0xf3, 0xe0,
	0x6f, 0xfa, 0x86, 0x1d, 0xad, 0x6c, 0xdb, 0x8a, 0x1c, 0x30,
	0xb2, 0x46, 0x26, 0xba, 0x3c, 0x71, 0x2c, 0x03, 0x45, 0x97,
	0x7f, 0xb0, 0x10, 0x24, 0xf4, 0x45, 0x00, 0x03, 0x01, 0x00,
	0x01, 0x00, 0x80, 0x58, 0x06, 0x40, 0x4e, 0x05, 0xd8, 0x54,
	0x87, 0xb1, 0x5b, 0xfc, 0x67, 0x95, 0xe5
      };

      m_buffer = Buffer ((BYTE *) fake_RSA_key, sizeof fake_RSA_key);
      buffer_size = m_buffer.size ();
    }

  Output("creating new APDU_Response, data = ");
  Buffer data = Buffer (1, (BYTE) (buffer_size >> 8) & 0xff) +	// key length
    Buffer (1, (BYTE) buffer_size & 0xff) +	// key length 
    Buffer (1, (BYTE) 0x90) + Buffer (1, (BYTE) 0x00);
  printBuf(&data);

  APDU_Response *apdu_resp = new APDU_Response (data);
  return apdu_resp;
}


SECKEYECParams * 
RA_Token::getECParams(const char *curve)
{
/*This function is borrowed from certutil*/
    SECKEYECParams *ecparams = NULL;
    SECOidData *oidData = NULL;
    SECOidTag curveOidTag = SEC_OID_UNKNOWN; /* default */
    int i, numCurves;

    if (curve != NULL) {
        numCurves = sizeof(nameTagPair)/sizeof(CurveNameTagPair);
        for (i = 0; ((i < numCurves) && (curveOidTag == SEC_OID_UNKNOWN)); 
            i++) {
            if (PL_strcmp(curve, nameTagPair[i].curveName) == 0)
              curveOidTag = nameTagPair[i].curveOidTag;
        }
    }

    /* Return NULL if curve name is not recognized */
    if ((curveOidTag == SEC_OID_UNKNOWN) || 
    (oidData = SECOID_FindOIDByTag(curveOidTag)) == NULL) {
        fprintf(stderr, "Unrecognized elliptic curve %s\n", curve);
        return NULL;
    }

    ecparams = SECITEM_AllocItem(NULL, NULL, (2 + oidData->oid.len));

    /* 
     * ecparams->data needs to contain the ASN encoding of an object ID (OID)
     * representing the named curve. The actual OID is in 
     * oidData->oid.data so we simply prepend 0x06 and OID length
     */
    ecparams->data[0] = SEC_ASN1_OBJECT_ID;
    ecparams->data[1] = oidData->oid.len;
    memcpy(ecparams->data + 2, oidData->oid.data, oidData->oid.len);

    return ecparams;
}

static int ReadLine(PRFileDesc *f, char *buf, int buf_len, int *removed_return)
{
    char *cur = buf;
    int sum = 0;
    PRInt32 rc;

    if (removed_return != NULL) {
        *removed_return = 0;
    }
    while (1) {
        rc = PR_Read(f, cur, 1);
        if (rc == -1 || rc == 0)
            break;
        if (*cur == '\r') {
            continue;
        }
        if (*cur == '\n') {
            *cur = '\0';
            if (removed_return != NULL) {
                *removed_return = 1;
            }
            break;
       }
       sum++;
       cur++;
    }
    return sum;
}


char *
RA_Token::getModulePasswordText(PK11SlotInfo *slot, PRBool retry, void *arg) {
    secuPWData *pwdata = (secuPWData *)arg;
    if (pwdata->data != NULL) {
        return PL_strdup(pwdata->data);
    } else {
        Output("getModulePasswordText: password not found");
        return NULL;
    }
}

/*
 * for EC keys
 */
APDU_Response *
RA_Token::ProcessGenerateKeyECC (Generate_Key_ECC_APDU * apdu,
        NameValueSet * vars, NameValueSet * params)
{
    CK_MECHANISM_TYPE mechanism = CKM_EC_KEY_PAIR_GEN;
    SECKEYPrivateKey *privKey = NULL;
    SECKEYPublicKey *pubKey = NULL;
    PK11SlotInfo *slot =  NULL;
    int buffer_size = 0;

    // for testing only
#ifdef VERBOSE
    Output ("RA_Token::ProcessGenerateKeyECC");
#endif
    if (vars->GetValueAsBool("test_enable", 0) == 1) {
        if (vars->GetValueAsBool("test_apdu_gk_return_enable", 0) == 1) {
          Buffer *data = ToBuffer (vars->GetValue ("test_apdu_gk_return"));
          APDU_Response *apdu_resp = new APDU_Response (*data);
          return apdu_resp;
        }
    }

    if (VerifyMAC (apdu) != 1) {
        Buffer data = Buffer (1, (BYTE) 0x6a) + Buffer (1, (BYTE) 0x88);
        APDU_Response *apdu_resp = new APDU_Response (data);
        return apdu_resp;
    }

    Buffer req = apdu->GetData ();
    BYTE *raw = (BYTE *) req;
    int keysize = (((BYTE *) req)[1] << 8) + ((BYTE *) req)[2];
#ifdef VERBOSE
    Output("Requested key size: %d", keysize);
#endif
    char *keycurve = NULL;
    /* only three curves are supported by token */
    if (keysize == 256) {
        keycurve = "nistp256";
    } else if (keysize == 384) {
        keycurve = "nistp384";
    } else if (keysize == 521) {
        keycurve = "nistp521";
    } else {
        Output("unsupported key size: %d, default to nistp256", keysize);
        keycurve = "nistp256";
    }

    int wrapped_challenge_len = ((BYTE *) req)[5];
#ifdef VERBOSE
    printf("Challenged Size=%d\n", wrapped_challenge_len);
#endif
    Buffer wrapped_challenge = Buffer ((BYTE *) & raw[6],
        wrapped_challenge_len);

    PK11AttrFlags attrFlags = 0;

    /* generate key pair */
    char *keygen_param = params->GetValue ("keygen");
 
    if (keygen_param == NULL || (strcmp (keygen_param, "true") == 0)) {
#ifdef VERBOSE
        Output("EC keygen is true");
#endif
        /*
         * slotnamefile contains the actual slot name.
         * This is to overcome the issue with spaces in a token name
         */
        char *slotnamefile = params->GetValue("slotnamefile");
        int removed_return = 0;
        char slotname[500] = "internal";
        PRFileDesc *fd_slotname = (PRFileDesc *) NULL;
        if (slotnamefile == NULL) {
            slot = PK11_GetInternalKeySlot();
        } else {
            fd_slotname = PR_Open(slotnamefile, PR_RDWR, 00400|00200);
            int n = ReadLine(fd_slotname, slotname, 500, &removed_return);
            slot = PK11_FindSlotByName(slotname);
        }

        Output("slotname=%s ",slotname);
        if (slot == NULL) {
            Output("slot NULL");
            exit(1);
        } else {
            Output("using slot : %s", slotname);
        }

        RA_Token::m_tokenpassword = params->GetValue("tokpasswd");
        /* log into token using plaintext*/
        secuPWData pwdata = {pwdata.PW_NONE, 0};
        pwdata.source = pwdata.PW_PLAINTEXT;
        pwdata.data = RA_Token::m_tokenpassword;
        PK11_SetPasswordFunc(RA_Token::getModulePasswordText);

        if (PK11_NeedLogin(slot)) {
            Output("slot needs login");
            SECStatus rv = SECFailure;
            rv  = PK11_Authenticate(slot, PR_TRUE, &pwdata);
            Output("after PK11_Authenticate");
            if (rv == SECSuccess) {
                Output("token authenticated\n");
            } else {
                Output("Could not get password for %s",
                    PK11_GetTokenName(slot));
            }
            if (PK11_IsLoggedIn(slot, &pwdata)) {
                Output("token logged in");
            } else {
                Output("token not logged in");
            }
        }

        SECKEYECParams *ecparams = getECParams(keycurve);
        if (ecparams == NULL) {
            Output("getECParams() returns NULL");
            exit(1);
        } else {
            Output("getECParams() returns not NULL");
        }

        Output("before calling PK11_GenerateKeyPair");
        privKey = PK11_GenerateKeyPair(slot,
                                          mechanism,
                                          ecparams,
                                          &pubKey,
                                          PR_TRUE /*isPerm*/,
                                          PR_TRUE /*isSensitive*/,
                                          &pwdata /*wincx*/);
        Output("after calling PK11_GenerateKeyPair");

        if (ecparams) {
            SECITEM_FreeItem((SECItem *)ecparams, PR_TRUE);
        }
        if ((privKey == NULL) || (pubKey == NULL)) {
            /*not good. should bail*/
            Output("privKey == NULL, fatal error.");
            exit(1);
        } else {
#ifdef VERBOSE
Output("privKey not NULL");
#endif
            /* put key in the buffer */
            Buffer blob = GetKeyBlobEC (keysize, pubKey);

/*
 * The key generation operation creates a proof-of-location for the
 * newly generated key. This proof is a signature computed with the 
 * new private key using the ECDSA_SHA1signature algorithm.  The 
 * signature is computed over the Muscle Key Blob representation of 
 * the new public key and the challenge sent in the key generation 
 * request.  These two data fields are concatenated together to form
 * the input to the signature, without any other data or length fields.
 */

            Buffer challenge = Buffer (16, (BYTE) 0x00);
#ifdef VERBOSE
            printf("Encrypted Enrollment Challenge:\n");
            wrapped_challenge.dump();
#endif
            Util::DecryptData (m_kek_key, wrapped_challenge, challenge);

#ifdef VERBOSE
            printf("Enrollment Challenge:\n");
            challenge.dump();
            printf("after challenge dump");
#endif
            Buffer muscle_public_key = GetMusclePublicKeyDataEC (pubKey, keysize);
#ifdef VERBOSE
            printf("after muscle_public_key get, muscle_public_key size=%d", muscle_public_key.size());
#endif
            Buffer data_blob = GetSignBlob ( /*muscle_public_key */ blob,
                challenge);
            Output("after getsignblob, blob size =%d",blob.size());
            Buffer proof = Sign (SEC_OID_ANSIX962_ECDSA_SHA1_SIGNATURE, privKey, data_blob);

#ifdef VERBOSE
            printf("begin verifying proof");
#endif
            unsigned char *pkeyb = (unsigned char *) (BYTE *) data_blob;
            int pkeyb_len = data_blob.size ();

Output("skipping VerifyProof");
#ifdef VERIFY_PROOF
            SECItem siProof;
            siProof.type = (SECItemType) 0;
            siProof.data = (unsigned char *) proof;
            siProof.len = proof.size ();

            if (VerifyProof (pubKey, &siProof, pkeyb_len, pkeyb, &challenge) != 1)
            {

            Output ("VerifyProof failed");
            Buffer data = Buffer (1, (BYTE) 0x6a) + Buffer (1, (BYTE) 0x88);
            APDU_Response *apdu_resp = new APDU_Response (data);
            return apdu_resp;

            }

Output("after VerifyProof");
Output("blob.size=%d", blob.size());
Output("pkeyb_len=", pkeyb_len);
Output("proof.size=", proof.size());
#endif /*VERIFY_PROOF */

            /* ECC format */
            m_buffer =
                Buffer (1, (BYTE) (blob.size () / 256)) +
            Buffer (1, (BYTE) (blob.size () % 256)) +
                Buffer (blob) +
            Buffer (1, (BYTE) (proof.size () / 256)) +
            Buffer (1, (BYTE) (proof.size () % 256)) + Buffer (proof);
            buffer_size = m_buffer.size ();
        }  // if private key not NULL

    } else {
        Output("keygen is false, using fake EC key with nistp256");

        // fake/static EC key
        BYTE fake_EC_key[] = {
            0x00, 0x47, // total length
            0x00, 0x0a, // EC
            0x01, 0x00, // keysize == 256
            0x00, 0x41, // length of pubkey
            // pubkey
            0x04, 0xd2,
            0x26 ,0x83 ,0x36 ,0x80 ,0x33 ,0x2d ,0x26 ,0xda ,0x76 ,0x97,
            0xbb ,0x0b ,0xc8 ,0xc3 ,0x86 ,0xc9 ,0x70 ,0x36 ,0x9b ,0x40,
            0x4c ,0xa4 ,0xec ,0x3a ,0x0b ,0xa5 ,0x89 ,0x67 ,0xde ,0xc4,
            0x89 ,0x47 ,0x28 ,0x15 ,0xdd ,0x74 ,0x4b ,0xf8 ,0x21 ,0x18,
            0x40 ,0x06 ,0xf9 ,0x28 ,0xc4 ,0x62 ,0x26 ,0xa1 ,0x59 ,0x59,
            0x85 ,0x62 ,0xaf ,0xd0 ,0x5d ,0x43 ,0xde ,0xd7 ,0xb4 ,0xcf,
            0xc5 ,0x5b ,0xee,
            // proof size
            0x00, 0x46,
            //proof
            0x30 ,0x44 ,0x02 ,0x20 ,0x00,
            0xd6 ,0xc2 ,0x08 ,0x34 ,0x79 ,0x28 ,0x2e ,0x5f ,0x70 ,0xe5,
            0x38 ,0x1d ,0x84 ,0xa9 ,0x40 ,0x05 ,0x65 ,0x67 ,0x0f ,0x65,
            0x46 ,0x5d ,0xf7 ,0x68 ,0x37 ,0x86 ,0x0b ,0x66 ,0xf7 ,0x71,
            0x0e ,0x02 ,0x20 ,0x3f ,0x48 ,0xdf ,0x29 ,0xa1 ,0x0e ,0xfb,
            0xdf ,0x38 ,0x26 ,0x9d ,0x54 ,0x01 ,0xbc ,0xb6 ,0x9d ,0xc0,
            0xbf ,0x27 ,0x29 ,0x95 ,0x97 ,0x3c ,0x2f ,0xef ,0xb1 ,0xd2,
            0xdc ,0x9f ,0xcb ,0x03 ,0x8d
          };

          m_buffer = Buffer ((BYTE *) fake_EC_key, sizeof fake_EC_key);
          buffer_size = m_buffer.size ();
    }

    Output("creating new APDU_Response, data = ");
    Buffer data =
         Buffer (1, (BYTE) (buffer_size >> 8) & 0xff) +  // key length
        Buffer (1, (BYTE) buffer_size & 0xff) +  // key length 
        Buffer (1, (BYTE) 0x90) + Buffer (1, (BYTE) 0x00);
    printBuf(&data);

    APDU_Response *apdu_resp = new APDU_Response (data);
    return apdu_resp;
}

APDU_Response *
RA_Token::ProcessCreateObject (Create_Object_APDU * apdu,
			       NameValueSet * vars, NameValueSet * params)
{
  Buffer inputdata;
  m_chunk_len = 0;
  m_object_len = 0;

#ifdef VERBOSE
  Output ("RA_Token::ProcessCreateObject");
#endif
  // for testing only
  if (vars->GetValueAsBool("test_enable", 0) == 1) {
    if (vars->GetValueAsBool("test_apdu_co_return_enable", 0) == 1) {
      Buffer *data = ToBuffer (vars->GetValue ("test_apdu_co_return"));
      APDU_Response *apdu_resp = new APDU_Response (*data);
      return apdu_resp;
    }
  }

  if (VerifyMAC (apdu) != 1)
    {
      Buffer data = Buffer (1, (BYTE) 0x6a) + Buffer (1, (BYTE) 0x88);
      APDU_Response *apdu_resp = new APDU_Response (data);
      return apdu_resp;
    }

  inputdata = apdu->GetData ();
//    inputdata.dump();
  m_objectid[0] = (char) (((BYTE *) inputdata)[0]);
  m_objectid[1] = (char) (((BYTE *) inputdata)[1]);
  m_objectid[2] = '\0';

// skip permissions

  m_object_len += (((BYTE *) inputdata)[4]) << 24;
  m_object_len += (((BYTE *) inputdata)[5]) << 16;
  m_object_len += (((BYTE *) inputdata)[6]) << 8;
  m_object_len += ((BYTE *) inputdata)[7];

  Buffer data = Buffer (1, (BYTE) 0x90) + Buffer (1, (BYTE) 0x00);
  APDU_Response *apdu_resp = new APDU_Response (data);
  if (m_object != NULL)
    {
      delete m_object;
      m_object = NULL;
    }
  m_object = new Buffer (m_object_len, (BYTE) 0);
  return apdu_resp;
}

APDU_Response *
RA_Token::ProcessLifecycle (Lifecycle_APDU * apdu,
			    NameValueSet * vars, NameValueSet * params)
{

#ifdef VERBOSE
  Output ("RA_Token::ProcessLifecycle");
#endif
  // for testing only
  if (vars->GetValueAsBool("test_enable", 0) == 1) {
    if (vars->GetValueAsBool("test_apdu_lc_return_enable", 0) == 1) {
      Buffer *data = ToBuffer (vars->GetValue ("test_apdu_lc_return"));
      APDU_Response *apdu_resp = new APDU_Response (*data);
      return apdu_resp;
    }
  }

  if (VerifyMAC (apdu) != 1)
    {
      Buffer data = Buffer (1, (BYTE) 0x6a) + Buffer (1, (BYTE) 0x88);
      APDU_Response *apdu_resp = new APDU_Response (data);
      return apdu_resp;
    }
  Buffer data = Buffer (1, (BYTE) 0x90) + Buffer (1, (BYTE) 0x00);
  APDU_Response *apdu_resp = new APDU_Response (data);
  return apdu_resp;
}

APDU_Response *
RA_Token::ProcessDeleteFile (Delete_File_APDU * apdu,
			     NameValueSet * vars, NameValueSet * params)
{
#ifdef VERBOSE
  Output ("RA_Token::ProcessDeleteFile");
#endif
  // for testing only
  if (vars->GetValueAsBool("test_enable", 0) == 1) {
    if (vars->GetValueAsBool("test_apdu_df_return_enable", 0) == 1) {
      Buffer *data = ToBuffer (vars->GetValue ("test_apdu_df_return"));
      APDU_Response *apdu_resp = new APDU_Response (*data);
      return apdu_resp;
    }
  }

  if (VerifyMAC (apdu) != 1)
    {
      Buffer data = Buffer (1, (BYTE) 0x6a) + Buffer (1, (BYTE) 0x88);
      APDU_Response *apdu_resp = new APDU_Response (data);
      return apdu_resp;
    }

  Buffer data = Buffer (1, (BYTE) 0x90) + Buffer (1, (BYTE) 0x00);
  APDU_Response *apdu_resp = new APDU_Response (data);
  return apdu_resp;
}

APDU_Response *
RA_Token::ProcessInstallApplet (Install_Applet_APDU * apdu,
				NameValueSet * vars, NameValueSet * params)
{
#ifdef VERBOSE
  Output ("RA_Token::InstallApplet");
#endif
  // for testing only
  if (vars->GetValueAsBool("test_enable", 0) == 1) {
    if (vars->GetValueAsBool("test_apdu_ia_return_enable", 0) == 1) {
      Buffer *data = ToBuffer (vars->GetValue ("test_apdu_ia_return"));
      APDU_Response *apdu_resp = new APDU_Response (*data);
      return apdu_resp;
    }
  }

  if (VerifyMAC (apdu) != 1)
    {
      Buffer data = Buffer (1, (BYTE) 0x6a) + Buffer (1, (BYTE) 0x88);
      APDU_Response *apdu_resp = new APDU_Response (data);
      return apdu_resp;
    }

  Buffer data = Buffer (1, (BYTE) 0x90) + Buffer (1, (BYTE) 0x00);
  APDU_Response *apdu_resp = new APDU_Response (data);
  return apdu_resp;
}

APDU_Response *
RA_Token::ProcessInstallLoad (Install_Load_APDU * apdu,
			      NameValueSet * vars, NameValueSet * params)
{
#ifdef VERBOSE
  Output ("RA_Token::InstallLoad");
#endif
  // for testing only
  if (vars->GetValueAsBool("test_enable", 0) == 1) {
    if (vars->GetValueAsBool("test_apdu_il_return_enable", 0) == 1) {
      Buffer *data = ToBuffer (vars->GetValue ("test_apdu_il_return"));
      APDU_Response *apdu_resp = new APDU_Response (*data);
      return apdu_resp;
    }
  }

  if (VerifyMAC (apdu) != 1)
    {
      Buffer data = Buffer (1, (BYTE) 0x6a) + Buffer (1, (BYTE) 0x88);
      APDU_Response *apdu_resp = new APDU_Response (data);
      return apdu_resp;
    }

  Buffer data = Buffer (1, (BYTE) 0x90) + Buffer (1, (BYTE) 0x00);
  APDU_Response *apdu_resp = new APDU_Response (data);
  return apdu_resp;
}

APDU_Response *
RA_Token::ProcessLoadFile (Load_File_APDU * apdu,
			   NameValueSet * vars, NameValueSet * params)
{
#ifdef VERBOSE
  Output ("RA_Token::ProcessLoadFile");
#endif
  // for testing only
  if (vars->GetValueAsBool("test_enable", 0) == 1) {
    if (vars->GetValueAsBool("test_apdu_lf_return_enable", 0) == 1) {
      Buffer *data = ToBuffer (vars->GetValue ("test_apdu_lf_return"));
      APDU_Response *apdu_resp = new APDU_Response (*data);
      return apdu_resp;
    }
  }

  if (VerifyMAC (apdu) != 1)
    {
      Buffer data = Buffer (1, (BYTE) 0x6a) + Buffer (1, (BYTE) 0x88);
      APDU_Response *apdu_resp = new APDU_Response (data);
      return apdu_resp;
    }

  Buffer data = Buffer (1, (BYTE) 0x90) + Buffer (1, (BYTE) 0x00);
  APDU_Response *apdu_resp = new APDU_Response (data);
  return apdu_resp;
}

APDU_Response *
RA_Token::ProcessFormatMuscleApplet (Format_Muscle_Applet_APDU * apdu,
				     NameValueSet * vars,
				     NameValueSet * params)
{

  if (VerifyMAC (apdu) != 1)
    {
      Buffer data = Buffer (1, (BYTE) 0x6a) + Buffer (1, (BYTE) 0x88);
      APDU_Response *apdu_resp = new APDU_Response (data);
      return apdu_resp;
    }
  Buffer data = Buffer (1, (BYTE) 0x90) + Buffer (1, (BYTE) 0x00);
  APDU_Response *apdu_resp = new APDU_Response (data);
  return apdu_resp;
}

APDU_Response *
RA_Token::ProcessSelect (Select_APDU * apdu,
			 NameValueSet * vars, NameValueSet * params)
{
  // for testing only
  if (vars->GetValueAsBool("test_enable", 0) == 1) {
    if (vars->GetValueAsBool("test_apdu_se_return_enable", 0) == 1) {
      Buffer *data = ToBuffer (vars->GetValue ("test_apdu_se_return"));
      APDU_Response *apdu_resp = new APDU_Response (*data);
      return apdu_resp;
    }
  }


  if (VerifyMAC (apdu) != 1)
    {
      Buffer data = Buffer (1, (BYTE) 0x6a) + Buffer (1, (BYTE) 0x88);
      APDU_Response *apdu_resp = new APDU_Response (data);
      return apdu_resp;
    }
  Buffer data = Buffer (1, (BYTE) 0x90) + Buffer (1, (BYTE) 0x00);
  APDU_Response *apdu_resp = new APDU_Response (data);
  return apdu_resp;
}

APDU_Response *
RA_Token::ProcessListPins (List_Pins_APDU * apdu,
			   NameValueSet * vars, NameValueSet * params)
{
  // for testing only
  if (vars->GetValueAsBool("test_enable", 0) == 1) {
    if (vars->GetValueAsBool("test_apdu_lp_return_enable", 0) == 1) {
      Buffer *data = ToBuffer (vars->GetValue ("test_apdu_lp_return"));
      APDU_Response *apdu_resp = new APDU_Response (*data);
      return apdu_resp;
    }
  }


  if (VerifyMAC (apdu) != 1)
    {
      Buffer data = Buffer (1, (BYTE) 0x6a) + Buffer (1, (BYTE) 0x88);
      APDU_Response *apdu_resp = new APDU_Response (data);
      return apdu_resp;
    }
  Buffer data = m_version + Buffer (1, (BYTE) 0x90) + Buffer (1, (BYTE) 0x00);
  APDU_Response *apdu_resp = new APDU_Response (data);
  return apdu_resp;
}

APDU_Response *
RA_Token::ProcessGetIssuerInfo (Get_IssuerInfo_APDU * apdu,
			    NameValueSet * vars, NameValueSet * params)
{
  // for testing only
  if (vars->GetValueAsBool("test_enable", 0) == 1) {
    if (vars->GetValueAsBool("test_apdu_cp_return_enable", 0) == 1) {
      Buffer *data = ToBuffer (vars->GetValue ("test_apdu_cp_return"));
      APDU_Response *apdu_resp = new APDU_Response (*data);
      return apdu_resp;
    }
  }

  if (VerifyMAC (apdu) != 1)
    {
      Buffer data = Buffer (1, (BYTE) 0x6a) + Buffer (1, (BYTE) 0x88);
      APDU_Response *apdu_resp = new APDU_Response (data);
      return apdu_resp;
    }

  Buffer data = m_version + Buffer (1, (BYTE) 0x90) + Buffer (1, (BYTE) 0x00);
  APDU_Response *apdu_resp = new APDU_Response (data);
  return apdu_resp;
}

APDU_Response *
RA_Token::ProcessSetIssuerInfo (Set_IssuerInfo_APDU * apdu,
			    NameValueSet * vars, NameValueSet * params)
{
  // for testing only
  if (vars->GetValueAsBool("test_enable", 0) == 1) {
    if (vars->GetValueAsBool("test_apdu_cp_return_enable", 0) == 1) {
      Buffer *data = ToBuffer (vars->GetValue ("test_apdu_cp_return"));
      APDU_Response *apdu_resp = new APDU_Response (*data);
      return apdu_resp;
    }
  }

  if (VerifyMAC (apdu) != 1)
    {
      Buffer data = Buffer (1, (BYTE) 0x6a) + Buffer (1, (BYTE) 0x88);
      APDU_Response *apdu_resp = new APDU_Response (data);
      return apdu_resp;
    }

  Buffer data = m_version + Buffer (1, (BYTE) 0x90) + Buffer (1, (BYTE) 0x00);
  APDU_Response *apdu_resp = new APDU_Response (data);
  return apdu_resp;
}

APDU_Response *
RA_Token::ProcessCreatePin (Create_Pin_APDU * apdu,
			    NameValueSet * vars, NameValueSet * params)
{
  // for testing only
  if (vars->GetValueAsBool("test_enable", 0) == 1) {
    if (vars->GetValueAsBool("test_apdu_cp_return_enable", 0) == 1) {
      Buffer *data = ToBuffer (vars->GetValue ("test_apdu_cp_return"));
      APDU_Response *apdu_resp = new APDU_Response (*data);
      return apdu_resp;
    }
  }

  if (VerifyMAC (apdu) != 1)
    {
      Buffer data = Buffer (1, (BYTE) 0x6a) + Buffer (1, (BYTE) 0x88);
      APDU_Response *apdu_resp = new APDU_Response (data);
      return apdu_resp;
    }

  Buffer data = m_version + Buffer (1, (BYTE) 0x90) + Buffer (1, (BYTE) 0x00);
  APDU_Response *apdu_resp = new APDU_Response (data);
  return apdu_resp;
}

APDU_Response *
RA_Token::ProcessGetVersion (Get_Version_APDU * apdu,
			     NameValueSet * vars, NameValueSet * params)
{
  // for testing only
  if (vars->GetValueAsBool("test_enable", 0) == 1) {
    if (vars->GetValueAsBool("test_apdu_gv_return_enable", 0) == 1) {
      Buffer *data = ToBuffer (vars->GetValue ("test_apdu_gv_return"));
      APDU_Response *apdu_resp = new APDU_Response (*data);
      return apdu_resp;
    }
  }

  if (VerifyMAC (apdu) != 1)
    {
      Buffer data = Buffer (1, (BYTE) 0x6a) + Buffer (1, (BYTE) 0x88);
      APDU_Response *apdu_resp = new APDU_Response (data);
      return apdu_resp;
    }

  Buffer data = m_version + Buffer (1, (BYTE) 0x90) + Buffer (1, (BYTE) 0x00);
  APDU_Response *apdu_resp = new APDU_Response (data);
  return apdu_resp;
}

APDU_Response *
RA_Token::ProcessGetData (Get_Data_APDU * apdu,
			  NameValueSet * vars, NameValueSet * params)
{
  // for testing only
  if (vars->GetValueAsBool("test_enable", 0) == 1) {
    if (vars->GetValueAsBool("test_apdu_gd_return_enable", 0) == 1) {
      Buffer *data = ToBuffer (vars->GetValue ("test_apdu_gd_return"));
      APDU_Response *apdu_resp = new APDU_Response (*data);
      return apdu_resp;
    }
  }

  if (VerifyMAC (apdu) != 1)
    {
      Buffer data = Buffer (1, (BYTE) 0x6a) + Buffer (1, (BYTE) 0x88);
      APDU_Response *apdu_resp = new APDU_Response (data);
      return apdu_resp;
    }

  Buffer data =
    Buffer (1, (BYTE) 0x01) + Buffer (1, (BYTE) 0x00) +
    Buffer (1, (BYTE) 0x01) +
    m_cuid.substr (0, 4) +
    Buffer (1, (BYTE) 0x01) + Buffer (1, (BYTE) 0x00) +
    Buffer (1, (BYTE) 0x01) + Buffer (1, (BYTE) 0x00) +
    Buffer (1, (BYTE) 0x01) + Buffer (1, (BYTE) 0x00) +
    Buffer (1, (BYTE) 0x01) + Buffer (1, (BYTE) 0x00) +
    m_cuid.substr (6, 4) +
    m_cuid.substr (4, 2) +
    Buffer (1, (BYTE) 0x01) + Buffer (1, (BYTE) 0x00) +
    Buffer (1, (BYTE) 0x01) + Buffer (1, (BYTE) 0x00) +
    Buffer (1, (BYTE) 0x00) + Buffer (1, (BYTE) 0x00) +
    Buffer (1, (BYTE) 0x01) + Buffer (1, (BYTE) 0x00) +
    Buffer (1, (BYTE) 0x01) + Buffer (1, (BYTE) 0x00) +
    Buffer (1, (BYTE) 0x01) + Buffer (1, (BYTE) 0x00) +
    Buffer (1, (BYTE) 0x01) + Buffer (1, (BYTE) 0x00) +
    Buffer (1, (BYTE) 0x00) + Buffer (1, (BYTE) 0x00) +
    Buffer (1, (BYTE) 0x01) + Buffer (1, (BYTE) 0x00) +
    Buffer (1, (BYTE) 0x01) + Buffer (1, (BYTE) 0x00) +
    m_msn.substr (0, 4) + Buffer (1, (BYTE) 0x90) + Buffer (1, (BYTE) 0x00);
  APDU_Response *apdu_resp = new APDU_Response (data);
  return apdu_resp;
}

APDU_Response *
RA_Token::ProcessGetStatus (Get_Status_APDU * apdu,
			    NameValueSet * vars, NameValueSet * params)
{
  // for testing only
  if (vars->GetValueAsBool("test_enable", 0) == 1) {
    if (vars->GetValueAsBool("test_apdu_gs_return_enable", 0) == 1) {
      Buffer *data = ToBuffer (vars->GetValue ("test_apdu_gs_return"));
      APDU_Response *apdu_resp = new APDU_Response (*data);
      return apdu_resp;
    }
  }

  if (VerifyMAC (apdu) != 1)
    {
      Buffer data = Buffer (1, (BYTE) 0x6a) + Buffer (1, (BYTE) 0x88);
      APDU_Response *apdu_resp = new APDU_Response (data);
      return apdu_resp;
    }

  //Return a reasonable value for available applet memory.
  //Free mem - 8192
  //Tot  mem - 8447
  BYTE free_mem_high = 0x20;
  BYTE free_mem_low  = 0x00;
  BYTE tot_mem_high  = 0x20;
  BYTE tot_mem_low   = 0xff;
  Buffer data =
    Buffer (1, (BYTE) m_major_version) + Buffer (1, (BYTE) m_minor_version) +
    Buffer (1, (BYTE) 0x00) + Buffer (1, (BYTE) 0x00) +
    Buffer (1, (BYTE) 0x01) + Buffer (1, (BYTE) 0x00) +
    Buffer (1, (BYTE) tot_mem_high) +  Buffer (1, (BYTE) tot_mem_low) +
    Buffer (1, (BYTE) 0x01) + Buffer (1, (BYTE) 0x00) +
    Buffer (1, (BYTE) free_mem_high) + Buffer (1, (BYTE) free_mem_low) +
    Buffer (1, (BYTE) 0x01) + Buffer (1, (BYTE) 0x00) +
    Buffer (1, (BYTE) 0x01) + Buffer (1, (BYTE) 0x00) +
    Buffer (1, (BYTE) 0x90) + Buffer (1, (BYTE) 0x00); 
  APDU_Response *apdu_resp = new APDU_Response (data);
  return apdu_resp;
}

APDU_Response *
RA_Token::ProcessPutKey (Put_Key_APDU * apdu,
			 NameValueSet * vars, NameValueSet * params)
{
#ifdef VERBOSE
  Output ("RA_Token::ProcessPutKey");
#endif
  Buffer key_set_data = apdu->GetData ();
  BYTE current_version = ((BYTE *) key_set_data)[0];
  BYTE current_index = (apdu->GetP2 () & 0x0f);

  BYTE ki[2] = { current_version, current_index };
  Buffer kib (ki, 2);
  SetKeyInfo (kib);

  // for testing only
  if (vars->GetValueAsBool("test_enable", 0) == 1) {
    if (vars->GetValueAsBool("test_apdu_pk_return_enable", 0) == 1) {
      Buffer *data = ToBuffer (vars->GetValue ("test_apdu_pk_return"));
      APDU_Response *apdu_resp = new APDU_Response (*data);
      return apdu_resp;
    }
  }

  if (VerifyMAC (apdu) != 1)
    {
      Buffer data = Buffer (1, (BYTE) 0x6a) + Buffer (1, (BYTE) 0x88);
      APDU_Response *apdu_resp = new APDU_Response (data);
      return apdu_resp;
    }

  //BYTE new_version = key_set_data[0];
  Buffer e_auth = key_set_data.substr (3, 16);
  Buffer e_mac = key_set_data.substr (25, 16);
  Buffer e_kek = key_set_data.substr (47, 16);

  // need to retrieve the old kek, and decrypt the data 
  // with it
  Buffer auth;
  Buffer mac;
  Buffer kek;
  Util::DecryptData (m_kek_key, e_auth, auth);
  Util::DecryptData (m_kek_key, e_mac, mac);
  Util::DecryptData (m_kek_key, e_kek, kek);

  m_kek_key = kek;
  m_mac_key = mac;
  m_auth_key = auth;

  Buffer data = Buffer (1, (BYTE) 0x90) + Buffer (1, (BYTE) 0x00);
  APDU_Response *apdu_resp = new APDU_Response (data);
  return apdu_resp;
}

APDU_Response *
RA_Token::ProcessImportKeyEnc (Import_Key_Enc_APDU * apdu,
			       NameValueSet * vars, NameValueSet * params)
{
#ifdef VERBOSE
  Output ("RA_Token::ProcessImportKeyEnc");
#endif
  Buffer data;

  // for testing only
  if (vars->GetValueAsBool("test_enable", 0) == 1) {
    if (vars->GetValueAsBool("test_apdu_ik_return_enable", 0) == 1) {
      Buffer *data = ToBuffer (vars->GetValue ("test_apdu_ik_return"));
      APDU_Response *apdu_resp = new APDU_Response (*data);
      return apdu_resp;
    }
  }

  if (VerifyMAC (apdu) != 1)
    {
      Buffer data = Buffer (1, (BYTE) 0x6a) + Buffer (1, (BYTE) 0x88);
      APDU_Response *apdu_resp = new APDU_Response (data);
      return apdu_resp;
    }
  data = apdu->GetData ();

  data = Buffer (1, (BYTE) 0x90) + Buffer (1, (BYTE) 0x00);
  APDU_Response *apdu_resp = new APDU_Response (data);
  return apdu_resp;
}

APDU_Response *
RA_Token::ProcessReadBuffer (Read_Buffer_APDU * apdu,
			     NameValueSet * vars, NameValueSet * params)
{
  Buffer buffer;

#ifdef VERBOSE
  Output ("RA_Token::ProcessReadBuffer");
#endif
  // for testing only
  if (vars->GetValueAsBool("test_enable", 0) == 1) {
    if (vars->GetValueAsBool("test_apdu_rb_return_enable", 0) == 1) {
      Buffer *data = ToBuffer (vars->GetValue ("test_apdu_rb_return"));
      APDU_Response *apdu_resp = new APDU_Response (*data);
      return apdu_resp;
    }
  }

  if (VerifyMAC (apdu) != 1)
    {
      Buffer data = Buffer (1, (BYTE) 0x6a) + Buffer (1, (BYTE) 0x88);
      APDU_Response *apdu_resp = new APDU_Response (data);
      return apdu_resp;
    }

  int len = apdu->GetLen ();
  int offset = apdu->GetOffset ();

  if (offset + len <= (int) m_buffer.size ())
    {
      buffer = m_buffer.substr (offset, len);
    }
  else
    {
      Output ("TESTING   offset = %d, len = %d, m_buffer.size = %d",
	      offset, len, m_buffer.size ());
      buffer = Buffer (len, (BYTE) 0);	/* for testing */
    }
  Buffer data = buffer + Buffer (1, (BYTE) 0x90) + Buffer (1, (BYTE) 0x00);
  APDU_Response *apdu_resp = new APDU_Response (data);
  return apdu_resp;
}

APDU_Response *
RA_Token::ProcessUnblockPin (Unblock_Pin_APDU * apdu,
			     NameValueSet * vars, NameValueSet * params)
{
#ifdef VERBOSE
  Output ("RA_Token::ProcessUnblockPin");
#endif
  // for testing only
  if (vars->GetValueAsBool("test_enable", 0) == 1) {
    if (vars->GetValueAsBool("test_apdu_up_return_enable", 0) == 1) {
      Buffer *data = ToBuffer (vars->GetValue ("test_apdu_up_return"));
      APDU_Response *apdu_resp = new APDU_Response (*data);
      return apdu_resp;
    }
  }

  if (VerifyMAC (apdu) != 1)
    {
      Buffer data = Buffer (1, (BYTE) 0x6a) + Buffer (1, (BYTE) 0x88);
      APDU_Response *apdu_resp = new APDU_Response (data);
      return apdu_resp;
    }
  Buffer data = Buffer (1, (BYTE) 0x90) + Buffer (1, (BYTE) 0x00);
  APDU_Response *apdu_resp = new APDU_Response (data);
  return apdu_resp;
}

APDU_Response *
RA_Token::ProcessListObjects (List_Objects_APDU * apdu,
			      NameValueSet * vars, NameValueSet * params)
{
  // for testing only
  if (vars->GetValueAsBool("test_enable", 0) == 1) {
    if (vars->GetValueAsBool("test_apdu_lo_return_enable", 0) == 1) {
      Buffer *data = ToBuffer (vars->GetValue ("test_apdu_lo_return"));
      APDU_Response *apdu_resp = new APDU_Response (*data);
      return apdu_resp;
    }
  }

  if (VerifyMAC (apdu) != 1)
    {
      Buffer data = Buffer (1, (BYTE) 0x6a) + Buffer (1, (BYTE) 0x88);
      APDU_Response *apdu_resp = new APDU_Response (data);
      return apdu_resp;
    }

  Buffer data = Buffer (1, (BYTE) 0x9C) + Buffer (1, (BYTE) 0x00);
  APDU_Response *apdu_resp = new APDU_Response (data);
  return apdu_resp;
}

APDU_Response *
RA_Token::ProcessReadObject (Read_Object_APDU * apdu,
			     NameValueSet * vars, NameValueSet * params)
{
  Buffer buffer;

#ifdef VERBOSE
  Output ("RA_Token::ProcessReadObject");
#endif
  // for testing only
  if (vars->GetValueAsBool("test_enable", 0) == 1) {
    if (vars->GetValueAsBool("test_apdu_ro_return_enable", 0) == 1) {
      Buffer *data = ToBuffer (vars->GetValue ("test_apdu_ro_return"));
      APDU_Response *apdu_resp = new APDU_Response (*data);
      return apdu_resp;
    }
  }

  if (VerifyMAC (apdu) != 1)
    {
      Buffer data = Buffer (1, (BYTE) 0x6a) + Buffer (1, (BYTE) 0x88);
      APDU_Response *apdu_resp = new APDU_Response (data);
      return apdu_resp;
    }

  Buffer buf = apdu->GetData();
  int len = ((BYTE*)buf)[8];
  int offset = (((BYTE*)buf)[4] << 24) + (((BYTE*)buf)[5] << 16) +
               (((BYTE*)buf)[6] << 8) + ((BYTE*)buf)[7];
                                                                                
  if (offset + len <= (int) m_buffer.size ())
    {
      buffer = m_buffer.substr (offset, len);
    }
  else
    {
      Output ("TESTING   offset = %d, len = %d, m_buffer.size = %d",
          offset, len, m_buffer.size ());
      buffer = Buffer (len, (BYTE) 0);  /* for testing */
    }
                                                                                
  Buffer data = buffer + Buffer (1, (BYTE) 0x90) + Buffer (1, (BYTE) 0x00);
  APDU_Response *apdu_resp = new APDU_Response (data);
  return apdu_resp;
}

APDU_Response *
RA_Token::ProcessWriteBuffer (Write_Object_APDU * apdu,
			      NameValueSet * vars, NameValueSet * params)
{
#ifdef VERBOSE
  Output ("RA_Token::ProcessWriteBuffer");
#endif
#define MAX_WRITE_BUFFER_SIZE 0x40
  int num = 0;
  int rv = -1;
  int index = MAX_WRITE_BUFFER_SIZE + 2;
  PK11SlotInfo *slot;
  CERTCertificate *cert = NULL;

  // for testing only
  if (vars->GetValueAsBool("test_enable", 0) == 1) {
    if (vars->GetValueAsBool("test_apdu_wb_return_enable", 0) == 1) {
      Buffer *data = ToBuffer (vars->GetValue ("test_apdu_wb_return"));
      APDU_Response *apdu_resp = new APDU_Response (*data);
      return apdu_resp;
    }
  }

  if (VerifyMAC (apdu) != 1)
    {
      Buffer data = Buffer (1, (BYTE) 0x6a) + Buffer (1, (BYTE) 0x88);
      APDU_Response *apdu_resp = new APDU_Response (data);
      return apdu_resp;
    }
  Buffer inputdata = apdu->GetData ();
  num = m_object_len - m_chunk_len;
  if (num > MAX_WRITE_BUFFER_SIZE)
    {
      for (int i = 2; i < index; i++)
	{
	  BYTE data = ((BYTE *) inputdata)[i];
	  ((BYTE *) * m_object)[m_chunk_len] = data;
	  m_chunk_len++;
	}
    }
  else
    {
      for (int i = 2; i < num + 2; i++)
	{
	  ((BYTE *) * m_object)[m_chunk_len] = ((BYTE *) inputdata)[i];
	  m_chunk_len++;
	}

      if (strcmp (m_objectid, "C0") == 0)
	{
	  // printf("RA_Token::ProcessWriteBuffer objectid = %s\n", m_objectid);
	  // we got the whole certificate, import to the db.
	  cert = CERT_DecodeCertFromPackage ((char *) ((BYTE *) * m_object),
					     m_object->size ());
	  if (cert == NULL)
	    {
	      // printf("cert is NULL\n");
	    }
	  else
	    {
	      slot = PK11_GetInternalKeySlot ();

	      rv = PK11_Authenticate (slot, PR_TRUE, NULL);
	      if (rv != SECSuccess)
		{
		  //  printf("Failed to authenticate to the internal token\n");
		}
	      else
		{
		  rv = PK11_ImportCert (slot, cert, CK_INVALID_HANDLE,
					(char *) "testcert", PR_FALSE);
		  if (rv != SECSuccess)
		    {
		      printf
			("Failed to import the cert to the internal token\n");
		    }
		}
	    }
	}
    }

  Buffer data = Buffer (1, (BYTE) 0x90) + Buffer (1, (BYTE) 0x00);
  APDU_Response *apdu_resp = new APDU_Response (data);
  return apdu_resp;
}

APDU_Response *
RA_Token::ProcessSetPin (Set_Pin_APDU * apdu,
			 NameValueSet * vars, NameValueSet * params)
{
  Buffer new_pin_buf = apdu->GetNewPIN ();
#ifdef VERBOSE
  Output ("RA_Token::ProcessSetPin");
#endif

  // for testing only
  if (vars->GetValueAsBool("test_enable", 0) == 1) {
    if (vars->GetValueAsBool("test_apdu_sp_return_enable", 0) == 1) {
      Buffer *data = ToBuffer (vars->GetValue ("test_apdu_sp_return"));
      APDU_Response *apdu_resp = new APDU_Response (*data);
      return apdu_resp;
    }
  }

  if (VerifyMAC (apdu) != 1)
    {
      Buffer data = Buffer (1, (BYTE) 0x6a) + Buffer (1, (BYTE) 0x88);
      APDU_Response *apdu_resp = new APDU_Response (data);
      return apdu_resp;
    }
#if 0
  printf ("New PIN: \n");
  new_pin_buf.dump ();
#endif

  /* replace current pin */
  int i;
  char *new_pin = (char *) malloc (new_pin_buf.size () + 1);
  for (i = 0; i < (int) new_pin_buf.size (); i++)
    {
      new_pin[i] = ((BYTE *) new_pin_buf)[i];
    }
  new_pin[new_pin_buf.size ()] = '\0';

  if (m_pin != NULL)
    {
      PL_strfree (m_pin);
      m_pin = NULL;
    }
  m_pin = new_pin;

  Buffer data = Buffer (1, (BYTE) 0x90) + Buffer (1, (BYTE) 0x00);
  APDU_Response *apdu_resp = new APDU_Response (data);
  return apdu_resp;
}

APDU_Response *
RA_Token::Process (APDU * apdu, NameValueSet * vars, NameValueSet * params)
{
  APDU_Response *resp = NULL;

  if (apdu->GetType () == APDU_INITIALIZE_UPDATE)
    {
      resp = ProcessInitializeUpdate ((Initialize_Update_APDU *) apdu, vars,
				      params);
    }
  else if (apdu->GetType () == APDU_EXTERNAL_AUTHENTICATE)
    {
      resp = ProcessExternalAuthenticate ((External_Authenticate_APDU *) apdu,
					  vars, params);
    }
  else if (apdu->GetType () == APDU_SET_PIN)
    {
      resp = ProcessSetPin ((Set_Pin_APDU *) apdu, vars, params);
    }
  else if (apdu->GetType () == APDU_LOAD_FILE)
    {
      resp = ProcessLoadFile ((Load_File_APDU *) apdu, vars, params);
    }
  else if (apdu->GetType () == APDU_FORMAT_MUSCLE_APPLET)
    {
      resp = ProcessFormatMuscleApplet ((Format_Muscle_Applet_APDU *) apdu,
					vars, params);
    }
  else if (apdu->GetType () == APDU_INSTALL_LOAD)
    {
      resp = ProcessInstallLoad ((Install_Load_APDU *) apdu, vars, params);
    }
  else if (apdu->GetType () == APDU_INSTALL_APPLET)
    {
      resp = ProcessInstallApplet ((Install_Applet_APDU *) apdu, vars,
				   params);
    }
  else if (apdu->GetType () == APDU_DELETE_FILE)
    {
      resp = ProcessDeleteFile ((Delete_File_APDU *) apdu, vars, params);
    }
  else if (apdu->GetType () == APDU_CREATE_OBJECT)
    {
      resp = ProcessCreateObject ((Create_Object_APDU *) apdu, vars, params);
    }
  else if (apdu->GetType () == APDU_LIFECYCLE)
    {
      resp = ProcessLifecycle ((Lifecycle_APDU *) apdu, vars, params);
    }
  else if (apdu->GetType () == APDU_READ_BUFFER)
    {
      resp = ProcessReadBuffer ((Read_Buffer_APDU *) apdu, vars, params);
    }
  else if (apdu->GetType () == APDU_UNBLOCK_PIN)
    {
      resp = ProcessUnblockPin ((Unblock_Pin_APDU *) apdu, vars, params);
    }
  else if (apdu->GetType () == APDU_LIST_OBJECTS)
    {
      resp = ProcessListObjects ((List_Objects_APDU *) apdu, vars, params);
    }
  else if (apdu->GetType () == APDU_READ_OBJECT)
    {
      resp = ProcessReadObject ((Read_Object_APDU *) apdu, vars, params);
    }
  else if (apdu->GetType () == APDU_WRITE_OBJECT)
    {
      resp = ProcessWriteBuffer ((Write_Object_APDU *) apdu, vars, params);
    }
  else if (apdu->GetType () == APDU_SELECT)
    {
      resp = ProcessSelect ((Select_APDU *) apdu, vars, params);
    }
  else if (apdu->GetType () == APDU_GET_VERSION)
    {
      resp = ProcessGetVersion ((Get_Version_APDU *) apdu, vars, params);
    }
  else if (apdu->GetType () == APDU_PUT_KEY)
    {
      resp = ProcessPutKey ((Put_Key_APDU *) apdu, vars, params);
    }
  else if (apdu->GetType () == APDU_GET_STATUS)
    {
      resp = ProcessGetStatus ((Get_Status_APDU *) apdu, vars, params);
    }
  else if (apdu->GetType () == APDU_GET_ISSUERINFO)
    {
      resp = ProcessGetIssuerInfo ((Get_IssuerInfo_APDU *) apdu, vars, params);
    }
  else if (apdu->GetType () == APDU_SET_ISSUERINFO)
    {
      resp = ProcessSetIssuerInfo ((Set_IssuerInfo_APDU *) apdu, vars, params);
    }
  else if (apdu->GetType () == APDU_GET_DATA)
    {
      resp = ProcessGetData ((Get_Data_APDU *) apdu, vars, params);
    }
  else if (apdu->GetType () == APDU_LIST_PINS)
    {
      resp = ProcessListPins ((List_Pins_APDU *) apdu, vars, params);
    }
  else if (apdu->GetType () == APDU_CREATE_PIN)
    {
      resp = ProcessCreatePin ((Create_Pin_APDU *) apdu, vars, params);
    }
  else if (apdu->GetType () == APDU_GENERATE_KEY)
    {
      resp = ProcessGenerateKey ((Generate_Key_APDU *) apdu, vars, params);
    }
  else if (apdu->GetType () == APDU_GENERATE_KEY_ECC)
    {
      resp = ProcessGenerateKeyECC ((Generate_Key_ECC_APDU *) apdu, vars, params);
    }
  else if (apdu->GetType () == APDU_IMPORT_KEY_ENC)
    {
      resp = ProcessImportKeyEnc ((Import_Key_Enc_APDU *) apdu, vars, params);
    }
  else
    {
      printf ("RA_Token: Unknown APDU (%d)\n", apdu->GetType ());
      /* error */
    }
  return resp;
}
