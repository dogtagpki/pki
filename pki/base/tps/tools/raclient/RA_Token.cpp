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

//#define VERIFY_PROOF

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
  m_msn = msn;
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
Sign (SECKEYPrivateKey * privKey, Buffer & blob)
{
  SECStatus status;

  SECItem sigitem;
  int signature_len;

  signature_len = PK11_SignatureLen (privKey);
  sigitem.len = signature_len;
  sigitem.data = (unsigned char *) PORT_Alloc (signature_len);

  status = SEC_SignData (&sigitem, (BYTE *) blob, blob.size (), privKey,
			 SEC_OID_ISO_SHA_WITH_RSA_SIGNATURE);
  if (status != SECSuccess)
    {
      printf ("Signing error\n");
      if (sigitem.data != NULL)
	{
	  PORT_Free (sigitem.data);
	  sigitem.data = NULL;
	}
      return Buffer (16, (BYTE) 0);	// sucks
    }

  Buffer proof = Buffer (sigitem.data, signature_len);
  if (sigitem.data != NULL)
    {
      PORT_Free (sigitem.data);
      sigitem.data = NULL;
    }
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
  return data;
}

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
      privKey = PK11_GenerateKeyPair (slot, mechanism,
				      x_params, &pubKey,
				      PR_FALSE /*isPerm */ ,
				      PR_TRUE /*isSensitive */ ,
				      NULL /*wincx */ );
      if (privKey == NULL)
	{
	  // printf("privKey == NULL\n");
	  buffer_size = 1024;	/* testing */
	}
      else
	{

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
	  Buffer proof = Sign (privKey, data_blob);
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

	  m_buffer =
	    Buffer (1, (BYTE) blob.size () / 256) +
	    Buffer (1, (BYTE) blob.size () % 256) +
	    Buffer (blob) +
	    Buffer (1, (BYTE) proof.size () / 256) +
	    Buffer (1, (BYTE) proof.size () % 256) + Buffer (proof);
	  buffer_size = m_buffer.size ();
	}			// if private key not NULL

    }
  else
    {
      // fake key
      BYTE fake_key[] = {
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
      m_buffer = Buffer ((BYTE *) fake_key, sizeof fake_key);
      buffer_size = m_buffer.size ();
    }


  Buffer data = Buffer (1, (BYTE) (buffer_size >> 8) & 0xff) +	// key length
    Buffer (1, (BYTE) buffer_size & 0xff) +	// key length 
    Buffer (1, (BYTE) 0x90) + Buffer (1, (BYTE) 0x00);
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

  Buffer data =
    Buffer (1, (BYTE) m_major_version) + Buffer (1, (BYTE) m_minor_version) +
    Buffer (1, (BYTE) 0x00) + Buffer (1, (BYTE) 0x00) +
    Buffer (1, (BYTE) 0x01) + Buffer (1, (BYTE) 0x00) +
    Buffer (1, (BYTE) 0x01) + Buffer (1, (BYTE) 0x00) +
    Buffer (1, (BYTE) 0x01) + Buffer (1, (BYTE) 0x00) +
    Buffer (1, (BYTE) 0x01) + Buffer (1, (BYTE) 0x00) +
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
