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
#include "prmem.h"
#include "pk11func.h"
#include "zlib.h"
#include "engine/RA.h"
#include "main/Buffer.h"
#include "main/PKCS11Obj.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

PKCS11Obj::PKCS11Obj ()
{
	for (int i = 0; i < MAX_OBJECT_SPEC; i++) {
			m_objSpec[i] = NULL;
	}
}

PKCS11Obj::~PKCS11Obj ()
{
	for (int i = 0; i < MAX_OBJECT_SPEC; i++) {
		if (m_objSpec[i] != NULL) {
			delete m_objSpec[i];
			m_objSpec[i] = NULL;
		}
	}
}

PKCS11Obj *PKCS11Obj::Parse(Buffer *b, int offset)
{
	PKCS11Obj *o = new PKCS11Obj();

	unsigned short formatVersion = (((BYTE *)*b)[offset + 0] << 8) + 
		(((BYTE *)*b)[offset + 1]);
	o->SetFormatVersion(formatVersion);
	unsigned short objectVersion = (((BYTE *)*b)[offset + 2] << 8) + 

		(((BYTE *)*b)[offset + 3]);
	o->SetObjectVersion(objectVersion);
	o->SetCUID(b->substr(offset + 4, 10));

	unsigned short compressionType = 
		(((BYTE *)*b)[offset + 14] << 8) + (((BYTE *)*b)[offset + 15]);
	unsigned short compressedDataSize = 
		(((BYTE *)*b)[offset + 16] << 8) + (((BYTE *)*b)[offset + 17]);
#if 0
	unsigned short compressedDataOffset = 
		(unsigned short)(((unsigned char *)*b)[offset + 18] << 8) + (((unsigned char *)*b)[offset + 19]);
#endif

	Buffer data;
       	if (compressionType == 0) { /* no compression */
           data = b->substr(offset + 20, compressedDataSize);
       	} else if (compressionType == 1) { /* zlib */
           Buffer compressedData = b->substr(offset + 20, compressedDataSize);

#define MAX_UNCOMPRESS_SIZE 20000
	   unsigned char buf[MAX_UNCOMPRESS_SIZE];
	   int len = MAX_UNCOMPRESS_SIZE;
           uncompress((Bytef*)buf, (uLongf*)&len, 
			   (Bytef*)((BYTE*)compressedData), 
			   (uLong)compressedData.size());
	   data = Buffer(buf, len);
       	} else {
		/* error */
       	}


	unsigned short objOffset = (((BYTE *)data)[0] << 8) + 
		((BYTE *)data)[1];
	unsigned short objCount = (((BYTE *)data)[2] << 8) + 
		((BYTE *)data)[3];
	Buffer tokenName = data.substr(5, ((BYTE *)data)[4]);
	o->SetTokenName(tokenName);


	int curpos = (int)objOffset;
	int nread = 0;
	for (int i = 0; i < objCount; i++) {
		ObjectSpec *objSpec = ObjectSpec::Parse(&data, curpos, &nread);
		o->AddObjectSpec(objSpec);

		unsigned long oid = objSpec->GetObjectID();
		char b[2];
		b[0] = (char)((oid >> 24) & 0xff);
		b[1] = (char)((oid >> 16) & 0xff);
		
		// add corresponding 'C' object for 'c'
	        if (b[0] == 'c') { 
			for (int j = 0; j < objSpec->GetAttributeSpecCount();
						j++) {
				AttributeSpec *as = objSpec->GetAttributeSpec(j);
				if (as->GetAttributeID() == CKA_VALUE) {
				  if (as->GetType() == (BYTE) 0) {
                                        Buffer cert = as->GetValue();

					unsigned long certid = 
						('C' << 24) + (b[1] << 16);
					ObjectSpec *certSpec = 
						ObjectSpec::ParseFromTokenData(
						certid, &cert);
					o->AddObjectSpec(certSpec);

					objSpec->RemoveAttributeSpec(j);
					break;
				  }
				}
			}

		}	

		Buffer objSpecData = objSpec->GetData();
		curpos += nread;
	}

	return o;
}


void PKCS11Obj::SetFormatVersion(unsigned short v)
{
	m_formatVersion = v;
}

void PKCS11Obj::SetObjectVersion(unsigned short v)
{
	m_objectVersion = v;
}

unsigned short PKCS11Obj::GetFormatVersion()
{
	return m_formatVersion;
}

unsigned short PKCS11Obj::GetObjectVersion()
{
	return m_objectVersion;
}

void PKCS11Obj::SetCUID(Buffer CUID)
{
	m_CUID = CUID;
}

Buffer PKCS11Obj::GetCUID()
{
	return m_CUID;
}

void PKCS11Obj::SetTokenName(Buffer tokenName)
{
	m_tokenName = tokenName;
}

Buffer PKCS11Obj::GetTokenName()
{
	return m_tokenName;
}

int PKCS11Obj::GetObjectSpecCount()
{
	for (int i = 0; i < MAX_OBJECT_SPEC; i++) {
		if (m_objSpec[i] == NULL) {
			return i;
		}
	}
        return 0;
}

ObjectSpec *PKCS11Obj::GetObjectSpec(int p)
{
	if (p < MAX_OBJECT_SPEC) {
		if (m_objSpec[p] != NULL) {
			return m_objSpec[p];
		}
	}
        return NULL;
}

void PKCS11Obj::AddObjectSpec(ObjectSpec *p)
{
        for (int i = 0; i < MAX_OBJECT_SPEC; i++) {
		if (m_objSpec[i] == NULL) {
			m_objSpec[i] = p;
			return;
		} else {
			// check duplicated
		        if (p->GetObjectID() == m_objSpec[i]->GetObjectID()) {
				delete m_objSpec[i];
				m_objSpec[i] = p;
				return;
			}	
		}
	}
}

void PKCS11Obj::RemoveObjectSpec(int p)
{
	if (p < MAX_OBJECT_SPEC) {
		if (m_objSpec[p] != NULL) {
			delete m_objSpec[p];
			m_objSpec[p] = NULL;
		}
		// fill hole
		int empty = p;
	        for (int x = p+1; x < MAX_OBJECT_SPEC; x++) {
			if (m_objSpec[x] != NULL) {
				m_objSpec[empty] = m_objSpec[x];
				m_objSpec[x] = NULL;
				empty++;
			}
		}	
	}
}

Buffer PKCS11Obj::GetData()
{
	Buffer data = Buffer();

	unsigned short objectOffset = m_tokenName.size() + 2 + 3;
	data += Buffer(1, (objectOffset >> 8) & 0xff);
	data += Buffer(1, objectOffset & 0xff);
	unsigned short objectCount = GetObjectSpecCount();
	unsigned short objectCountX = objectCount;
	if (objectCountX == 0) {
		objectCountX = 0;
	} else {
		objectCountX = objectCountX - (objectCountX / 4);
	}
	data += Buffer(1, (objectCountX >> 8) & 0xff);
	data += Buffer(1, objectCountX & 0xff);
	data += Buffer(1, m_tokenName.size() & 0xff);
	data += m_tokenName;
	for (int i = 0; i < objectCount; i++) {
	    ObjectSpec *spec = GetObjectSpec(i);
	    unsigned long objectID = spec->GetObjectID();
	    char c = (char)((objectID >> 24) & 0xff);
	    unsigned long fixedAttrs = spec->GetFixedAttributes();
	    unsigned int xclass = (fixedAttrs & 0x70) >> 4;
	    unsigned int id = (fixedAttrs & 0x0f);
	    /* locate all certificate objects */
	    if (c == 'c' && xclass == CKO_CERTIFICATE) {
		/* locate the certificate object */
	        for (int u = 0; u < objectCount; u++) {
	    		ObjectSpec *u_spec = GetObjectSpec(u);
	    		unsigned long u_objectID = u_spec->GetObjectID();
	    		char u_c = (char)((u_objectID >> 24) & 0xff);
	    		unsigned long u_fixedAttrs = 
				u_spec->GetFixedAttributes();
	    		unsigned int u_xclass = (u_fixedAttrs & 0x70) >> 4;
	    		unsigned int u_id = (u_fixedAttrs & 0x0f);
	    		if (u_c == 'C' && u_xclass == CKO_CERTIFICATE && u_id == id) {
	    			AttributeSpec * u_attr = 
					u_spec->GetAttributeSpec(0);
	    		AttributeSpec * n_attr = new AttributeSpec();
                n_attr->SetAttributeID(u_attr->GetAttributeID());
                n_attr->SetType(u_attr->GetType());
                n_attr->SetData(u_attr->GetValue());
				spec->AddAttributeSpec(n_attr);
			}
		}

	    	data += spec->GetData();

		/* locate public object */
	        for (int x = 0; x < objectCount; x++) {
	    		ObjectSpec *x_spec = GetObjectSpec(x);
	    		unsigned long x_fixedAttrs = 
				x_spec->GetFixedAttributes();
	    		unsigned int x_xclass = (x_fixedAttrs & 0x70) >> 4;
	    		unsigned int x_id = (x_fixedAttrs & 0x0f);
	    		if (x_xclass == CKO_PUBLIC_KEY && x_id == id) {
	    			data += x_spec->GetData();
			}
		}

		/* locate private object */
	        for (int y = 0; y < objectCount; y++) {
	    		ObjectSpec *y_spec = GetObjectSpec(y);
	    		unsigned long y_fixedAttrs = 
				y_spec->GetFixedAttributes();
	    		unsigned int y_xclass = (y_fixedAttrs & 0x70) >> 4;
	    		unsigned int y_id = (y_fixedAttrs & 0x0f);
	    		if (y_xclass == CKO_PRIVATE_KEY && y_id == id) {
	    			data += y_spec->GetData();
			}
		}
	    }
	}

	Buffer header = Buffer();
	header += Buffer(1, (m_formatVersion >> 8) & 0xff);
	header += Buffer(1, m_formatVersion & 0xff);
	header += Buffer(1, (m_objectVersion >> 8) & 0xff);
	header += Buffer(1, m_objectVersion & 0xff);
	header += m_CUID;
	// COMP_NONE = 0x00
	// COMP_ZLIB = 0x01
	unsigned short compressionType = 0x00;
	header += Buffer(1, (compressionType >> 8) & 0xff);
	header += Buffer(1, compressionType & 0xff);
	unsigned short compressedDataSize = data.size();
	header += Buffer(1, (compressedDataSize >> 8) & 0xff);
	header += Buffer(1, compressedDataSize & 0xff);
	unsigned short compressedDataOffset = 20;
	header += Buffer(1, (compressedDataOffset >> 8) & 0xff);
	header += Buffer(1, compressedDataOffset & 0xff);

	return header + data;
}

Buffer PKCS11Obj::GetCompressedData()
{
	Buffer data = Buffer();

	unsigned short objectOffset = m_tokenName.size() + 2 + 3;
	data += Buffer(1, (objectOffset >> 8) & 0xff);
	data += Buffer(1, objectOffset & 0xff);
	unsigned short objectCount = GetObjectSpecCount();
	unsigned short objectCountX = objectCount;
	if (objectCountX == 0) {
		objectCountX = 0;
	} else {
		objectCountX = objectCountX - (objectCountX / 4);
	}
	data += Buffer(1, (objectCountX >> 8) & 0xff);
	data += Buffer(1, objectCountX & 0xff);
	data += Buffer(1, m_tokenName.size() & 0xff);
	data += m_tokenName;

	for (int i = 0; i < objectCount; i++) {
	    ObjectSpec *spec = GetObjectSpec(i);
	    unsigned long objectID = spec->GetObjectID();
	    char c = (char)((objectID >> 24) & 0xff);
	    unsigned long fixedAttrs = spec->GetFixedAttributes();
	    unsigned int xclass = (fixedAttrs & 0x70) >> 4;
	    unsigned int id = (fixedAttrs & 0x0f);
	    /* locate all certificate objects */
	    if (c == 'c' && xclass == CKO_CERTIFICATE) {

		/* locate the certificate object */
	        for (int u = 0; u < objectCount; u++) {
	    		ObjectSpec *u_spec = GetObjectSpec(u);
	    		unsigned long u_objectID = u_spec->GetObjectID();
	    		char u_c = (char)((u_objectID >> 24) & 0xff);
	    		unsigned long u_fixedAttrs = 
				u_spec->GetFixedAttributes();
	    		unsigned int u_xclass = (u_fixedAttrs & 0x70) >> 4;
	    		unsigned int u_id = (u_fixedAttrs & 0x0f);
	    		if (u_c == 'C' && u_xclass == CKO_CERTIFICATE && u_id == id) {
	    			AttributeSpec * u_attr = 
					u_spec->GetAttributeSpec(0);
	    		AttributeSpec * n_attr = new AttributeSpec();
                n_attr->SetAttributeID(u_attr->GetAttributeID());
                n_attr->SetType(u_attr->GetType());
                n_attr->SetData(u_attr->GetValue());
				spec->AddAttributeSpec(n_attr);
			}
		}

		/* output certificate attribute object */
	    	data += spec->GetData();

		/* locate public object */
	        for (int x = 0; x < objectCount; x++) {
	    		ObjectSpec *x_spec = GetObjectSpec(x);
	    		unsigned long x_fixedAttrs = 
				x_spec->GetFixedAttributes();
	    		unsigned int x_xclass = (x_fixedAttrs & 0x70) >> 4;
	    		unsigned int x_id = (x_fixedAttrs & 0x0f);
	    		if (x_xclass == CKO_PUBLIC_KEY && x_id == id) {
	    			data += x_spec->GetData();
			}
		}

		/* locate private object */
	        for (int y = 0; y < objectCount; y++) {
	    		ObjectSpec *y_spec = GetObjectSpec(y);
	    		unsigned long y_fixedAttrs = 
				y_spec->GetFixedAttributes();
	    		unsigned int y_xclass = (y_fixedAttrs & 0x70) >> 4;
	    		unsigned int y_id = (y_fixedAttrs & 0x0f);
	    		if (y_xclass == CKO_PRIVATE_KEY && y_id == id) {
	    			data += y_spec->GetData();
			}
		}
	    }
	}

#define MAX_COMPRESS_SIZE 50000
	char buffer[MAX_COMPRESS_SIZE];
	unsigned long len = MAX_COMPRESS_SIZE ;

    int rc = 0;
  
    RA::Debug("PKCS11Obj", "before compress length = %d", len);

    BYTE *src_buffer = (BYTE*)data;

    RA::Debug("PKCS11Obj", "sizeof src_buffer = %d", sizeof(src_buffer));
    RA::Debug("PKCS11Obj", "data size = %d", data.size());

    rc = compress((Bytef*)buffer, (uLongf*)&len, (Bytef*)src_buffer,
               (uLong)data.size());

    RA::Debug("PKCS11Obj", "after compress length = %d", len);
    RA::Debug("PKCS11Obj", "rc = %d", rc);

	Buffer compressedData = Buffer((BYTE*)buffer, len);

	Buffer header = Buffer();
	header += Buffer(1, (m_formatVersion >> 8) & 0xff);
	header += Buffer(1, m_formatVersion & 0xff);
	header += Buffer(1, (m_objectVersion >> 8) & 0xff);
	header += Buffer(1, m_objectVersion & 0xff);
	header += m_CUID;
	// COMP_NONE = 0x00
	// COMP_ZLIB = 0x01
	unsigned short compressionType = 0x01;
	header += Buffer(1, (compressionType >> 8) & 0xff);
	header += Buffer(1, compressionType & 0xff);
	unsigned short compressedDataSize = compressedData.size();
	header += Buffer(1, (compressedDataSize >> 8) & 0xff);
	header += Buffer(1, compressedDataSize & 0xff);
	unsigned short compressedDataOffset = 20;
	header += Buffer(1, (compressedDataOffset >> 8) & 0xff);
	header += Buffer(1, compressedDataOffset & 0xff);

	return header + compressedData;
}

