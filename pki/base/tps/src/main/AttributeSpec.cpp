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
#include "main/Buffer.h"
#include "main/AttributeSpec.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

AttributeSpec::AttributeSpec ()
{
}

AttributeSpec::~AttributeSpec ()
{
}

AttributeSpec *AttributeSpec::Parse(Buffer *b, int offset)
{
	AttributeSpec *o = new AttributeSpec();
	unsigned long id = (((unsigned char *)*b)[offset+0] << 24) + 
		(((unsigned char *)*b)[offset+1] << 16) + 
		(((unsigned char *)*b)[offset+2] << 8) + 
		(((unsigned char *)*b)[offset+3]);
	o->SetAttributeID(id);
	// The following line generates the following known benign warning
	// message on Windows platforms:
	//
	//    AttributeSpec.cpp(40) : warning C4244: 'argument' : conversion
	//    from 'unsigned long' to 'unsigned char', possible loss of data
	//
	o->SetType((unsigned long)(((unsigned char *)*b)[offset+4]));
	// DatatypeString contains two bytes for AttributeLen of AttributeData
	Buffer data;
	if (o->GetType() == (BYTE) 0)
            data = b->substr(offset+5+2, b->size() - 5-2);
	else
            data = b->substr(offset+5, b->size() - 5);

	o->SetData(data);
        return o;
}

void AttributeSpec::SetAttributeID(unsigned long v)
{
	m_id = v;
}

unsigned long AttributeSpec::GetAttributeID()
{
	return m_id;
}

void AttributeSpec::SetType(BYTE v)
{
	m_type = v;
}

BYTE AttributeSpec::GetType()
{
	return m_type;
}

// sets AttributeData (for string type, contains AttributeLen+AttributeValue)
void AttributeSpec::SetData(Buffer data)
{
	m_data = data;
}

// gets AttributeData
Buffer AttributeSpec::GetValue()
{
  return m_data;
}

// gets AttributeSpec
Buffer AttributeSpec::GetData()
{
	Buffer data = Buffer();
	data += Buffer(1, (BYTE)(m_id >> 24) & 0xff);
	data += Buffer(1, (BYTE)(m_id >> 16) & 0xff);
	data += Buffer(1, (BYTE)(m_id >>  8) & 0xff);
	data += Buffer(1, (BYTE)m_id & 0xff);
	data += Buffer(1, m_type);
	if (m_type == 0) { /* String */
		data += Buffer(1, (m_data.size() >> 8) & 0xff);
		data += Buffer(1, m_data.size() & 0xff);
	}
	data += m_data;
	return data;
}

