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
package com.netscape.cmsutil.xml;
import org.w3c.dom.*;
import org.xml.sax.*;
import org.apache.xerces.parsers.DOMParser;
import org.apache.xerces.dom.*;
import javax.xml.parsers.*;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.util.*;

public class XMLObject
{
    private Document mDoc = null;

    public XMLObject() throws ParserConfigurationException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder docBuilder = factory.newDocumentBuilder();
        mDoc = docBuilder.newDocument();
    }

    public XMLObject(InputStream s) 
      throws SAXException, IOException, ParserConfigurationException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder docBuilder = factory.newDocumentBuilder();
        mDoc = docBuilder.parse(s);
    }

    public XMLObject(File f) 
      throws SAXException, IOException, ParserConfigurationException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder docBuilder = factory.newDocumentBuilder();
        mDoc = docBuilder.parse(f);
    }

    public Document getDocument() {
        return mDoc;
    }

    /**
     * Each document should have 1 root only. This method should be called once.
     */
    public Node createRoot(String name) {
        Element root = mDoc.createElement(name);
        mDoc.appendChild(root);
        return (Node)root;
    }

    public Node getRoot() {
        return mDoc.getFirstChild();
    }

    /** 
     * If you have duplicate containers, then this method will return the
     * first container in the list.
     */
    public Node getContainer(String tagname) {
        NodeList list = mDoc.getElementsByTagName(tagname);
        if (list.getLength() > 0)
            return list.item(0);
        return null;
    }

    public Node createContainer(Node containerParent, String containerName) {
        Element node = mDoc.createElement(containerName);
        containerParent.appendChild(node);
        return (Node)node;
    }

    public void addItemToContainer(Node container, String tagname, String value) {
        Element node = mDoc.createElement(tagname);
        Text text = mDoc.createTextNode(value);
        node.appendChild(text);
        container.appendChild(node);
    }

    public String getValue(String tagname) {
        Node n = getContainer(tagname); 

        if (n != null) {
            NodeList c = n.getChildNodes();
            if (c.getLength() == 0)
                return null;
            Node item = c.item(0);
            return item.getNodeValue();
        }

        return null;
    }

    public Vector getAllValues(String tagname) {
        Vector v = new Vector();
        NodeList nodes = mDoc.getElementsByTagName(tagname);
        for (int i=0; i<nodes.getLength(); i++) {
            Node n = nodes.item(i);
            NodeList c = n.getChildNodes();
            if (c.getLength() > 0) {
                Node nn = c.item(0);
                if (nn.getNodeType() == Node.TEXT_NODE)
                    v.addElement(nn.getNodeValue());
            }
        }
        return v;
    }

    public Vector getValuesFromContainer(Node container, String tagname) {
        Vector v = new Vector();
        NodeList c = container.getChildNodes();
        int len = c.getLength();
        for (int i=0; i<len; i++) {
            Node subchild = c.item(i);
            if (subchild.getNodeName().equals(tagname)) {
                NodeList grandchildren = subchild.getChildNodes();
                if (grandchildren.getLength() > 0) {
                    Node grandchild = grandchildren.item(0);
                    if (grandchild.getNodeType() == Node.TEXT_NODE)
                        v.addElement(grandchild.getNodeValue());
                }
            }
        }

        return v;
    }

    public byte[] toByteArray() throws TransformerConfigurationException, TransformerException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        TransformerFactory tranFactory = TransformerFactory.newInstance();
        Transformer aTransformer = tranFactory.newTransformer();
        Source src = new DOMSource(mDoc);
        Result dest = new StreamResult(bos);
        aTransformer.transform(src, dest);
        return bos.toByteArray();
    }

    public void output(OutputStream os) 
      throws TransformerConfigurationException, TransformerException {
        TransformerFactory tranFactory = TransformerFactory.newInstance();
        Transformer aTransformer = tranFactory.newTransformer();
        Source src = new DOMSource(mDoc);
        Result dest = new StreamResult(os);
        aTransformer.transform(src, dest);
    }

    public String toXMLString() throws TransformerConfigurationException, TransformerException {
        TransformerFactory tranFactory = TransformerFactory.newInstance();
        Transformer transformer = tranFactory.newTransformer();
        Source src = new DOMSource(mDoc);
        StreamResult dest = new StreamResult(new StringWriter());
        transformer.transform(src, dest);
        String xmlString = dest.getWriter().toString();
        return xmlString;
   }
}
