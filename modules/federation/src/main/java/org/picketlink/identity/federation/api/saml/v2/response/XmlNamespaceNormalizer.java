package org.picketlink.identity.federation.api.saml.v2.response;

import org.picketlink.common.exceptions.ProcessingException;
import org.picketlink.common.util.DocumentUtil;
import org.picketlink.common.util.StaxUtil;
import org.w3c.dom.*;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.HashSet;
import java.util.Set;
import java.util.Stack;

/**
 * Created by spyrkob on 04/07/2017.
 */
public class XmlNamespaceNormalizer {
    public Document normalizeNS(Document source) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter writer = StaxUtil.getXMLStreamWriter(baos);

        writeDOMElement(writer, source.getDocumentElement());
        writer.flush();
        writer.close();

        return DocumentUtil.getDocument(new ByteArrayInputStream(baos.toByteArray()));
    }


    class Frame {
        Set<String> namespaces = new HashSet<>();
    }
    Stack<Frame> knownNamespaces = new Stack<>();

    public void writeDOMElement(XMLStreamWriter writer, Element domElement) throws ProcessingException {

        if (!knownNamespaces.empty()) {
            Frame frame = new Frame();
            frame.namespaces.addAll(knownNamespaces.peek().namespaces);
            knownNamespaces.push(frame);
        } else {
            knownNamespaces.add(new Frame());
        }

        String domElementPrefix = domElement.getPrefix();

        if (domElementPrefix == null) {
            domElementPrefix = "";
        }

        String domElementNS = domElement.getNamespaceURI();
        if (domElementNS == null) {
            domElementNS = "";
        }

        writeStartElement(writer, domElementPrefix, domElement.getLocalName(), domElementNS);

        if (!knownNamespaces.peek().namespaces.contains(domElementNS)) {
            knownNamespaces.peek().namespaces.add(domElementNS);
            writeNameSpace(writer, domElementPrefix, domElementNS);
        }

        if (!knownNamespaces.peek().namespaces.contains(domElementNS) && domElementPrefix == "" && domElementNS != null) {
            knownNamespaces.peek().namespaces.add(domElementNS);
            writeNameSpace(writer, "xmlns", domElementNS);
        }

        // Deal with Attributes
        NamedNodeMap attrs = domElement.getAttributes();
        for (int i = 0, len = attrs.getLength(); i < len; ++i) {
            Attr attr = (Attr) attrs.item(i);
            String attributePrefix = attr.getPrefix();
            String attribLocalName = attr.getLocalName();
            String attribValue = attr.getValue();

            if (attributePrefix == null || attributePrefix.length() == 0) {
                if (!("xmlns".equals(attribLocalName))) {
                    writeAttribute(writer, attribLocalName, attribValue);
                }
            } else {
                if (!"xmlns".equals(attributePrefix)) {
                    writeAttribute(writer, new QName(attr.getNamespaceURI(), attribLocalName, attributePrefix), attribValue);
                }
            }
        }

        for (Node child = domElement.getFirstChild(); child != null; child = child.getNextSibling()) {
            writeDOMNode(writer, child);
        }

        writeEndElement(writer);
        knownNamespaces.pop();
    }

    public void writeStartElement(XMLStreamWriter writer, String prefix, String localPart, String ns)
            throws ProcessingException {
        try {
            writer.writeStartElement(prefix, localPart, ns);
        } catch (XMLStreamException e) {
//            throw logger.processingError(e);
            throw new ProcessingException(e);
        }
    }

    public void writeEndElement(XMLStreamWriter writer) throws ProcessingException {
        try {
            writer.writeEndElement();
        } catch (XMLStreamException e) {
//            throw logger.processingError(e);
            throw new ProcessingException(e);
        }
    }

    public void writeDOMNode(XMLStreamWriter writer, Node node) throws ProcessingException {
        try {
            short nodeType = node.getNodeType();

            switch (nodeType) {
                case Node.ELEMENT_NODE:
                    writeDOMElement(writer, (Element) node);
                    break;
                case Node.TEXT_NODE:
                    writer.writeCharacters(node.getNodeValue());
                    break;
                case Node.COMMENT_NODE:
                    writer.writeComment(node.getNodeValue());
                    break;
                case Node.CDATA_SECTION_NODE:
                    writer.writeCData(node.getNodeValue());
                    break;
                default:
                    // Don't care
            }
        } catch (DOMException e) {
            //            throw logger.processingError(e);
            throw new ProcessingException(e);
        } catch (XMLStreamException e) {
            //            throw logger.processingError(e);
            throw new ProcessingException(e);
        }
    }

    public void writeAttribute(XMLStreamWriter writer, QName attributeName, String attributeValue)
            throws ProcessingException {
        try {
            writer.writeAttribute(attributeName.getPrefix(), attributeName.getNamespaceURI(), attributeName.getLocalPart(),
                    attributeValue);
        } catch (XMLStreamException e) {
            //            throw logger.processingError(e);
            throw new ProcessingException(e);
        }
    }

    public void writeAttribute(XMLStreamWriter writer, String localName, String value) throws ProcessingException {
        try {
            writer.writeAttribute(localName, value);
        } catch (XMLStreamException e) {
            //            throw logger.processingError(e);
            throw new ProcessingException(e);
        }
    }

    public void writeNameSpace(XMLStreamWriter writer, String prefix, String ns) throws ProcessingException {
        try {
            writer.writeNamespace(prefix, ns);
        } catch (XMLStreamException e) {
            //            throw logger.processingError(e);
            throw new ProcessingException(e);
        }
    }
}
