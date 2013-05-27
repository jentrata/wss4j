/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.wss4j.stax.test;

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.Attachment;
import org.apache.wss4j.common.ext.AttachmentRequestCallback;
import org.apache.wss4j.common.ext.AttachmentResultCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.AttachmentUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSEncryptionPart;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.message.WSSecEncrypt;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.stax.WSSec;
import org.apache.wss4j.stax.ext.InboundWSSec;
import org.apache.wss4j.stax.ext.OutboundWSSec;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.test.utils.StAX2DOM;
import org.apache.wss4j.stax.test.utils.XmlReaderToWriter;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.SecurePart;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.util.*;

public class AttachmentTest extends AbstractTestBase {

    private static final org.slf4j.Logger LOG =
            org.slf4j.LoggerFactory.getLogger(AttachmentTest.class);

    private Crypto crypto;

    public AttachmentTest() throws Exception {
    }

    protected Map<String, String> getHeaders(String attachmentId) {
        Map<String, String> headers = new HashMap<String, String>();
        headers.put(AttachmentUtils.MIME_HEADER_CONTENT_DESCRIPTION, "Attachment");
        headers.put(AttachmentUtils.MIME_HEADER_CONTENT_DISPOSITION, "attachment; filename=\"fname.ext\"");
        headers.put(AttachmentUtils.MIME_HEADER_CONTENT_ID, "<attachment=" + attachmentId + ">");
        headers.put(AttachmentUtils.MIME_HEADER_CONTENT_LOCATION, "http://ws.apache.org");
        headers.put(AttachmentUtils.MIME_HEADER_CONTENT_TYPE, "text/xml; charset=UTF-8");
        headers.put("TestHeader", "testHeaderValue");
        return headers;
    }

    protected byte[] readInputStream(InputStream inputStream) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        int read = 0;
        byte[] buf = new byte[4096];
        while ((read = inputStream.read(buf)) != -1) {
            byteArrayOutputStream.write(buf, 0, read);
        }
        return byteArrayOutputStream.toByteArray();
    }

    @Test
    public void testXMLAttachmentContentSignature() throws Exception {

        final String attachmentId = UUID.randomUUID().toString();
        final Attachment[] attachment = new Attachment[1];
        attachment[0] = new Attachment();
        attachment[0].setMimeType("text/xml");
        attachment[0].addHeaders(getHeaders(attachmentId));
        attachment[0].setId(attachmentId);
        attachment[0].setSourceStream(new ByteArrayInputStream(SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.SIGNATURE};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.addSignaturePart(new SecurePart(new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body"), SecurePart.Modifier.Element));
            securityProperties.addSignaturePart(new SecurePart("cid:Attachments", SecurePart.Modifier.Content));
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            securityProperties.setAttachmentCallbackHandler(new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    if (callbacks[0] instanceof AttachmentRequestCallback) {
                        AttachmentRequestCallback attachmentRequestCallback = (AttachmentRequestCallback) callbacks[0];
                        List<Attachment> attachments = new ArrayList<Attachment>();
                        attachments.add(attachment[0]);
                        attachmentRequestCallback.setAttachments(attachments);
                    } else {
                        AttachmentResultCallback attachmentResultCallback = (AttachmentResultCallback) callbacks[0];
                        attachment[0] = attachmentResultCallback.getAttachment();
                    }
                }
            });

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();
        }

        //done signature; now test sig-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setAttachmentCallbackHandler(new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    if (callbacks[0] instanceof AttachmentRequestCallback) {
                        AttachmentRequestCallback attachmentRequestCallback = (AttachmentRequestCallback) callbacks[0];

                        if (!attachment[0].getId().equals(attachmentRequestCallback.getAttachmentId())) {
                            throw new RuntimeException("wrong attachment requested");
                        }

                        List<Attachment> attachments = new ArrayList<Attachment>();
                        attachments.add(attachment[0]);
                        attachmentRequestCallback.setAttachments(attachments);
                    } else {
                        AttachmentResultCallback attachmentResultCallback = (AttachmentResultCallback) callbacks[0];
                        attachment[0] = attachmentResultCallback.getAttachment();
                    }
                }
            });

            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));
            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            NodeList sigReferences = document.getElementsByTagNameNS(WSConstants.SIG_NS, "Reference");
            Assert.assertEquals(2, sigReferences.getLength());
        }

        byte[] attachmentBytes = readInputStream(attachment[0].getSourceStream());
        Assert.assertTrue(Arrays.equals(attachmentBytes, SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));
        Assert.assertEquals("text/xml", attachment[0].getMimeType());
    }

    @Test
    public void testInvalidXMLAttachmentContentSignature() throws Exception {

        final String attachmentId = UUID.randomUUID().toString();
        final Attachment[] attachment = new Attachment[1];
        attachment[0] = new Attachment();
        attachment[0].setMimeType("text/xml");
        attachment[0].addHeaders(getHeaders(attachmentId));
        attachment[0].setId(attachmentId);
        attachment[0].setSourceStream(new ByteArrayInputStream(SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.SIGNATURE};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.addSignaturePart(new SecurePart(new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body"), SecurePart.Modifier.Element));
            securityProperties.addSignaturePart(new SecurePart("cid:Attachments", SecurePart.Modifier.Content));
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            securityProperties.setAttachmentCallbackHandler(new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    if (callbacks[0] instanceof AttachmentRequestCallback) {
                        AttachmentRequestCallback attachmentRequestCallback = (AttachmentRequestCallback) callbacks[0];
                        List<Attachment> attachments = new ArrayList<Attachment>();
                        attachments.add(attachment[0]);
                        attachmentRequestCallback.setAttachments(attachments);
                    } else {
                        AttachmentResultCallback attachmentResultCallback = (AttachmentResultCallback) callbacks[0];
                        attachment[0] = attachmentResultCallback.getAttachment();
                    }
                }
            });

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();
        }

        //done signature; now test sig-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setAttachmentCallbackHandler(new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    if (callbacks[0] instanceof AttachmentRequestCallback) {
                        AttachmentRequestCallback attachmentRequestCallback = (AttachmentRequestCallback) callbacks[0];

                        if (!attachment[0].getId().equals(attachmentRequestCallback.getAttachmentId())) {
                            throw new RuntimeException("wrong attachment requested");
                        }

                        List<Attachment> attachments = new ArrayList<Attachment>();
                        attachment[0].setSourceStream(new ByteArrayInputStream(
                                SOAPUtil.SAMPLE_SOAP_MSG.replace("15", "16").getBytes("UTF-8")));
                        attachments.add(attachment[0]);
                        attachmentRequestCallback.setAttachments(attachments);
                    } else {
                        AttachmentResultCallback attachmentResultCallback = (AttachmentResultCallback) callbacks[0];
                        attachment[0] = attachmentResultCallback.getAttachment();
                    }
                }
            });

            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));
            try {
                Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
                Assert.fail("Exception expected");
            } catch (XMLStreamException e) {
                Assert.assertTrue(e.getCause() instanceof XMLSecurityException);
                Assert.assertTrue(e.getCause().getMessage().startsWith("Invalid digest of reference cid:"));
            }
        }
    }

    @Test
    public void testXMLAttachmentCompleteSignature() throws Exception {

        final String attachmentId = UUID.randomUUID().toString();
        final Attachment[] attachment = new Attachment[1];
        attachment[0] = new Attachment();
        attachment[0].setMimeType("text/xml");
        attachment[0].addHeaders(getHeaders(attachmentId));
        attachment[0].setId(attachmentId);
        attachment[0].setSourceStream(new ByteArrayInputStream(SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.SIGNATURE};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.addSignaturePart(new SecurePart(new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body"), SecurePart.Modifier.Element));
            securityProperties.addSignaturePart(new SecurePart("cid:Attachments", SecurePart.Modifier.Element));
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            securityProperties.setAttachmentCallbackHandler(new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    if (callbacks[0] instanceof AttachmentRequestCallback) {
                        AttachmentRequestCallback attachmentRequestCallback = (AttachmentRequestCallback) callbacks[0];
                        List<Attachment> attachments = new ArrayList<Attachment>();
                        attachments.add(attachment[0]);
                        attachmentRequestCallback.setAttachments(attachments);
                    } else {
                        AttachmentResultCallback attachmentResultCallback = (AttachmentResultCallback) callbacks[0];
                        attachment[0] = attachmentResultCallback.getAttachment();
                    }
                }
            });

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();
        }

        //done signature; now test sig-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setAttachmentCallbackHandler(new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    if (callbacks[0] instanceof AttachmentRequestCallback) {
                        AttachmentRequestCallback attachmentRequestCallback = (AttachmentRequestCallback) callbacks[0];

                        if (!attachment[0].getId().equals(attachmentRequestCallback.getAttachmentId())) {
                            throw new RuntimeException("wrong attachment requested");
                        }

                        List<Attachment> attachments = new ArrayList<Attachment>();
                        attachments.add(attachment[0]);
                        attachmentRequestCallback.setAttachments(attachments);
                    } else {
                        AttachmentResultCallback attachmentResultCallback = (AttachmentResultCallback) callbacks[0];
                        attachment[0] = attachmentResultCallback.getAttachment();
                    }
                }
            });

            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));
            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            NodeList sigReferences = document.getElementsByTagNameNS(WSConstants.SIG_NS, "Reference");
            Assert.assertEquals(2, sigReferences.getLength());
        }

        byte[] attachmentBytes = readInputStream(attachment[0].getSourceStream());
        Assert.assertTrue(Arrays.equals(attachmentBytes, SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));
        Assert.assertEquals("text/xml", attachment[0].getMimeType());
    }

    @Test
    public void testInvalidXMLAttachmentCompleteSignature() throws Exception {

        final String attachmentId = UUID.randomUUID().toString();
        final Attachment[] attachment = new Attachment[1];
        attachment[0] = new Attachment();
        attachment[0].setMimeType("text/xml");
        attachment[0].addHeaders(getHeaders(attachmentId));
        attachment[0].setId(attachmentId);
        attachment[0].setSourceStream(new ByteArrayInputStream(SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.SIGNATURE};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.addSignaturePart(new SecurePart(new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body"), SecurePart.Modifier.Element));
            securityProperties.addSignaturePart(new SecurePart("cid:Attachments", SecurePart.Modifier.Element));
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            securityProperties.setAttachmentCallbackHandler(new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    if (callbacks[0] instanceof AttachmentRequestCallback) {
                        AttachmentRequestCallback attachmentRequestCallback = (AttachmentRequestCallback) callbacks[0];
                        List<Attachment> attachments = new ArrayList<Attachment>();
                        attachments.add(attachment[0]);
                        attachmentRequestCallback.setAttachments(attachments);
                    } else {
                        AttachmentResultCallback attachmentResultCallback = (AttachmentResultCallback) callbacks[0];
                        attachment[0] = attachmentResultCallback.getAttachment();
                    }
                }
            });

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();
        }

        //done signature; now test sig-verification:
        {
            attachment[0].addHeader(AttachmentUtils.MIME_HEADER_CONTENT_DESCRIPTION, "Kaputt");

            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setAttachmentCallbackHandler(new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    if (callbacks[0] instanceof AttachmentRequestCallback) {
                        AttachmentRequestCallback attachmentRequestCallback = (AttachmentRequestCallback) callbacks[0];

                        if (!attachment[0].getId().equals(attachmentRequestCallback.getAttachmentId())) {
                            throw new RuntimeException("wrong attachment requested");
                        }

                        List<Attachment> attachments = new ArrayList<Attachment>();
                        attachments.add(attachment[0]);
                        attachmentRequestCallback.setAttachments(attachments);
                    } else {
                        AttachmentResultCallback attachmentResultCallback = (AttachmentResultCallback) callbacks[0];
                        attachment[0] = attachmentResultCallback.getAttachment();
                    }
                }
            });

            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));
            try {
                Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
                Assert.fail("Exception expected");
            } catch (XMLStreamException e) {
                Assert.assertTrue(e.getCause() instanceof XMLSecurityException);
                Assert.assertTrue(e.getCause().getMessage().startsWith("Invalid digest of reference cid:"));
            }
        }
    }

    @Test
    public void testMultipleAttachmentCompleteSignature() throws Exception {

        final String attachment1Id = UUID.randomUUID().toString();
        final Attachment[] attachment = new Attachment[2];
        attachment[0] = new Attachment();
        attachment[0].setMimeType("text/xml");
        attachment[0].addHeaders(getHeaders(attachment1Id));
        attachment[0].setId(attachment1Id);
        attachment[0].setSourceStream(new ByteArrayInputStream(SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));

        final String attachment2Id = UUID.randomUUID().toString();
        attachment[1] = new Attachment();
        attachment[1].setMimeType("text/plain");
        attachment[1].addHeaders(getHeaders(attachment2Id));
        attachment[1].setId(attachment2Id);
        attachment[1].setSourceStream(new ByteArrayInputStream(SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.SIGNATURE};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.addSignaturePart(new SecurePart(new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body"), SecurePart.Modifier.Element));
            securityProperties.addSignaturePart(new SecurePart("cid:Attachments", SecurePart.Modifier.Element));
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            securityProperties.setAttachmentCallbackHandler(new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    if (callbacks[0] instanceof AttachmentRequestCallback) {
                        AttachmentRequestCallback attachmentRequestCallback = (AttachmentRequestCallback) callbacks[0];
                        List<Attachment> attachments = new ArrayList<Attachment>();
                        attachments.add(attachment[0]);
                        attachments.add(attachment[1]);
                        attachmentRequestCallback.setAttachments(attachments);
                    } else {
                        AttachmentResultCallback attachmentResultCallback = (AttachmentResultCallback) callbacks[0];
                        if (attachmentResultCallback.getAttachmentId().equals(attachment[0].getId())) {
                            attachment[0] = attachmentResultCallback.getAttachment();
                        } else {
                            attachment[1] = attachmentResultCallback.getAttachment();
                        }
                    }
                }
            });

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();
        }

        //done signature; now test sig-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setAttachmentCallbackHandler(new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    if (callbacks[0] instanceof AttachmentRequestCallback) {
                        AttachmentRequestCallback attachmentRequestCallback = (AttachmentRequestCallback) callbacks[0];

                        List<Attachment> attachments = new ArrayList<Attachment>();
                        attachmentRequestCallback.setAttachments(attachments);

                        if (attachment[0].getId().equals(attachmentRequestCallback.getAttachmentId())) {
                            attachments.add(attachment[0]);
                        } else if (attachment[1].getId().equals(attachmentRequestCallback.getAttachmentId())) {
                            attachments.add(attachment[1]);
                        } else {
                            throw new RuntimeException("invalid attachment requested");
                        }
                    } else {
                        AttachmentResultCallback attachmentResultCallback = (AttachmentResultCallback) callbacks[0];
                        if (attachmentResultCallback.getAttachmentId().equals(attachment[0].getId())) {
                            attachment[0] = attachmentResultCallback.getAttachment();
                        } else {
                            attachment[1] = attachmentResultCallback.getAttachment();
                        }
                    }
                }
            });

            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));
            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            NodeList sigReferences = document.getElementsByTagNameNS(WSConstants.SIG_NS, "Reference");
            Assert.assertEquals(3, sigReferences.getLength());
        }

        byte[] attachmentBytes = readInputStream(attachment[0].getSourceStream());
        Assert.assertTrue(Arrays.equals(attachmentBytes, SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));
        Assert.assertEquals("text/xml", attachment[0].getMimeType());
    }

    @Test
    public void testXMLAttachmentContentEncryption() throws Exception {

        final String attachmentId = UUID.randomUUID().toString();
        final Attachment[] attachment = new Attachment[1];
        attachment[0] = new Attachment();
        attachment[0].setMimeType("text/xml");
        attachment[0].addHeaders(getHeaders(attachmentId));
        attachment[0].setId(attachmentId);
        attachment[0].setSourceStream(new ByteArrayInputStream(SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.ENCRYPT};
            securityProperties.setOutAction(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.addEncryptionPart(new SecurePart(new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body"), SecurePart.Modifier.Content));
            securityProperties.addEncryptionPart(new SecurePart("cid:Attachments", SecurePart.Modifier.Content));
            securityProperties.setAttachmentCallbackHandler(new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    if (callbacks[0] instanceof AttachmentRequestCallback) {
                        AttachmentRequestCallback attachmentRequestCallback = (AttachmentRequestCallback) callbacks[0];
                        List<Attachment> attachments = new ArrayList<Attachment>();
                        attachments.add(attachment[0]);
                        attachmentRequestCallback.setAttachments(attachments);
                    } else {
                        AttachmentResultCallback attachmentResultCallback = (AttachmentResultCallback) callbacks[0];
                        attachment[0] = attachmentResultCallback.getAttachment();
                    }
                }
            });

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document securedDoc = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));

            NodeList references = securedDoc.getElementsByTagNameNS(WSConstants.ENC_NS, "DataReference");
            Assert.assertEquals(2, references.getLength());
            NodeList cipherReferences = securedDoc.getElementsByTagNameNS(WSConstants.ENC_NS, "CipherReference");
            Assert.assertEquals(1, cipherReferences.getLength());
            NodeList encDatas = securedDoc.getElementsByTagNameNS(WSConstants.ENC_NS, "EncryptedData");
            Assert.assertEquals(2, encDatas.getLength());

            NodeList securityHeaderElement = securedDoc.getElementsByTagNameNS(WSConstants.WSSE_NS, "Security");
            Assert.assertEquals(1, securityHeaderElement.getLength());
            NodeList childs = securityHeaderElement.item(0).getChildNodes();
            Assert.assertEquals(2, childs.getLength());
            Assert.assertEquals(childs.item(0).getLocalName(), "EncryptedKey");
            Assert.assertEquals(childs.item(1).getLocalName(), "EncryptedData");
        }

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            securityProperties.setAttachmentCallbackHandler(new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    if (callbacks[0] instanceof AttachmentRequestCallback) {
                        AttachmentRequestCallback attachmentRequestCallback = (AttachmentRequestCallback) callbacks[0];

                        if (!attachment[0].getId().equals(attachmentRequestCallback.getAttachmentId())) {
                            throw new RuntimeException("wrong attachment requested");
                        }

                        List<Attachment> attachments = new ArrayList<Attachment>();
                        attachments.add(attachment[0]);
                        attachmentRequestCallback.setAttachments(attachments);
                    } else {
                        AttachmentResultCallback attachmentResultCallback = (AttachmentResultCallback) callbacks[0];
                        attachment[0] = attachmentResultCallback.getAttachment();
                    }
                }
            });

            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));
            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
        }

        byte[] attachmentBytes = readInputStream(attachment[0].getSourceStream());
        Assert.assertTrue(Arrays.equals(attachmentBytes, SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));
        Assert.assertEquals("text/xml", attachment[0].getMimeType());

        Map<String, String> attHeaders = attachment[0].getHeaders();
        Assert.assertEquals(6, attHeaders.size());
    }

    @Test
    public void testInvalidXMLAttachmentContentEncryption() throws Exception {
        final String attachmentId = UUID.randomUUID().toString();
        final Attachment[] attachment = new Attachment[1];
        attachment[0] = new Attachment();
        attachment[0].setMimeType("text/xml");
        attachment[0].addHeaders(getHeaders(attachmentId));
        attachment[0].setId(attachmentId);
        attachment[0].setSourceStream(new ByteArrayInputStream(SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.ENCRYPT};
            securityProperties.setOutAction(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.addEncryptionPart(new SecurePart(new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body"), SecurePart.Modifier.Content));
            securityProperties.addEncryptionPart(new SecurePart("cid:Attachments", SecurePart.Modifier.Content));
            securityProperties.setAttachmentCallbackHandler(new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    if (callbacks[0] instanceof AttachmentRequestCallback) {
                        AttachmentRequestCallback attachmentRequestCallback = (AttachmentRequestCallback) callbacks[0];
                        List<Attachment> attachments = new ArrayList<Attachment>();
                        attachments.add(attachment[0]);
                        attachmentRequestCallback.setAttachments(attachments);
                    } else {
                        AttachmentResultCallback attachmentResultCallback = (AttachmentResultCallback) callbacks[0];
                        attachment[0] = attachmentResultCallback.getAttachment();
                    }
                }
            });

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document securedDoc = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));

            NodeList references = securedDoc.getElementsByTagNameNS(WSConstants.ENC_NS, "DataReference");
            Assert.assertEquals(2, references.getLength());
            NodeList cipherReferences = securedDoc.getElementsByTagNameNS(WSConstants.ENC_NS, "CipherReference");
            Assert.assertEquals(1, cipherReferences.getLength());
            NodeList encDatas = securedDoc.getElementsByTagNameNS(WSConstants.ENC_NS, "EncryptedData");
            Assert.assertEquals(2, encDatas.getLength());

            NodeList securityHeaderElement = securedDoc.getElementsByTagNameNS(WSConstants.WSSE_NS, "Security");
            Assert.assertEquals(1, securityHeaderElement.getLength());
            NodeList childs = securityHeaderElement.item(0).getChildNodes();
            Assert.assertEquals(2, childs.getLength());
            Assert.assertEquals(childs.item(0).getLocalName(), "EncryptedKey");
            Assert.assertEquals(childs.item(1).getLocalName(), "EncryptedData");
        }

        {
            final PushbackInputStream pis = new PushbackInputStream(attachment[0].getSourceStream(), 1);
            pis.unread('K');
            attachment[0].setSourceStream(pis);

            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            securityProperties.setAttachmentCallbackHandler(new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    if (callbacks[0] instanceof AttachmentRequestCallback) {
                        AttachmentRequestCallback attachmentRequestCallback = (AttachmentRequestCallback) callbacks[0];

                        if (!attachment[0].getId().equals(attachmentRequestCallback.getAttachmentId())) {
                            throw new RuntimeException("wrong attachment requested");
                        }

                        List<Attachment> attachments = new ArrayList<Attachment>();
                        attachments.add(attachment[0]);
                        attachmentRequestCallback.setAttachments(attachments);
                    } else {
                        AttachmentResultCallback attachmentResultCallback = (AttachmentResultCallback) callbacks[0];
                        attachment[0] = attachmentResultCallback.getAttachment();
                    }
                }
            });

            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));
            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
        }

        byte[] attachmentBytes = readInputStream(attachment[0].getSourceStream());
        Assert.assertFalse(Arrays.equals(attachmentBytes, SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));
        Assert.assertEquals("text/xml", attachment[0].getMimeType());

        Map<String, String> attHeaders = attachment[0].getHeaders();
        Assert.assertEquals(6, attHeaders.size());
    }

    @Test
    public void testXMLAttachmentContentEncryptionExternalReferenceList() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecEncrypt encrypt = new WSSecEncrypt();
        encrypt.setUserInfo("receiver", "default");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
        parts.add(new WSEncryptionPart("Body", "http://schemas.xmlsoap.org/soap/envelope/", "Content"));
        parts.add(new WSEncryptionPart("cid:Attachments", "Content"));
        encrypt.setParts(parts);

        String attachmentId = UUID.randomUUID().toString();
        final Attachment[] attachment = new Attachment[1];
        attachment[0] = new Attachment();
        attachment[0].setMimeType("text/xml");
        attachment[0].addHeaders(getHeaders(attachmentId));
        attachment[0].setId(attachmentId);
        attachment[0].setSourceStream(new ByteArrayInputStream(SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));

        encrypt.setAttachmentCallbackHandler(new CallbackHandler() {
            @Override
            public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                if (callbacks[0] instanceof AttachmentRequestCallback) {
                    AttachmentRequestCallback attachmentRequestCallback = (AttachmentRequestCallback) callbacks[0];
                    List<Attachment> attachments = new ArrayList<Attachment>();
                    attachments.add(attachment[0]);
                    attachmentRequestCallback.setAttachments(attachments);
                } else {
                    AttachmentResultCallback attachmentResultCallback = (AttachmentResultCallback) callbacks[0];
                    attachment[0] = attachmentResultCallback.getAttachment();
                }
            }
        });

        encrypt.prepare(doc, CryptoFactory.getInstance("transmitter-crypto.properties"));
        Element refs = encrypt.encryptForRef(null, parts);
        encrypt.addAttachmentEncryptedDataElements(secHeader);
        encrypt.addExternalRefElement(refs, secHeader);
        encrypt.prependToHeader(secHeader);

        NodeList references = doc.getElementsByTagNameNS(WSConstants.ENC_NS, "DataReference");
        Assert.assertEquals(2, references.getLength());
        NodeList cipherReferences = doc.getElementsByTagNameNS(WSConstants.ENC_NS, "CipherReference");
        Assert.assertEquals(1, cipherReferences.getLength());
        NodeList encDatas = doc.getElementsByTagNameNS(WSConstants.ENC_NS, "EncryptedData");
        Assert.assertEquals(2, encDatas.getLength());

        NodeList securityHeaderElement = doc.getElementsByTagNameNS(WSConstants.WSSE_NS, "Security");
        Assert.assertEquals(1, securityHeaderElement.getLength());
        NodeList childs = securityHeaderElement.item(0).getChildNodes();
        Assert.assertEquals(3, childs.getLength());
        Assert.assertEquals(childs.item(0).getLocalName(), "EncryptedKey");
        Assert.assertEquals(childs.item(1).getLocalName(), "ReferenceList");
        Assert.assertEquals(childs.item(2).getLocalName(), "EncryptedData");

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
        transformer.transform(new DOMSource(doc), new StreamResult(baos));

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            securityProperties.setAttachmentCallbackHandler(new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    if (callbacks[0] instanceof AttachmentRequestCallback) {
                        AttachmentRequestCallback attachmentRequestCallback = (AttachmentRequestCallback) callbacks[0];

                        if (!attachment[0].getId().equals(attachmentRequestCallback.getAttachmentId())) {
                            throw new RuntimeException("wrong attachment requested");
                        }

                        List<Attachment> attachments = new ArrayList<Attachment>();
                        attachments.add(attachment[0]);
                        attachmentRequestCallback.setAttachments(attachments);
                    } else {
                        AttachmentResultCallback attachmentResultCallback = (AttachmentResultCallback) callbacks[0];
                        attachment[0] = attachmentResultCallback.getAttachment();
                    }
                }
            });

            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));
            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
        }

        byte[] attachmentBytes = readInputStream(attachment[0].getSourceStream());
        Assert.assertTrue(Arrays.equals(attachmentBytes, SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));
        Assert.assertEquals("text/xml", attachment[0].getMimeType());

        Map<String, String> attHeaders = attachment[0].getHeaders();
        Assert.assertEquals(6, attHeaders.size());
    }

    @Test
    public void testXMLAttachmentCompleteEncryption() throws Exception {

        final String attachmentId = UUID.randomUUID().toString();
        final Attachment[] attachment = new Attachment[1];
        attachment[0] = new Attachment();
        attachment[0].setMimeType("text/xml");
        attachment[0].addHeaders(getHeaders(attachmentId));
        attachment[0].setId(attachmentId);
        attachment[0].setSourceStream(new ByteArrayInputStream(SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.ENCRYPT};
            securityProperties.setOutAction(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.addEncryptionPart(new SecurePart(new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body"), SecurePart.Modifier.Content));
            securityProperties.addEncryptionPart(new SecurePart("cid:Attachments", SecurePart.Modifier.Element));
            securityProperties.setAttachmentCallbackHandler(new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    if (callbacks[0] instanceof AttachmentRequestCallback) {
                        AttachmentRequestCallback attachmentRequestCallback = (AttachmentRequestCallback) callbacks[0];
                        List<Attachment> attachments = new ArrayList<Attachment>();
                        attachments.add(attachment[0]);
                        attachmentRequestCallback.setAttachments(attachments);
                    } else {
                        AttachmentResultCallback attachmentResultCallback = (AttachmentResultCallback) callbacks[0];
                        attachment[0] = attachmentResultCallback.getAttachment();
                    }
                }
            });

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document securedDoc = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));

            NodeList references = securedDoc.getElementsByTagNameNS(WSConstants.ENC_NS, "DataReference");
            Assert.assertEquals(2, references.getLength());
            NodeList cipherReferences = securedDoc.getElementsByTagNameNS(WSConstants.ENC_NS, "CipherReference");
            Assert.assertEquals(1, cipherReferences.getLength());
            NodeList encDatas = securedDoc.getElementsByTagNameNS(WSConstants.ENC_NS, "EncryptedData");
            Assert.assertEquals(2, encDatas.getLength());

            NodeList securityHeaderElement = securedDoc.getElementsByTagNameNS(WSConstants.WSSE_NS, "Security");
            Assert.assertEquals(1, securityHeaderElement.getLength());
            NodeList childs = securityHeaderElement.item(0).getChildNodes();
            Assert.assertEquals(2, childs.getLength());
            Assert.assertEquals(childs.item(0).getLocalName(), "EncryptedKey");
            Assert.assertEquals(childs.item(1).getLocalName(), "EncryptedData");

            Assert.assertEquals(1, attachment[0].getHeaders().size());
        }

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            securityProperties.setAttachmentCallbackHandler(new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    if (callbacks[0] instanceof AttachmentRequestCallback) {
                        AttachmentRequestCallback attachmentRequestCallback = (AttachmentRequestCallback) callbacks[0];

                        if (!attachment[0].getId().equals(attachmentRequestCallback.getAttachmentId())) {
                            throw new RuntimeException("wrong attachment requested");
                        }

                        List<Attachment> attachments = new ArrayList<Attachment>();
                        attachments.add(attachment[0]);
                        attachmentRequestCallback.setAttachments(attachments);
                    } else {
                        AttachmentResultCallback attachmentResultCallback = (AttachmentResultCallback) callbacks[0];
                        attachment[0] = attachmentResultCallback.getAttachment();
                    }
                }
            });

            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));
            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
        }

        byte[] attachmentBytes = readInputStream(attachment[0].getSourceStream());
        Assert.assertTrue(Arrays.equals(attachmentBytes, SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));
        Assert.assertEquals("text/xml", attachment[0].getMimeType());

        Map<String, String> attHeaders = attachment[0].getHeaders();
        Assert.assertEquals(6, attHeaders.size());
    }

    @Test
    public void testInvalidXMLAttachmentCompleteEncryption() throws Exception {

        final String attachmentId = UUID.randomUUID().toString();
        final Attachment[] attachment = new Attachment[1];
        attachment[0] = new Attachment();
        attachment[0].setMimeType("text/xml");
        attachment[0].addHeaders(getHeaders(attachmentId));
        attachment[0].setId(attachmentId);
        attachment[0].setSourceStream(new ByteArrayInputStream(SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.ENCRYPT};
            securityProperties.setOutAction(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.addEncryptionPart(new SecurePart(new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body"), SecurePart.Modifier.Content));
            securityProperties.addEncryptionPart(new SecurePart("cid:Attachments", SecurePart.Modifier.Element));
            securityProperties.setAttachmentCallbackHandler(new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    if (callbacks[0] instanceof AttachmentRequestCallback) {
                        AttachmentRequestCallback attachmentRequestCallback = (AttachmentRequestCallback) callbacks[0];
                        List<Attachment> attachments = new ArrayList<Attachment>();
                        attachments.add(attachment[0]);
                        attachmentRequestCallback.setAttachments(attachments);
                    } else {
                        AttachmentResultCallback attachmentResultCallback = (AttachmentResultCallback) callbacks[0];
                        attachment[0] = attachmentResultCallback.getAttachment();
                    }
                }
            });

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document securedDoc = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));

            NodeList references = securedDoc.getElementsByTagNameNS(WSConstants.ENC_NS, "DataReference");
            Assert.assertEquals(2, references.getLength());
            NodeList cipherReferences = securedDoc.getElementsByTagNameNS(WSConstants.ENC_NS, "CipherReference");
            Assert.assertEquals(1, cipherReferences.getLength());
            NodeList encDatas = securedDoc.getElementsByTagNameNS(WSConstants.ENC_NS, "EncryptedData");
            Assert.assertEquals(2, encDatas.getLength());

            NodeList securityHeaderElement = securedDoc.getElementsByTagNameNS(WSConstants.WSSE_NS, "Security");
            Assert.assertEquals(1, securityHeaderElement.getLength());
            NodeList childs = securityHeaderElement.item(0).getChildNodes();
            Assert.assertEquals(2, childs.getLength());
            Assert.assertEquals(childs.item(0).getLocalName(), "EncryptedKey");
            Assert.assertEquals(childs.item(1).getLocalName(), "EncryptedData");

            Assert.assertEquals(1, attachment[0].getHeaders().size());
        }

        {
            final PushbackInputStream pis = new PushbackInputStream(attachment[0].getSourceStream(), 1);
            pis.unread('K');
            attachment[0].setSourceStream(pis);

            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            securityProperties.setAttachmentCallbackHandler(new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    if (callbacks[0] instanceof AttachmentRequestCallback) {
                        AttachmentRequestCallback attachmentRequestCallback = (AttachmentRequestCallback) callbacks[0];

                        if (!attachment[0].getId().equals(attachmentRequestCallback.getAttachmentId())) {
                            throw new RuntimeException("wrong attachment requested");
                        }

                        List<Attachment> attachments = new ArrayList<Attachment>();
                        attachments.add(attachment[0]);
                        attachmentRequestCallback.setAttachments(attachments);
                    } else {
                        AttachmentResultCallback attachmentResultCallback = (AttachmentResultCallback) callbacks[0];
                        attachment[0] = attachmentResultCallback.getAttachment();
                    }
                }
            });

            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));
            try {
                Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
            } catch (XMLStreamException e) {
                Assert.assertTrue(e.getCause() instanceof WSSecurityException);
                Assert.assertEquals(e.getCause().getMessage(), "The signature or decryption was invalid");
                return;
            }
        }

        byte[] attachmentBytes = readInputStream(attachment[0].getSourceStream());
        Assert.assertFalse(Arrays.equals(attachmentBytes, SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));
        Assert.assertEquals("text/xml", attachment[0].getMimeType());
    }

    @Test
    public void testMultipleAttachmentCompleteEncryption() throws Exception {

        final String attachment1Id = UUID.randomUUID().toString();
        final Attachment[] attachment = new Attachment[2];
        attachment[0] = new Attachment();
        attachment[0].setMimeType("text/xml");
        attachment[0].addHeaders(getHeaders(attachment1Id));
        attachment[0].setId(attachment1Id);
        attachment[0].setSourceStream(new ByteArrayInputStream(SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));

        final String attachment2Id = UUID.randomUUID().toString();
        attachment[1] = new Attachment();
        attachment[1].setMimeType("text/plain");
        attachment[1].addHeaders(getHeaders(attachment2Id));
        attachment[1].setId(attachment2Id);
        attachment[1].setSourceStream(new ByteArrayInputStream(SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.ENCRYPT};
            securityProperties.setOutAction(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.addEncryptionPart(new SecurePart(new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body"), SecurePart.Modifier.Content));
            securityProperties.addEncryptionPart(new SecurePart("cid:Attachments", SecurePart.Modifier.Element));
            securityProperties.setAttachmentCallbackHandler(new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    if (callbacks[0] instanceof AttachmentRequestCallback) {
                        AttachmentRequestCallback attachmentRequestCallback = (AttachmentRequestCallback) callbacks[0];
                        List<Attachment> attachments = new ArrayList<Attachment>();
                        attachments.add(attachment[0]);
                        attachments.add(attachment[1]);
                        attachmentRequestCallback.setAttachments(attachments);
                    } else {
                        AttachmentResultCallback attachmentResultCallback = (AttachmentResultCallback) callbacks[0];
                        if (attachmentResultCallback.getAttachmentId().equals(attachment[0].getId())) {
                            attachment[0] = attachmentResultCallback.getAttachment();
                        } else {
                            attachment[1] = attachmentResultCallback.getAttachment();
                        }
                    }
                }
            });

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();
        }

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            securityProperties.setAttachmentCallbackHandler(new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    if (callbacks[0] instanceof AttachmentRequestCallback) {
                        AttachmentRequestCallback attachmentRequestCallback = (AttachmentRequestCallback) callbacks[0];

                        List<Attachment> attachments = new ArrayList<Attachment>();
                        attachmentRequestCallback.setAttachments(attachments);

                        if (attachment[0].getId().equals(attachmentRequestCallback.getAttachmentId())) {
                            attachments.add(attachment[0]);
                        } else if (attachment[1].getId().equals(attachmentRequestCallback.getAttachmentId())) {
                            attachments.add(attachment[1]);
                        } else {
                            throw new RuntimeException("invalid attachment requested");
                        }
                    } else {
                        AttachmentResultCallback attachmentResultCallback = (AttachmentResultCallback) callbacks[0];
                        if (attachmentResultCallback.getAttachmentId().equals(attachment[0].getId())) {
                            attachment[0] = attachmentResultCallback.getAttachment();
                        } else {
                            attachment[1] = attachmentResultCallback.getAttachment();
                        }
                    }
                }
            });

            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));
            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
        }

        byte[] attachment1Bytes = readInputStream(attachment[0].getSourceStream());
        Assert.assertTrue(Arrays.equals(attachment1Bytes, SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));
        Assert.assertEquals("text/xml", attachment[0].getMimeType());

        byte[] attachment2Bytes = readInputStream(attachment[1].getSourceStream());
        Assert.assertTrue(Arrays.equals(attachment2Bytes, SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));
        Assert.assertEquals("text/plain", attachment[1].getMimeType());

        Map<String, String> att1Headers = attachment[0].getHeaders();
        Assert.assertEquals(6, att1Headers.size());

        Map<String, String> att2Headers = attachment[1].getHeaders();
        Assert.assertEquals(6, att2Headers.size());
    }

    @Test
    public void testXMLAttachmentCmplSignCmplEnc() throws Exception {

        final String attachmentId = UUID.randomUUID().toString();
        final Attachment[] attachment = new Attachment[1];
        attachment[0] = new Attachment();
        attachment[0].setMimeType("text/xml");
        attachment[0].addHeaders(getHeaders(attachmentId));
        attachment[0].setId(attachmentId);
        attachment[0].setSourceStream(new ByteArrayInputStream(SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.SIGNATURE, WSSConstants.ENCRYPT};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.addSignaturePart(new SecurePart(new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body"), SecurePart.Modifier.Element));
            securityProperties.addSignaturePart(new SecurePart("cid:Attachments", SecurePart.Modifier.Element));
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.addEncryptionPart(new SecurePart(new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body"), SecurePart.Modifier.Content));
            securityProperties.addEncryptionPart(new SecurePart("cid:Attachments", SecurePart.Modifier.Element));

            securityProperties.setAttachmentCallbackHandler(new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    if (callbacks[0] instanceof AttachmentRequestCallback) {
                        AttachmentRequestCallback attachmentRequestCallback = (AttachmentRequestCallback) callbacks[0];
                        List<Attachment> attachments = new ArrayList<Attachment>();
                        attachments.add(attachment[0]);
                        attachmentRequestCallback.setAttachments(attachments);
                    } else {
                        AttachmentResultCallback attachmentResultCallback = (AttachmentResultCallback) callbacks[0];
                        attachment[0] = attachmentResultCallback.getAttachment();
                    }
                }
            });

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document securedDoc = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));

            NodeList securityHeaderElement = securedDoc.getElementsByTagNameNS(WSConstants.WSSE_NS, "Security");
            Assert.assertEquals(1, securityHeaderElement.getLength());
            NodeList childs = securityHeaderElement.item(0).getChildNodes();
            Assert.assertEquals(3, childs.getLength());
            Assert.assertEquals(childs.item(0).getLocalName(), "EncryptedKey");
            Assert.assertEquals(childs.item(1).getLocalName(), "EncryptedData");
            Assert.assertEquals(childs.item(2).getLocalName(), "Signature");

            Assert.assertEquals(1, attachment[0].getHeaders().size());
        }

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            securityProperties.setAttachmentCallbackHandler(new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    if (callbacks[0] instanceof AttachmentRequestCallback) {
                        AttachmentRequestCallback attachmentRequestCallback = (AttachmentRequestCallback) callbacks[0];

                        if (!attachment[0].getId().equals(attachmentRequestCallback.getAttachmentId())) {
                            throw new RuntimeException("wrong attachment requested");
                        }

                        List<Attachment> attachments = new ArrayList<Attachment>();
                        attachments.add(attachment[0]);
                        attachmentRequestCallback.setAttachments(attachments);
                    } else {
                        AttachmentResultCallback attachmentResultCallback = (AttachmentResultCallback) callbacks[0];
                        attachment[0] = attachmentResultCallback.getAttachment();
                    }
                }
            });

            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));
            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
        }

        byte[] attachmentBytes = readInputStream(attachment[0].getSourceStream());
        Assert.assertTrue(Arrays.equals(attachmentBytes, SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));
        Assert.assertEquals("text/xml", attachment[0].getMimeType());

        Map<String, String> attHeaders = attachment[0].getHeaders();
        Assert.assertEquals(6, attHeaders.size());
    }

    @Test
    public void testInvalidXMLAttachmentCmplSignCmplEnc() throws Exception {

        final String attachmentId = UUID.randomUUID().toString();
        final Attachment[] attachment = new Attachment[1];
        attachment[0] = new Attachment();
        attachment[0].setMimeType("text/xml");
        attachment[0].addHeaders(getHeaders(attachmentId));
        attachment[0].setId(attachmentId);
        attachment[0].setSourceStream(new ByteArrayInputStream(SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.SIGNATURE, WSSConstants.ENCRYPT};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.addSignaturePart(new SecurePart(new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body"), SecurePart.Modifier.Element));
            securityProperties.addSignaturePart(new SecurePart("cid:Attachments", SecurePart.Modifier.Element));
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.addEncryptionPart(new SecurePart(new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body"), SecurePart.Modifier.Content));
            securityProperties.addEncryptionPart(new SecurePart("cid:Attachments", SecurePart.Modifier.Element));

            securityProperties.setAttachmentCallbackHandler(new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    if (callbacks[0] instanceof AttachmentRequestCallback) {
                        AttachmentRequestCallback attachmentRequestCallback = (AttachmentRequestCallback) callbacks[0];
                        List<Attachment> attachments = new ArrayList<Attachment>();
                        attachments.add(attachment[0]);
                        attachmentRequestCallback.setAttachments(attachments);
                    } else {
                        AttachmentResultCallback attachmentResultCallback = (AttachmentResultCallback) callbacks[0];
                        attachment[0] = attachmentResultCallback.getAttachment();
                    }
                }
            });

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();
        }

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            securityProperties.setAttachmentCallbackHandler(new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    if (callbacks[0] instanceof AttachmentRequestCallback) {
                        AttachmentRequestCallback attachmentRequestCallback = (AttachmentRequestCallback) callbacks[0];

                        if (!attachment[0].getId().equals(attachmentRequestCallback.getAttachmentId())) {
                            throw new RuntimeException("wrong attachment requested");
                        }

                        List<Attachment> attachments = new ArrayList<Attachment>();
                        attachments.add(attachment[0]);

                        if (attachment[0].getHeaders().size() == 6) {
                            //signature callback
                            attachment[0].addHeader(AttachmentUtils.MIME_HEADER_CONTENT_DESCRIPTION, "Kaputt");
                        }

                        attachmentRequestCallback.setAttachments(attachments);
                    } else {
                        AttachmentResultCallback attachmentResultCallback = (AttachmentResultCallback) callbacks[0];
                        attachment[0] = attachmentResultCallback.getAttachment();
                    }
                }
            });
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));
            try {
                Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
                Assert.fail("Exception expected");
            } catch (XMLStreamException e) {
                Assert.assertTrue(e.getCause() instanceof XMLSecurityException);
                Assert.assertTrue(e.getCause().getMessage().startsWith("Invalid digest of reference cid:"));
            }
        }
    }

    @Test
    public void testXMLAttachmentCmplEncCmplSign() throws Exception {

        final String attachmentId = UUID.randomUUID().toString();
        final Attachment[] attachment = new Attachment[1];
        attachment[0] = new Attachment();
        attachment[0].setMimeType("text/xml");
        attachment[0].addHeaders(getHeaders(attachmentId));
        attachment[0].setId(attachmentId);
        attachment[0].setSourceStream(new ByteArrayInputStream(SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.ENCRYPT, WSSConstants.SIGNATURE};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.addSignaturePart(new SecurePart(new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body"), SecurePart.Modifier.Element));
            securityProperties.addSignaturePart(new SecurePart("cid:Attachments", SecurePart.Modifier.Element));
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.addEncryptionPart(new SecurePart(new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body"), SecurePart.Modifier.Content));
            securityProperties.addEncryptionPart(new SecurePart("cid:Attachments", SecurePart.Modifier.Element));

            securityProperties.setAttachmentCallbackHandler(new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    if (callbacks[0] instanceof AttachmentRequestCallback) {
                        AttachmentRequestCallback attachmentRequestCallback = (AttachmentRequestCallback) callbacks[0];
                        List<Attachment> attachments = new ArrayList<Attachment>();
                        attachments.add(attachment[0]);
                        attachmentRequestCallback.setAttachments(attachments);
                    } else {
                        AttachmentResultCallback attachmentResultCallback = (AttachmentResultCallback) callbacks[0];
                        attachment[0] = attachmentResultCallback.getAttachment();
                    }
                }
            });

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document securedDoc = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));

            NodeList securityHeaderElement = securedDoc.getElementsByTagNameNS(WSConstants.WSSE_NS, "Security");
            Assert.assertEquals(1, securityHeaderElement.getLength());
            NodeList childs = securityHeaderElement.item(0).getChildNodes();
            Assert.assertEquals(3, childs.getLength());
            Assert.assertEquals(childs.item(0).getLocalName(), "Signature");
            Assert.assertEquals(childs.item(1).getLocalName(), "EncryptedKey");
            Assert.assertEquals(childs.item(2).getLocalName(), "EncryptedData");

            Assert.assertEquals(1, attachment[0].getHeaders().size());
        }

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            securityProperties.setAttachmentCallbackHandler(new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    if (callbacks[0] instanceof AttachmentRequestCallback) {
                        AttachmentRequestCallback attachmentRequestCallback = (AttachmentRequestCallback) callbacks[0];

                        if (!attachment[0].getId().equals(attachmentRequestCallback.getAttachmentId())) {
                            throw new RuntimeException("wrong attachment requested");
                        }

                        List<Attachment> attachments = new ArrayList<Attachment>();
                        attachments.add(attachment[0]);
                        attachmentRequestCallback.setAttachments(attachments);
                    } else {
                        AttachmentResultCallback attachmentResultCallback = (AttachmentResultCallback) callbacks[0];
                        attachment[0] = attachmentResultCallback.getAttachment();
                    }
                }
            });

            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));
            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
        }

        byte[] attachmentBytes = readInputStream(attachment[0].getSourceStream());
        Assert.assertTrue(Arrays.equals(attachmentBytes, SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));
        Assert.assertEquals("text/xml", attachment[0].getMimeType());

        Map<String, String> attHeaders = attachment[0].getHeaders();
        Assert.assertEquals(6, attHeaders.size());
    }

    @Test
    public void testInvalidXMLAttachmentCmplEncCmplSign() throws Exception {

        final String attachmentId = UUID.randomUUID().toString();
        final Attachment[] attachment = new Attachment[1];
        attachment[0] = new Attachment();
        attachment[0].setMimeType("text/xml");
        attachment[0].addHeaders(getHeaders(attachmentId));
        attachment[0].setId(attachmentId);
        attachment[0].setSourceStream(new ByteArrayInputStream(SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.ENCRYPT, WSSConstants.SIGNATURE};
            securityProperties.setOutAction(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.addSignaturePart(new SecurePart(new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body"), SecurePart.Modifier.Element));
            securityProperties.addSignaturePart(new SecurePart("cid:Attachments", SecurePart.Modifier.Element));
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.addEncryptionPart(new SecurePart(new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body"), SecurePart.Modifier.Content));
            securityProperties.addEncryptionPart(new SecurePart("cid:Attachments", SecurePart.Modifier.Element));

            securityProperties.setAttachmentCallbackHandler(new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    if (callbacks[0] instanceof AttachmentRequestCallback) {
                        AttachmentRequestCallback attachmentRequestCallback = (AttachmentRequestCallback) callbacks[0];
                        List<Attachment> attachments = new ArrayList<Attachment>();
                        attachments.add(attachment[0]);
                        attachmentRequestCallback.setAttachments(attachments);
                    } else {
                        AttachmentResultCallback attachmentResultCallback = (AttachmentResultCallback) callbacks[0];
                        attachment[0] = attachmentResultCallback.getAttachment();
                    }
                }
            });

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, "UTF-8", new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document securedDoc = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));

            NodeList securityHeaderElement = securedDoc.getElementsByTagNameNS(WSConstants.WSSE_NS, "Security");
            Assert.assertEquals(1, securityHeaderElement.getLength());
            NodeList childs = securityHeaderElement.item(0).getChildNodes();
            Assert.assertEquals(3, childs.getLength());
            Assert.assertEquals(childs.item(0).getLocalName(), "Signature");
            Assert.assertEquals(childs.item(1).getLocalName(), "EncryptedKey");
            Assert.assertEquals(childs.item(2).getLocalName(), "EncryptedData");
        }

        {
            final PushbackInputStream pis = new PushbackInputStream(attachment[0].getSourceStream(), 1);
            pis.unread('K');
            attachment[0].setSourceStream(pis);

            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            securityProperties.setAttachmentCallbackHandler(new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    if (callbacks[0] instanceof AttachmentRequestCallback) {
                        AttachmentRequestCallback attachmentRequestCallback = (AttachmentRequestCallback) callbacks[0];

                        if (!attachment[0].getId().equals(attachmentRequestCallback.getAttachmentId())) {
                            throw new RuntimeException("wrong attachment requested");
                        }

                        List<Attachment> attachments = new ArrayList<Attachment>();
                        attachments.add(attachment[0]);
                        attachmentRequestCallback.setAttachments(attachments);
                    } else {
                        AttachmentResultCallback attachmentResultCallback = (AttachmentResultCallback) callbacks[0];
                        attachment[0] = attachmentResultCallback.getAttachment();
                    }
                }
            });

            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));
            try {
                Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
                Assert.fail("Exception expected");
            } catch (XMLStreamException e) {
                Assert.assertNotNull(e.getMessage());
            }
        }
    }
}
