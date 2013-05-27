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
package org.apache.wss4j.dom.message;

import org.junit.Assert;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.Attachment;
import org.apache.wss4j.common.ext.AttachmentRequestCallback;
import org.apache.wss4j.common.ext.AttachmentResultCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.AttachmentUtils;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.*;
import org.apache.wss4j.dom.common.KeystoreCallbackHandler;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.handler.RequestData;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.*;
import java.util.*;

public class AttachmentTest extends org.junit.Assert {

    private static final org.slf4j.Logger LOG =
            org.slf4j.LoggerFactory.getLogger(AttachmentTest.class);

    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private Crypto crypto = null;

    public AttachmentTest() throws Exception {
        WSSConfig.init();
        crypto = CryptoFactory.getInstance();
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

    @org.junit.Test
    public void testXMLAttachmentContentSignature() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");

        List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
        parts.add(new WSEncryptionPart("Body", "http://schemas.xmlsoap.org/soap/envelope/", "Content"));
        parts.add(new WSEncryptionPart("cid:Attachments", "Content"));
        builder.setParts(parts);

        final String attachmentId = UUID.randomUUID().toString();
        final Attachment[] attachment = new Attachment[1];
        attachment[0] = new Attachment();
        attachment[0].setMimeType("text/xml");
        attachment[0].addHeaders(getHeaders(attachmentId));
        attachment[0].setId(attachmentId);
        attachment[0].setSourceStream(new ByteArrayInputStream(SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));

        builder.setAttachmentCallbackHandler(new CallbackHandler() {
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

        LOG.info("Before Signing....");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("After Signing....");
            String outputString = XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }

        NodeList sigReferences = signedDoc.getElementsByTagNameNS(WSConstants.SIG_NS, "Reference");
        Assert.assertEquals(2, sigReferences.getLength());

        verify(signedDoc, new CallbackHandler() {
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

        byte[] attachmentBytes = readInputStream(attachment[0].getSourceStream());
        Assert.assertTrue(Arrays.equals(attachmentBytes, SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));
        Assert.assertEquals("text/xml", attachment[0].getMimeType());
    }

    @org.junit.Test
    public void testInvalidXMLAttachmentContentSignature() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");

        List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
        parts.add(new WSEncryptionPart("Body", "http://schemas.xmlsoap.org/soap/envelope/", "Content"));
        parts.add(new WSEncryptionPart("cid:Attachments", "Content"));
        builder.setParts(parts);

        final String attachmentId = UUID.randomUUID().toString();
        final Attachment[] attachment = new Attachment[1];
        attachment[0] = new Attachment();
        attachment[0].setMimeType("text/xml");
        attachment[0].addHeaders(getHeaders(attachmentId));
        attachment[0].setId(attachmentId);
        attachment[0].setSourceStream(new ByteArrayInputStream(SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));

        builder.setAttachmentCallbackHandler(new CallbackHandler() {
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

        LOG.info("Before Signing....");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("After Signing....");
            String outputString = XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }

        try {
            verify(signedDoc, new CallbackHandler() {
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
            Assert.fail();
        } catch (WSSecurityException e) {
            Assert.assertEquals(e.getMessage(), "The signature or decryption was invalid");
        }
    }

    @org.junit.Test
    public void testXMLAttachmentCompleteSignature() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");

        List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
        parts.add(new WSEncryptionPart("Body", "http://schemas.xmlsoap.org/soap/envelope/", "Content"));
        parts.add(new WSEncryptionPart("cid:Attachments", "Content"));
        builder.setParts(parts);

        final String attachmentId = UUID.randomUUID().toString();
        final Attachment[] attachment = new Attachment[1];
        attachment[0] = new Attachment();
        attachment[0].setMimeType("text/xml");
        attachment[0].addHeaders(getHeaders(attachmentId));
        attachment[0].setId(attachmentId);
        attachment[0].setSourceStream(new ByteArrayInputStream(SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));

        builder.setAttachmentCallbackHandler(new CallbackHandler() {
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

        LOG.info("Before Signing....");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("After Signing....");
            String outputString = XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }

        NodeList sigReferences = signedDoc.getElementsByTagNameNS(WSConstants.SIG_NS, "Reference");
        Assert.assertEquals(2, sigReferences.getLength());

        verify(signedDoc, new CallbackHandler() {
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

        byte[] attachmentBytes = readInputStream(attachment[0].getSourceStream());
        Assert.assertTrue(Arrays.equals(attachmentBytes, SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));
        Assert.assertEquals("text/xml", attachment[0].getMimeType());
    }

    @org.junit.Test
    public void testInvalidXMLAttachmentCompleteSignature() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");

        List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
        parts.add(new WSEncryptionPart("Body", "http://schemas.xmlsoap.org/soap/envelope/", "Content"));
        parts.add(new WSEncryptionPart("cid:Attachments", "Element"));
        builder.setParts(parts);

        final String attachmentId = UUID.randomUUID().toString();
        final Attachment[] attachment = new Attachment[1];
        attachment[0] = new Attachment();
        attachment[0].setMimeType("text/xml");
        attachment[0].addHeaders(getHeaders(attachmentId));
        attachment[0].setId(attachmentId);
        attachment[0].setSourceStream(new ByteArrayInputStream(SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));

        builder.setAttachmentCallbackHandler(new CallbackHandler() {
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

        LOG.info("Before Signing....");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("After Signing....");
            String outputString = XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }

        try {
            attachment[0].addHeader(AttachmentUtils.MIME_HEADER_CONTENT_DESCRIPTION, "Kaputt");
            verify(signedDoc, new CallbackHandler() {
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
            Assert.fail();
        } catch (WSSecurityException e) {
            Assert.assertEquals(e.getMessage(), "The signature or decryption was invalid");
        }
    }

    @org.junit.Test
    public void testMultipleAttachmentCompleteSignature() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");

        List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
        parts.add(new WSEncryptionPart("Body", "http://schemas.xmlsoap.org/soap/envelope/", "Content"));
        parts.add(new WSEncryptionPart("cid:Attachments", "Element"));
        builder.setParts(parts);

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

        builder.setAttachmentCallbackHandler(new CallbackHandler() {
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

        LOG.info("Before Signing....");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("After Signing....");
            String outputString = XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }

        NodeList sigReferences = signedDoc.getElementsByTagNameNS(WSConstants.SIG_NS, "Reference");
        Assert.assertEquals(3, sigReferences.getLength());

        verify(signedDoc, new CallbackHandler() {
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

        byte[] attachment1Bytes = readInputStream(attachment[0].getSourceStream());
        Assert.assertTrue(Arrays.equals(attachment1Bytes, SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));
        Assert.assertEquals("text/xml", attachment[0].getMimeType());

        byte[] attachment2Bytes = readInputStream(attachment[1].getSourceStream());
        Assert.assertTrue(Arrays.equals(attachment2Bytes, SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));
        Assert.assertEquals("text/plain", attachment[1].getMimeType());
    }

    @org.junit.Test
    public void testXMLAttachmentContentEncryption() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecEncrypt encrypt = new WSSecEncrypt();
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
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

        Document encryptedDoc = encrypt.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = XMLUtils.PrettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }

        NodeList references = doc.getElementsByTagNameNS(WSConstants.ENC_NS, "DataReference");
        Assert.assertEquals(2, references.getLength());
        NodeList cipherReferences = doc.getElementsByTagNameNS(WSConstants.ENC_NS, "CipherReference");
        Assert.assertEquals(1, cipherReferences.getLength());
        NodeList encDatas = doc.getElementsByTagNameNS(WSConstants.ENC_NS, "EncryptedData");
        Assert.assertEquals(2, encDatas.getLength());

        NodeList securityHeaderElement = doc.getElementsByTagNameNS(WSConstants.WSSE_NS, "Security");
        Assert.assertEquals(1, securityHeaderElement.getLength());
        NodeList childs = securityHeaderElement.item(0).getChildNodes();
        Assert.assertEquals(2, childs.getLength());
        Assert.assertEquals(childs.item(0).getLocalName(), "EncryptedKey");
        Assert.assertEquals(childs.item(1).getLocalName(), "EncryptedData");

        verify(encryptedDoc, new CallbackHandler() {
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

        byte[] attachmentBytes = readInputStream(attachment[0].getSourceStream());
        Assert.assertTrue(Arrays.equals(attachmentBytes, SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));
        Assert.assertEquals("text/xml", attachment[0].getMimeType());

        Map<String, String> attHeaders = attachment[0].getHeaders();
        Assert.assertEquals(6, attHeaders.size());
    }

    @org.junit.Test
    public void testInvalidXMLAttachmentContentEncryption() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecEncrypt encrypt = new WSSecEncrypt();
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
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

        Document encryptedDoc = encrypt.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = XMLUtils.PrettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }

        final PushbackInputStream pis = new PushbackInputStream(attachment[0].getSourceStream(), 1);
        pis.unread('K');
        attachment[0].setSourceStream(pis);
        verify(encryptedDoc, new CallbackHandler() {
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

        byte[] attachmentBytes = readInputStream(attachment[0].getSourceStream());
        Assert.assertFalse(Arrays.equals(attachmentBytes, SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));
        Assert.assertEquals("text/xml", attachment[0].getMimeType());

        Map<String, String> attHeaders = attachment[0].getHeaders();
        Assert.assertEquals(6, attHeaders.size());
    }

    @org.junit.Test
    public void testXMLAttachmentContentEncryptionExternalReferenceList() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecEncrypt encrypt = new WSSecEncrypt();
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
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

        encrypt.prepare(doc, crypto);
        Element refs = encrypt.encryptForRef(null, parts);
        encrypt.addAttachmentEncryptedDataElements(secHeader);
        encrypt.addExternalRefElement(refs, secHeader);
        encrypt.prependToHeader(secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }

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

        verify(doc, new CallbackHandler() {
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

        byte[] attachmentBytes = readInputStream(attachment[0].getSourceStream());
        Assert.assertTrue(Arrays.equals(attachmentBytes, SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));
        Assert.assertEquals("text/xml", attachment[0].getMimeType());

        Map<String, String> attHeaders = attachment[0].getHeaders();
        Assert.assertEquals(6, attHeaders.size());
    }

    @org.junit.Test
    public void testXMLAttachmentContentEncryptionNoReference() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecEncrypt encrypt = new WSSecEncrypt();
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
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

        encrypt.prepare(doc, crypto);
        Element refs = encrypt.encryptForRef(null, parts);
        encrypt.addAttachmentEncryptedDataElements(secHeader);
        //encrypt.addExternalRefElement(refs, secHeader);
        encrypt.prependToHeader(secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        NodeList references = doc.getElementsByTagNameNS(WSConstants.ENC_NS, "DataReference");
        Assert.assertEquals(0, references.getLength());
        NodeList cipherReferences = doc.getElementsByTagNameNS(WSConstants.ENC_NS, "CipherReference");
        Assert.assertEquals(1, cipherReferences.getLength());
        NodeList encDatas = doc.getElementsByTagNameNS(WSConstants.ENC_NS, "EncryptedData");
        Assert.assertEquals(2, encDatas.getLength());

        NodeList securityHeaderElement = doc.getElementsByTagNameNS(WSConstants.WSSE_NS, "Security");
        Assert.assertEquals(1, securityHeaderElement.getLength());
        NodeList childs = securityHeaderElement.item(0).getChildNodes();
        Assert.assertEquals(2, childs.getLength());
        Assert.assertEquals(childs.item(0).getLocalName(), "EncryptedKey");
        Assert.assertEquals(childs.item(1).getLocalName(), "EncryptedData");

        verify(doc, new CallbackHandler() {
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

        byte[] attachmentBytes = readInputStream(attachment[0].getSourceStream());
        Assert.assertTrue(Arrays.equals(attachmentBytes, SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));
        Assert.assertEquals("text/xml", attachment[0].getMimeType());

        Map<String, String> attHeaders = attachment[0].getHeaders();
        Assert.assertEquals(6, attHeaders.size());
    }

    @org.junit.Test
    public void testXMLAttachmentCompleteEncryption() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecEncrypt encrypt = new WSSecEncrypt();
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
        parts.add(new WSEncryptionPart("Body", "http://schemas.xmlsoap.org/soap/envelope/", "Content"));
        parts.add(new WSEncryptionPart("cid:Attachments", "Element"));
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

        Document encryptedDoc = encrypt.build(doc, crypto, secHeader);

        Assert.assertEquals(1, attachment[0].getHeaders().size());

        if (LOG.isDebugEnabled()) {
            String outputString = XMLUtils.PrettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }

        verify(encryptedDoc, new CallbackHandler() {
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

        byte[] attachmentBytes = readInputStream(attachment[0].getSourceStream());
        Assert.assertTrue(Arrays.equals(attachmentBytes, SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));
        Assert.assertEquals("text/xml", attachment[0].getMimeType());

        Map<String, String> attHeaders = attachment[0].getHeaders();
        Assert.assertEquals(6, attHeaders.size());
    }

    @org.junit.Test
    public void testInvalidXMLAttachmentCompleteEncryption() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecEncrypt encrypt = new WSSecEncrypt();
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
        parts.add(new WSEncryptionPart("Body", "http://schemas.xmlsoap.org/soap/envelope/", "Content"));
        parts.add(new WSEncryptionPart("cid:Attachments", "Element"));
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

        Document encryptedDoc = encrypt.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = XMLUtils.PrettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }

        try {
            final PushbackInputStream pis = new PushbackInputStream(attachment[0].getSourceStream(), 1);
            pis.unread('K');
            attachment[0].setSourceStream(pis);
            verify(encryptedDoc, new CallbackHandler() {
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
                        if (attachmentResultCallback.getAttachmentId().equals(attachment[0].getId())) {
                            attachment[0] = attachmentResultCallback.getAttachment();
                        } else {
                            attachment[1] = attachmentResultCallback.getAttachment();
                        }
                    }
                }
            });
        } catch (WSSecurityException e) {
            Assert.assertEquals(e.getMessage(), "The signature or decryption was invalid");
            return;
        }

        byte[] attachmentBytes = readInputStream(attachment[0].getSourceStream());
        Assert.assertFalse(Arrays.equals(attachmentBytes, SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));
        Assert.assertEquals("text/xml", attachment[0].getMimeType());
    }

    @org.junit.Test
    public void testMultipleAttachmentCompleteEncryption() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecEncrypt encrypt = new WSSecEncrypt();
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
        WSEncryptionPart att =
                new WSEncryptionPart("*", "*", "Attachments");
        parts.add(new WSEncryptionPart("Body", "http://schemas.xmlsoap.org/soap/envelope/", "Content"));
        parts.add(new WSEncryptionPart("cid:Attachments", "Element"));
        encrypt.setParts(parts);

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

        encrypt.setAttachmentCallbackHandler(new CallbackHandler() {
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

        Document encryptedDoc = encrypt.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = XMLUtils.PrettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }

        verify(encryptedDoc, new CallbackHandler() {
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

    @org.junit.Test
    public void testXMLAttachmentCmplSignCmplEnc() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        WSSecSignature signature = new WSSecSignature();
        signature.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");

        List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
        parts.add(new WSEncryptionPart("Body", "http://schemas.xmlsoap.org/soap/envelope/", "Content"));
        parts.add(new WSEncryptionPart("cid:Attachments", "Element"));
        signature.setParts(parts);

        String attachmentId = UUID.randomUUID().toString();
        final Attachment[] attachment = new Attachment[1];
        attachment[0] = new Attachment();
        attachment[0].setMimeType("text/xml");
        attachment[0].addHeaders(getHeaders(attachmentId));
        attachment[0].setId(attachmentId);
        attachment[0].setSourceStream(new ByteArrayInputStream(SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));

        signature.setAttachmentCallbackHandler(new CallbackHandler() {
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

        doc = signature.build(doc, crypto, secHeader);

        WSSecEncrypt encrypt = new WSSecEncrypt();
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        encrypt.setParts(parts);

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

        Document encryptedDoc = encrypt.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = XMLUtils.PrettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }

        NodeList securityHeaderElement = doc.getElementsByTagNameNS(WSConstants.WSSE_NS, "Security");
        Assert.assertEquals(1, securityHeaderElement.getLength());
        NodeList childs = securityHeaderElement.item(0).getChildNodes();
        Assert.assertEquals(3, childs.getLength());
        Assert.assertEquals(childs.item(0).getLocalName(), "EncryptedKey");
        Assert.assertEquals(childs.item(1).getLocalName(), "EncryptedData");
        Assert.assertEquals(childs.item(2).getLocalName(), "Signature");

        verify(encryptedDoc, new CallbackHandler() {
            @Override
            public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                if (callbacks[0] instanceof AttachmentRequestCallback) {
                    AttachmentRequestCallback attachmentRequestCallback = (AttachmentRequestCallback) callbacks[0];

                    if (!attachment[0].getId().equals(attachmentRequestCallback.getAttachmentId())) {
                        throw new RuntimeException("wrong attachment requested");
                    }

                    List<Attachment> attachmentList = new ArrayList<Attachment>();
                    attachmentList.add(attachment[0]);
                    attachmentRequestCallback.setAttachments(attachmentList);

                } else {
                    AttachmentResultCallback attachmentResultCallback = (AttachmentResultCallback) callbacks[0];
                    attachment[0] = attachmentResultCallback.getAttachment();
                }
            }
        });

        byte[] attachmentBytes = readInputStream(attachment[0].getSourceStream());
        Assert.assertTrue(Arrays.equals(attachmentBytes, SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));
        Assert.assertEquals("text/xml", attachment[0].getMimeType());

        Map<String, String> attHeaders = attachment[0].getHeaders();
        Assert.assertEquals(6, attHeaders.size());
    }

    @org.junit.Test
    public void testInvalidXMLAttachmentCmplSignCmplEnc() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        WSSecSignature signature = new WSSecSignature();
        signature.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");

        List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
        parts.add(new WSEncryptionPart("Body", "http://schemas.xmlsoap.org/soap/envelope/", "Content"));
        parts.add(new WSEncryptionPart("cid:Attachments", "Element"));
        signature.setParts(parts);

        String attachmentId = UUID.randomUUID().toString();
        final Attachment[] attachment = new Attachment[1];
        attachment[0] = new Attachment();
        attachment[0].setMimeType("text/xml");
        attachment[0].addHeaders(getHeaders(attachmentId));
        attachment[0].setId(attachmentId);
        attachment[0].setSourceStream(new ByteArrayInputStream(SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));

        signature.setAttachmentCallbackHandler(new CallbackHandler() {
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

        doc = signature.build(doc, crypto, secHeader);

        WSSecEncrypt encrypt = new WSSecEncrypt();
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        encrypt.setParts(parts);

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

        Document encryptedDoc = encrypt.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = XMLUtils.PrettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }

        try {
            verify(encryptedDoc, new CallbackHandler() {
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
            Assert.fail();
        } catch (WSSecurityException e) {
            Assert.assertEquals(e.getMessage(), "The signature or decryption was invalid");
        }
    }

    @org.junit.Test
    public void testXMLAttachmentCmplEncCmplSign() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        WSSecEncrypt encrypt = new WSSecEncrypt();
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
        parts.add(new WSEncryptionPart("Body", "http://schemas.xmlsoap.org/soap/envelope/", "Content"));
        parts.add(new WSEncryptionPart("cid:Attachments", "Element"));
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

        doc = encrypt.build(doc, crypto, secHeader);

        WSSecSignature signature = new WSSecSignature();
        signature.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        signature.setParts(parts);

        signature.setAttachmentCallbackHandler(new CallbackHandler() {
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

        doc = signature.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        NodeList securityHeaderElement = doc.getElementsByTagNameNS(WSConstants.WSSE_NS, "Security");
        Assert.assertEquals(1, securityHeaderElement.getLength());
        NodeList childs = securityHeaderElement.item(0).getChildNodes();
        Assert.assertEquals(3, childs.getLength());
        Assert.assertEquals(childs.item(0).getLocalName(), "Signature");
        Assert.assertEquals(childs.item(1).getLocalName(), "EncryptedKey");
        Assert.assertEquals(childs.item(2).getLocalName(), "EncryptedData");

        verify(doc, new CallbackHandler() {
            @Override
            public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                if (callbacks[0] instanceof AttachmentRequestCallback) {
                    AttachmentRequestCallback attachmentRequestCallback = (AttachmentRequestCallback) callbacks[0];

                    if (!attachment[0].getId().equals(attachmentRequestCallback.getAttachmentId())) {
                        throw new RuntimeException("wrong attachment requested");
                    }

                    List<Attachment> attachmentList = new ArrayList<Attachment>();
                    attachmentList.add(attachment[0]);
                    attachmentRequestCallback.setAttachments(attachmentList);

                } else {
                    AttachmentResultCallback attachmentResultCallback = (AttachmentResultCallback) callbacks[0];
                    attachment[0] = attachmentResultCallback.getAttachment();
                }
            }
        });

        byte[] attachmentBytes = readInputStream(attachment[0].getSourceStream());
        Assert.assertTrue(Arrays.equals(attachmentBytes, SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));
        Assert.assertEquals("text/xml", attachment[0].getMimeType());

        Map<String, String> attHeaders = attachment[0].getHeaders();
        Assert.assertEquals(6, attHeaders.size());
    }

    @org.junit.Test
    public void testInvalidXMLAttachmentCmplEncCmplSign() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        WSSecEncrypt encrypt = new WSSecEncrypt();
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
        parts.add(new WSEncryptionPart("Body", "http://schemas.xmlsoap.org/soap/envelope/", "Content"));
        parts.add(new WSEncryptionPart("cid:Attachments", "Element"));
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

        doc = encrypt.build(doc, crypto, secHeader);

        WSSecSignature signature = new WSSecSignature();
        signature.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        signature.setParts(parts);

        signature.setAttachmentCallbackHandler(new CallbackHandler() {
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

        doc = signature.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        final PushbackInputStream pis = new PushbackInputStream(attachment[0].getSourceStream(), 1);
        pis.unread('K');
        attachment[0].setSourceStream(pis);
        try {
            verify(doc, new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    if (callbacks[0] instanceof AttachmentRequestCallback) {
                        AttachmentRequestCallback attachmentRequestCallback = (AttachmentRequestCallback) callbacks[0];

                        if (!attachment[0].getId().equals(attachmentRequestCallback.getAttachmentId())) {
                            throw new RuntimeException("wrong attachment requested");
                        }

                        List<Attachment> attachmentList = new ArrayList<Attachment>();
                        attachmentList.add(attachment[0]);
                        attachmentRequestCallback.setAttachments(attachmentList);

                    } else {
                        AttachmentResultCallback attachmentResultCallback = (AttachmentResultCallback) callbacks[0];
                        attachment[0] = attachmentResultCallback.getAttachment();
                    }
                }
            });
            Assert.fail();
        } catch (WSSecurityException e) {
            Assert.assertEquals(e.getMessage(), "The signature or decryption was invalid");
        }
    }

    /**
     * Verifies the soap envelope.
     * This method verifies all the signature generated.
     *
     * @throws java.lang.Exception Thrown when there is a problem in verification
     */
    private List<WSSecurityEngineResult> verify(Document doc, CallbackHandler attachmentCallbackHandler) throws Exception {
        RequestData requestData = new RequestData();
        requestData.setAttachmentCallbackHandler(attachmentCallbackHandler);
        requestData.setSigVerCrypto(crypto);
        requestData.setDecCrypto(crypto);
        requestData.setCallbackHandler(new KeystoreCallbackHandler());
        return secEngine.processSecurityHeader(doc, null, requestData);
    }
}
