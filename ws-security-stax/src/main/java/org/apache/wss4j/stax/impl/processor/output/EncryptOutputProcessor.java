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
package org.apache.wss4j.stax.impl.processor.output;

import java.io.*;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.*;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Attribute;

import org.apache.wss4j.common.ext.Attachment;
import org.apache.wss4j.common.ext.AttachmentRequestCallback;
import org.apache.wss4j.common.ext.AttachmentResultCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.AttachmentUtils;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.ext.WSSUtils;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.config.JCEAlgorithmMapper;
import org.apache.xml.security.stax.config.TransformerAlgorithmMapper;
import org.apache.xml.security.stax.ext.OutputProcessorChain;
import org.apache.xml.security.stax.ext.SecurePart;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.stax.XMLSecAttribute;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.apache.xml.security.stax.impl.EncryptionPartDef;
import org.apache.xml.security.stax.impl.processor.output.AbstractEncryptOutputProcessor;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.apache.xml.security.stax.securityToken.OutboundSecurityToken;
import org.apache.xml.security.stax.securityToken.SecurityTokenProvider;

/**
 * Processor to encrypt XML structures
 */
public class EncryptOutputProcessor extends AbstractEncryptOutputProcessor {

    private static final transient org.slf4j.Logger logger = 
        org.slf4j.LoggerFactory.getLogger(EncryptOutputProcessor.class);

    public EncryptOutputProcessor() throws XMLSecurityException {
        super();
    }

    @Override
    public void init(OutputProcessorChain outputProcessorChain) throws XMLSecurityException {
        super.init(outputProcessorChain);
        EncryptEndingOutputProcessor encryptEndingOutputProcessor = new EncryptEndingOutputProcessor();
        encryptEndingOutputProcessor.setXMLSecurityProperties(getSecurityProperties());
        encryptEndingOutputProcessor.setAction(getAction());
        encryptEndingOutputProcessor.init(outputProcessorChain);
    }

    @Override
    public void processEvent(XMLSecEvent xmlSecEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
        if (xmlSecEvent.getEventType() == XMLStreamConstants.START_ELEMENT) {
            XMLSecStartElement xmlSecStartElement = xmlSecEvent.asStartElement();

            //avoid double encryption when child elements matches too
            if (getActiveInternalEncryptionOutputProcessor() == null) {
                SecurePart securePart = securePartMatches(xmlSecStartElement, outputProcessorChain, WSSConstants.ENCRYPTION_PARTS);
                if (securePart != null) {
                    logger.debug("Matched encryptionPart for encryption");
                    InternalEncryptionOutputProcessor internalEncryptionOutputProcessor;
                    String tokenId = outputProcessorChain.getSecurityContext().get(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTION);
                    SecurityTokenProvider<OutboundSecurityToken> securityTokenProvider = outputProcessorChain.getSecurityContext().getSecurityTokenProvider(tokenId);
                    OutboundSecurityToken securityToken = securityTokenProvider.getSecurityToken();
                    EncryptionPartDef encryptionPartDef = new EncryptionPartDef();
                    encryptionPartDef.setSecurePart(securePart);
                    encryptionPartDef.setModifier(securePart.getModifier());
                    encryptionPartDef.setEncRefId(IDGenerator.generateID(null));
                    encryptionPartDef.setKeyId(securityTokenProvider.getId());
                    encryptionPartDef.setSymmetricKey(securityToken.getSecretKey(getSecurityProperties().getEncryptionSymAlgorithm()));
                    outputProcessorChain.getSecurityContext().putAsList(EncryptionPartDef.class, encryptionPartDef);
                    internalEncryptionOutputProcessor =
                            new InternalEncryptionOutputProcessor(
                                    encryptionPartDef,
                                    xmlSecStartElement,
                                    outputProcessorChain.getDocumentContext().getEncoding()
                            );
                    internalEncryptionOutputProcessor.setXMLSecurityProperties(getSecurityProperties());
                    internalEncryptionOutputProcessor.setAction(getAction());
                    internalEncryptionOutputProcessor.init(outputProcessorChain);

                    setActiveInternalEncryptionOutputProcessor(internalEncryptionOutputProcessor);

                    //we can remove this processor when the whole body will be encrypted since there is
                    //nothing more which can be encrypted.
                    if (WSSConstants.TAG_soap_Body_LocalName.equals(xmlSecStartElement.getName().getLocalPart())
                            && WSSUtils.isInSOAPBody(xmlSecStartElement)) {
                        doFinalInternal(outputProcessorChain);
                        outputProcessorChain.removeProcessor(this);
                    }
                }
            }
        }

        outputProcessorChain.processEvent(xmlSecEvent);
    }

    @Override
    public void doFinalInternal(OutputProcessorChain outputProcessorChain) throws XMLSecurityException {
        setupAttachmentEncryptionStreams(outputProcessorChain);
        super.doFinalInternal(outputProcessorChain);
    }

    protected void setupAttachmentEncryptionStreams(OutputProcessorChain outputProcessorChain) throws XMLSecurityException {

        SecurePart attachmentSecurePart = null;

        Map<Object, SecurePart> dynamicSecureParts = outputProcessorChain.getSecurityContext().getAsMap(XMLSecurityConstants.ENCRYPTION_PARTS);
        Iterator<Map.Entry<Object, SecurePart>> securePartsMapIterator = dynamicSecureParts.entrySet().iterator();
        while (securePartsMapIterator.hasNext()) {
            Map.Entry<Object, SecurePart> securePartEntry = securePartsMapIterator.next();
            final SecurePart securePart = securePartEntry.getValue();
            final String externalReference = securePart.getExternalReference();
            if (externalReference != null && "cid:Attachments".equals(externalReference)) {
                attachmentSecurePart = securePart;
                break;
            }
        }
        if (attachmentSecurePart == null) {
            return;
        }

        CallbackHandler attachmentCallbackHandler =
                ((WSSSecurityProperties) getSecurityProperties()).getAttachmentCallbackHandler();
        if (attachmentCallbackHandler == null) {
            throw new WSSecurityException(
                    WSSecurityException.ErrorCode.FAILURE,
                    "empty", "no attachment callbackhandler supplied"
            );
        }

        AttachmentRequestCallback attachmentRequestCallback = new AttachmentRequestCallback();
        try {
            attachmentCallbackHandler.handle(new Callback[]{attachmentRequestCallback});
        } catch (Exception e) {
            throw new WSSecurityException(
                    WSSecurityException.ErrorCode.FAILURE, e
            );
        }
        List<Attachment> attachments = attachmentRequestCallback.getAttachments();
        if (attachments == null || attachments.isEmpty()) {
            throw new WSSecurityException(
                    WSSecurityException.ErrorCode.FAILURE,
                    "noEncElement"
            );
        }

        for (int i = 0; i < attachments.size(); i++) {
            final Attachment attachment = attachments.get(i);
            final String attachmentId = attachment.getId();

            String tokenId = outputProcessorChain.getSecurityContext().get(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTION);
            SecurityTokenProvider<OutboundSecurityToken> securityTokenProvider =
                    outputProcessorChain.getSecurityContext().getSecurityTokenProvider(tokenId);
            OutboundSecurityToken securityToken = securityTokenProvider.getSecurityToken();
            EncryptionPartDef encryptionPartDef = new EncryptionPartDef();
            encryptionPartDef.setSecurePart(attachmentSecurePart);
            encryptionPartDef.setModifier(attachmentSecurePart.getModifier());
            encryptionPartDef.setCipherReferenceId(attachment.getId());
            encryptionPartDef.setMimeType(attachment.getMimeType());
            encryptionPartDef.setEncRefId(IDGenerator.generateID(null));
            encryptionPartDef.setKeyId(securityTokenProvider.getId());
            encryptionPartDef.setSymmetricKey(securityToken.getSecretKey(getSecurityProperties().getEncryptionSymAlgorithm()));
            outputProcessorChain.getSecurityContext().putAsList(EncryptionPartDef.class, encryptionPartDef);

            final Attachment resultAttachment = new Attachment();
            resultAttachment.setId(attachmentId);
            resultAttachment.setMimeType("application/octet-stream");

            String encryptionSymAlgorithm = getSecurityProperties().getEncryptionSymAlgorithm();
            String jceAlgorithm = JCEAlgorithmMapper.translateURItoJCEID(encryptionSymAlgorithm);
            if (jceAlgorithm == null) {
                throw new XMLSecurityException("algorithms.NoSuchMap", encryptionSymAlgorithm);
            }
            //initialize the cipher
            Cipher cipher = null;
            try {
                cipher = Cipher.getInstance(jceAlgorithm);

                // The Spec mandates a 96-bit IV for GCM algorithms
                if ("AES/GCM/NoPadding".equals(cipher.getAlgorithm())) {
                    byte[] temp = new byte[12];
                    XMLSecurityConstants.secureRandom.nextBytes(temp);
                    IvParameterSpec ivParameterSpec = new IvParameterSpec(temp);
                    cipher.init(Cipher.ENCRYPT_MODE, encryptionPartDef.getSymmetricKey(), ivParameterSpec);
                } else {
                    cipher.init(Cipher.ENCRYPT_MODE, encryptionPartDef.getSymmetricKey());
                }
            } catch (Exception e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_ENCRYPTION, e);
            }

            final Map<String, String> headers = new HashMap<String, String>();
            headers.putAll(attachment.getHeaders());
            resultAttachment.setSourceStream(
                    AttachmentUtils.setupAttachmentEncryptionStream(
                            cipher,
                            SecurePart.Modifier.Element == encryptionPartDef.getModifier(),
                            attachment, headers
                    ));
            resultAttachment.addHeaders(headers);

            final AttachmentResultCallback attachmentResultCallback = new AttachmentResultCallback();
            attachmentResultCallback.setAttachmentId(attachmentId);
            attachmentResultCallback.setAttachment(resultAttachment);
            try {
                attachmentCallbackHandler.handle(new Callback[]{attachmentResultCallback});
            } catch (Exception e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_ENCRYPTION, e);
            }
        }
    }

    /**
     * Processor which handles the effective enryption of the data
     */
    class InternalEncryptionOutputProcessor extends AbstractInternalEncryptionOutputProcessor {

        private boolean doEncryptedHeader = false;

        InternalEncryptionOutputProcessor(EncryptionPartDef encryptionPartDef, XMLSecStartElement xmlSecStartElement, String encoding)
                throws XMLSecurityException, XMLStreamException {

            super(encryptionPartDef, xmlSecStartElement, encoding);
            this.addBeforeProcessor(EncryptEndingOutputProcessor.class.getName());
            this.addBeforeProcessor(InternalEncryptionOutputProcessor.class.getName());
            this.addAfterProcessor(EncryptOutputProcessor.class.getName());
        }

        protected OutputStream applyTransforms(OutputStream outputStream) throws XMLSecurityException {
            String compressionAlgorithm = ((WSSSecurityProperties)getSecurityProperties()).getEncryptionCompressionAlgorithm();
            if (compressionAlgorithm != null) {
                @SuppressWarnings("unchecked")
                Class<OutputStream> transformerClass =
                        (Class<OutputStream>) TransformerAlgorithmMapper.getTransformerClass(
                                compressionAlgorithm, XMLSecurityConstants.DIRECTION.OUT
                        );
                try {
                    Constructor<OutputStream> constructor = transformerClass.getConstructor(OutputStream.class);
                    outputStream = constructor.newInstance(outputStream);
                } catch (InvocationTargetException e) {
                    throw new XMLSecurityException(e);
                } catch (NoSuchMethodException e) {
                    throw new XMLSecurityException(e);
                } catch (InstantiationException e) {
                    throw new XMLSecurityException(e);
                } catch (IllegalAccessException e) {
                    throw new XMLSecurityException(e);
                }
            }
            return outputStream;
        }

        /**
         * Creates the Data structure around the cipher data
         */
        @Override
        protected void processEventInternal(XMLSecStartElement xmlSecStartElement, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {

            List<QName> elementPath = xmlSecStartElement.getElementPath();

            //WSS 1.1 EncryptedHeader Element:
            if (elementPath.size() == 3 && WSSUtils.isInSOAPHeader(elementPath)) {
                doEncryptedHeader = true;

                List<XMLSecAttribute> attributes = new ArrayList<XMLSecAttribute>(1);

                @SuppressWarnings("unchecked")
                Iterator<Attribute> attributeIterator = getXmlSecStartElement().getAttributes();
                while (attributeIterator.hasNext()) {
                    Attribute attribute = attributeIterator.next();
                    if (!attribute.isNamespace() &&
                            (WSSConstants.NS_SOAP11.equals(attribute.getName().getNamespaceURI()) ||
                                    WSSConstants.NS_SOAP12.equals(attribute.getName().getNamespaceURI()))) {
                        attributes.add(createAttribute(attribute.getName(), attribute.getValue()));
                    }
                }
                createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse11_EncryptedHeader, true, attributes);
            }

            super.processEventInternal(xmlSecStartElement, outputProcessorChain);
            /*
            <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Id="EncDataId-1612925417"
                Type="http://www.w3.org/2001/04/xmlenc#Content">
                <xenc:EncryptionMethod xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"
                    Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc" />
                <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                    <wsse:SecurityTokenReference xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
                    <wsse:Reference xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                        URI="#EncKeyId-1483925398" />
                    </wsse:SecurityTokenReference>
                </ds:KeyInfo>
                <xenc:CipherData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
                    <xenc:CipherValue xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
                    ...
                    </xenc:CipherValue>
                </xenc:CipherData>
            </xenc:EncryptedData>
             */
        }

        @Override
        protected void createKeyInfoStructure(OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
            createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_dsig_KeyInfo, true, null);
            createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_SecurityTokenReference, true, null);

            if (WSSecurityTokenConstants.KeyIdentifier_EncryptedKeySha1Identifier.equals(
                    ((WSSSecurityProperties) getSecurityProperties()).getEncryptionKeyIdentifier())) {
                WSSUtils.createEncryptedKeySha1IdentifierStructure(this, outputProcessorChain, getEncryptionPartDef().getSymmetricKey());
            } else {
                List<XMLSecAttribute> attributes = new ArrayList<XMLSecAttribute>(1);
                attributes.add(createAttribute(WSSConstants.ATT_NULL_URI, "#" + getEncryptionPartDef().getKeyId()));
                createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_Reference, false, attributes);
                createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_Reference);
            }
            createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_SecurityTokenReference);
            createEndElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_dsig_KeyInfo);
        }

        @Override
        protected void doFinalInternal(OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {

            super.doFinalInternal(outputProcessorChain);

            if (doEncryptedHeader) {
                createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse11_EncryptedHeader);
            }
        }
    }
}
