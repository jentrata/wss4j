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
package org.apache.wss4j.stax.ext;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.stax.impl.processor.output.*;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.OutputProcessor;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.impl.DocumentContextImpl;
import org.apache.xml.security.stax.impl.OutboundSecurityContextImpl;
import org.apache.xml.security.stax.impl.OutputProcessorChainImpl;
import org.apache.xml.security.stax.impl.XMLSecurityStreamWriter;
import org.apache.xml.security.stax.impl.processor.output.FinalOutputProcessor;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEventListener;

import javax.xml.stream.XMLStreamWriter;
import java.io.OutputStream;
import java.util.List;

/**
 * Outbound Streaming-WebService-Security
 * An instance of this class can be retrieved over the WSSec class
 */
public class OutboundWSSec {

    private final WSSSecurityProperties securityProperties;

    public OutboundWSSec(WSSSecurityProperties securityProperties) {
        this.securityProperties = securityProperties;
    }

    /**
     * This method is the entry point for the incoming security-engine.
     * Hand over a outputStream and use the returned XMLStreamWriter for further processing
     *
     * @param outputStream The original outputStream
     * @return A new XMLStreamWriter which does transparently the security processing.
     * @throws WSSecurityException thrown when a Security failure occurs
     */
    public XMLStreamWriter processOutMessage(
            OutputStream outputStream, String encoding,
            List<SecurityEvent> requestSecurityEvents) throws WSSecurityException {
        return processOutMessage(outputStream, encoding, requestSecurityEvents, null);
    }

    /**
     * This method is the entry point for the incoming security-engine.
     * Hand over the original XMLStreamWriter and use the returned one for further processing
     *
     * @param xmlStreamWriter The original xmlStreamWriter
     * @return A new XMLStreamWriter which does transparently the security processing.
     * @throws WSSecurityException thrown when a Security failure occurs
     */
    public XMLStreamWriter processOutMessage(
            XMLStreamWriter xmlStreamWriter, String encoding,
            List<SecurityEvent> requestSecurityEvents) throws WSSecurityException {
        return processOutMessage(xmlStreamWriter, encoding, requestSecurityEvents, null);
    }

    /**
     * This method is the entry point for the incoming security-engine.
     * Hand over a outputstream and use the returned XMLStreamWriter for further processing
     *
     * @param outputStream The original outputStream
     * @return A new XMLStreamWriter which does transparently the security processing.
     * @throws WSSecurityException thrown when a Security failure occurs
     */
    public XMLStreamWriter processOutMessage(
            OutputStream outputStream, String encoding, List<SecurityEvent> requestSecurityEvents,
            SecurityEventListener securityEventListener) throws WSSecurityException {
        return processOutMessage((Object) outputStream, encoding, requestSecurityEvents, securityEventListener);
    }

    /**
     * This method is the entry point for the incoming security-engine.
     * Hand over the original XMLStreamWriter and use the returned one for further processing
     *
     * @param xmlStreamWriter The original outputStream
     * @return A new XMLStreamWriter which does transparently the security processing.
     * @throws WSSecurityException thrown when a Security failure occurs
     */
    public XMLStreamWriter processOutMessage(
            XMLStreamWriter xmlStreamWriter, String encoding, List<SecurityEvent> requestSecurityEvents,
            SecurityEventListener securityEventListener) throws WSSecurityException {
        return processOutMessage((Object) xmlStreamWriter, encoding, requestSecurityEvents, securityEventListener);
    }

    private XMLStreamWriter processOutMessage(
            Object output, String encoding, List<SecurityEvent> requestSecurityEvents,
            SecurityEventListener securityEventListener) throws WSSecurityException {

        final OutboundSecurityContextImpl outboundSecurityContext = new OutboundSecurityContextImpl();
        outboundSecurityContext.putList(SecurityEvent.class, requestSecurityEvents);
        outboundSecurityContext.addSecurityEventListener(securityEventListener);

        final DocumentContextImpl documentContext = new DocumentContextImpl();
        documentContext.setEncoding(encoding);

        OutputProcessorChainImpl outputProcessorChain = new OutputProcessorChainImpl(outboundSecurityContext, documentContext);

        try {
            final SecurityHeaderOutputProcessor securityHeaderOutputProcessor = new SecurityHeaderOutputProcessor();
            initializeOutputProcessor(outputProcessorChain, securityHeaderOutputProcessor, null);
            //todo some combinations are not possible atm: eg Action.SIGNATURE and Action.USERNAMETOKEN_SIGNED
            //todo they use the same signaure parts
            for (int i = 0; i < securityProperties.getOutAction().length; i++) {
                XMLSecurityConstants.Action action = securityProperties.getOutAction()[i];
                if (WSSConstants.TIMESTAMP.equals(action)) {
                    final TimestampOutputProcessor timestampOutputProcessor = new TimestampOutputProcessor();
                    initializeOutputProcessor(outputProcessorChain, timestampOutputProcessor, action);

                } else if (WSSConstants.SIGNATURE.equals(action)) {
                    final BinarySecurityTokenOutputProcessor binarySecurityTokenOutputProcessor =
                            new BinarySecurityTokenOutputProcessor();
                    initializeOutputProcessor(outputProcessorChain, binarySecurityTokenOutputProcessor, action);

                    final WSSSignatureOutputProcessor signatureOutputProcessor = new WSSSignatureOutputProcessor();
                    initializeOutputProcessor(outputProcessorChain, signatureOutputProcessor, action);

                } else if (WSSConstants.ENCRYPT.equals(action)) {
                    final BinarySecurityTokenOutputProcessor binarySecurityTokenOutputProcessor =
                            new BinarySecurityTokenOutputProcessor();
                    initializeOutputProcessor(outputProcessorChain, binarySecurityTokenOutputProcessor, action);

                    final EncryptedKeyOutputProcessor encryptedKeyOutputProcessor = new EncryptedKeyOutputProcessor();
                    initializeOutputProcessor(outputProcessorChain, encryptedKeyOutputProcessor, action);

                    final EncryptOutputProcessor encryptOutputProcessor = new EncryptOutputProcessor();
                    initializeOutputProcessor(outputProcessorChain, encryptOutputProcessor, action);

                } else if (WSSConstants.USERNAMETOKEN.equals(action)) {
                    final UsernameTokenOutputProcessor usernameTokenOutputProcessor = new UsernameTokenOutputProcessor();
                    initializeOutputProcessor(outputProcessorChain, usernameTokenOutputProcessor, action);

                } else if (WSSConstants.USERNAMETOKEN_SIGNED.equals(action)) {
                    final UsernameTokenOutputProcessor usernameTokenOutputProcessor = new UsernameTokenOutputProcessor();
                    initializeOutputProcessor(outputProcessorChain, usernameTokenOutputProcessor, action);

                    final WSSSignatureOutputProcessor signatureOutputProcessor = new WSSSignatureOutputProcessor();
                    initializeOutputProcessor(outputProcessorChain, signatureOutputProcessor, action);

                } else if (WSSConstants.SIGNATURE_WITH_DERIVED_KEY.equals(action)) {
                    final BinarySecurityTokenOutputProcessor binarySecurityTokenOutputProcessor =
                            new BinarySecurityTokenOutputProcessor();
                    initializeOutputProcessor(outputProcessorChain, binarySecurityTokenOutputProcessor, action);

                    if (securityProperties.getDerivedKeyTokenReference() == WSSConstants.DerivedKeyTokenReference.EncryptedKey) {
                        final EncryptedKeyOutputProcessor encryptedKeyOutputProcessor = new EncryptedKeyOutputProcessor();
                        initializeOutputProcessor(outputProcessorChain, encryptedKeyOutputProcessor, action);

                    } else if (securityProperties.getDerivedKeyTokenReference() == WSSConstants.DerivedKeyTokenReference.SecurityContextToken) {
                        final SecurityContextTokenOutputProcessor securityContextTokenOutputProcessor =
                                new SecurityContextTokenOutputProcessor();
                        initializeOutputProcessor(outputProcessorChain, securityContextTokenOutputProcessor, action);

                    }
                    final DerivedKeyTokenOutputProcessor derivedKeyTokenOutputProcessor = new DerivedKeyTokenOutputProcessor();
                    initializeOutputProcessor(outputProcessorChain, derivedKeyTokenOutputProcessor, action);

                    final WSSSignatureOutputProcessor signatureOutputProcessor = new WSSSignatureOutputProcessor();
                    initializeOutputProcessor(outputProcessorChain, signatureOutputProcessor, action);

                } else if (WSSConstants.ENCRYPT_WITH_DERIVED_KEY.equals(action)) {
                    final BinarySecurityTokenOutputProcessor binarySecurityTokenOutputProcessor =
                            new BinarySecurityTokenOutputProcessor();
                    initializeOutputProcessor(outputProcessorChain, binarySecurityTokenOutputProcessor, action);

                    if (securityProperties.getDerivedKeyTokenReference() == WSSConstants.DerivedKeyTokenReference.EncryptedKey) {
                        final EncryptedKeyOutputProcessor encryptedKeyOutputProcessor = new EncryptedKeyOutputProcessor();
                        initializeOutputProcessor(outputProcessorChain, encryptedKeyOutputProcessor, action);

                    } else if (securityProperties.getDerivedKeyTokenReference() == WSSConstants.DerivedKeyTokenReference.SecurityContextToken) {
                        final SecurityContextTokenOutputProcessor securityContextTokenOutputProcessor =
                                new SecurityContextTokenOutputProcessor();
                        initializeOutputProcessor(outputProcessorChain, securityContextTokenOutputProcessor, action);

                    }
                    final DerivedKeyTokenOutputProcessor derivedKeyTokenOutputProcessor = new DerivedKeyTokenOutputProcessor();
                    initializeOutputProcessor(outputProcessorChain, derivedKeyTokenOutputProcessor, action);

                    final EncryptOutputProcessor encryptOutputProcessor = new EncryptOutputProcessor();
                    initializeOutputProcessor(outputProcessorChain, encryptOutputProcessor, action);

                } else if (WSSConstants.SAML_TOKEN_SIGNED.equals(action)) {
                    final SAMLTokenOutputProcessor samlTokenOutputProcessor = new SAMLTokenOutputProcessor();
                    initializeOutputProcessor(outputProcessorChain, samlTokenOutputProcessor, action);

                    final WSSSignatureOutputProcessor signatureOutputProcessor = new WSSSignatureOutputProcessor();
                    initializeOutputProcessor(outputProcessorChain, signatureOutputProcessor, action);

                } else if (WSSConstants.SAML_TOKEN_UNSIGNED.equals(action)) {
                    final SAMLTokenOutputProcessor samlTokenOutputProcessor = new SAMLTokenOutputProcessor();
                    initializeOutputProcessor(outputProcessorChain, samlTokenOutputProcessor, action);
                } else if (WSSConstants.SIGNATURE_WITH_KERBEROS_TOKEN.equals(action)) {
                    final KerberosSecurityTokenOutputProcessor kerberosTokenOutputProcessor =
                            new KerberosSecurityTokenOutputProcessor();
                    initializeOutputProcessor(outputProcessorChain, kerberosTokenOutputProcessor, action);

                    final WSSSignatureOutputProcessor signatureOutputProcessor = new WSSSignatureOutputProcessor();
                    initializeOutputProcessor(outputProcessorChain, signatureOutputProcessor, action);
                } else if (WSSConstants.ENCRYPT_WITH_KERBEROS_TOKEN.equals(action)) {
                    final KerberosSecurityTokenOutputProcessor kerberosTokenOutputProcessor =
                            new KerberosSecurityTokenOutputProcessor();
                    initializeOutputProcessor(outputProcessorChain, kerberosTokenOutputProcessor, action);

                    final EncryptOutputProcessor encryptOutputProcessor = new EncryptOutputProcessor();
                    initializeOutputProcessor(outputProcessorChain, encryptOutputProcessor, action);
                }
            }
            
            final SecurityHeaderReorderProcessor securityHeaderReorderProcessor = new SecurityHeaderReorderProcessor();
            initializeOutputProcessor(outputProcessorChain, securityHeaderReorderProcessor, null);
            
            if (output instanceof OutputStream) {
                final FinalOutputProcessor finalOutputProcessor = new FinalOutputProcessor((OutputStream) output, encoding);
                initializeOutputProcessor(outputProcessorChain, finalOutputProcessor, null);

            } else if (output instanceof XMLStreamWriter) {
                final FinalOutputProcessor finalOutputProcessor = new FinalOutputProcessor((XMLStreamWriter) output);
                initializeOutputProcessor(outputProcessorChain, finalOutputProcessor, null);

            } else {
                throw new IllegalArgumentException(output + " is not supported as output");
            }
        } catch (XMLSecurityException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
        }
        return new XMLSecurityStreamWriter(outputProcessorChain);
    }

    private void initializeOutputProcessor(
            OutputProcessorChainImpl outputProcessorChain, OutputProcessor outputProcessor,
            XMLSecurityConstants.Action action) throws XMLSecurityException {
        outputProcessor.setXMLSecurityProperties(securityProperties);
        outputProcessor.setAction(action);
        outputProcessor.init(outputProcessorChain);
    }
}
