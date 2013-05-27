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
package org.apache.wss4j.cxfIntegration.interceptor;

import org.apache.cxf.attachment.AttachmentDataSource;
import org.apache.cxf.binding.soap.SoapFault;
import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.binding.soap.interceptor.AbstractSoapInterceptor;
import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.interceptor.StaxInInterceptor;

import org.apache.cxf.message.Message;
import org.apache.cxf.phase.AbstractPhaseInterceptor;
import org.apache.cxf.phase.Phase;
import org.apache.wss4j.common.ext.Attachment;
import org.apache.wss4j.common.ext.AttachmentRequestCallback;
import org.apache.wss4j.common.ext.AttachmentResultCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.stax.WSSec;
import org.apache.wss4j.stax.ext.InboundWSSec;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;

import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEventListener;

import javax.activation.DataHandler;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import java.io.IOException;
import java.util.*;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SecurityInInterceptor extends AbstractSoapInterceptor {

    private static final Set<QName> HEADERS = new HashSet<QName>();

    static {
        HEADERS.add(WSSConstants.TAG_wsse_Security);
        HEADERS.add(WSSConstants.TAG_xenc_EncryptedData);
    }

    private WSSSecurityProperties wssSecurityProperties;

    public SecurityInInterceptor(String p, WSSSecurityProperties wssSecurityProperties) throws Exception {
        super(p);
        getAfter().add(StaxInInterceptor.class.getName());
        this.wssSecurityProperties = wssSecurityProperties;
    }

    @Override
    public void handleMessage(final SoapMessage soapMessage) throws Fault {

        XMLStreamReader originalXmlStreamReader = soapMessage.getContent(XMLStreamReader.class);
        XMLStreamReader newXmlStreamReader;

        final List<SecurityEvent> incomingSecurityEventList = new LinkedList<SecurityEvent>();
        SecurityEventListener securityEventListener = new SecurityEventListener() {
            @Override
            public void registerSecurityEvent(SecurityEvent securityEvent) throws WSSecurityException {
                incomingSecurityEventList.add(securityEvent);
            }
        };
        soapMessage.getExchange().put(SecurityEvent.class.getName() + ".in", incomingSecurityEventList);

        try {
            final List<SecurityEvent> requestSecurityEvents = (List<SecurityEvent>) soapMessage.getExchange().get(SecurityEvent.class.getName() + ".out");

            WSSSecurityProperties wssSecurityProperties = new WSSSecurityProperties(this.wssSecurityProperties);
            wssSecurityProperties.setAttachmentCallbackHandler(new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    for (int i = 0; i < callbacks.length; i++) {
                        Callback callback = callbacks[i];
                        if (callback instanceof AttachmentRequestCallback) {
                            AttachmentRequestCallback attachmentRequestCallback = (AttachmentRequestCallback) callback;

                            List<org.apache.wss4j.common.ext.Attachment> attachmentList =
                                    new ArrayList<Attachment>();
                            attachmentRequestCallback.setAttachments(attachmentList);

                            org.apache.cxf.message.Attachment attachment = null;

                            final Collection<org.apache.cxf.message.Attachment> attachments = soapMessage.getAttachments();
                            for (Iterator<org.apache.cxf.message.Attachment> iterator = attachments.iterator(); iterator.hasNext(); ) {
                                attachment = iterator.next();

                                if (!attachmentRequestCallback.getAttachmentId().equals(attachment.getId())) {
                                    continue;
                                }

                                org.apache.wss4j.common.ext.Attachment att =
                                        new org.apache.wss4j.common.ext.Attachment();
                                att.setMimeType(attachment.getDataHandler().getContentType());
                                att.setId(attachment.getId());
                                att.setSourceStream(attachment.getDataHandler().getInputStream());
                                Iterator<String> headerIterator = attachment.getHeaderNames();
                                while (headerIterator.hasNext()) {
                                    String next = headerIterator.next();
                                    att.addHeader(next, attachment.getHeader(next));
                                }
                                attachmentList.add(att);

                                //todo we receive an java.lang.IndexOutOfBoundsException: Index: 1, Size: 1 if we call iterator.remove() here...
                                //iterator.remove();
                            }
                            //todo ...so we remove it manually for now:
                            soapMessage.getAttachments().remove(attachment);


                        } else if (callback instanceof AttachmentResultCallback) {
                            AttachmentResultCallback attachmentResultCallback = (AttachmentResultCallback) callback;

                            final Collection<org.apache.cxf.message.Attachment> attachments = soapMessage.getAttachments();

                            org.apache.cxf.attachment.AttachmentImpl securedAttachment =
                                    new org.apache.cxf.attachment.AttachmentImpl(
                                            attachmentResultCallback.getAttachmentId(),
                                            new DataHandler(
                                                    new AttachmentDataSource(
                                                            attachmentResultCallback.getAttachment().getMimeType(),
                                                            attachmentResultCallback.getAttachment().getSourceStream())
                                            )
                                    );
                            Map<String, String> headers = attachmentResultCallback.getAttachment().getHeaders();
                            Iterator<Map.Entry<String, String>> iterator = headers.entrySet().iterator();
                            while (iterator.hasNext()) {
                                Map.Entry<String, String> next = iterator.next();
                                securedAttachment.setHeader(next.getKey(), next.getValue());
                            }
                            attachments.add(securedAttachment);

                        } else {
                            throw new UnsupportedCallbackException(callback, "Unsupported callback");
                        }
                    }
                }
            });
            final InboundWSSec inboundWSSec = WSSec.getInboundWSSec(wssSecurityProperties);
            newXmlStreamReader = inboundWSSec.processInMessage(originalXmlStreamReader, requestSecurityEvents, securityEventListener);
            soapMessage.setContent(XMLStreamReader.class, newXmlStreamReader);

            //Warning: The exceptions which can occur here are not security relevant exceptions but configuration-errors.
            //To catch security relevant exceptions you have to catch them e.g.in the FaultOutInterceptor.
            //Why? Because we do streaming security. This interceptor doesn't handle the ws-security stuff but just
            //setup the relevant stuff for it. Exceptions will be thrown as a wrapped XMLStreamException during further
            //processing in the WS-Stack.

        } catch (WSSecurityException e) {
            throw new SoapFault("unexpected service error", SoapFault.FAULT_CODE_SERVER);
        } catch (XMLStreamException e) {
            throw new SoapFault("unexpected service error", SoapFault.FAULT_CODE_SERVER);
        }

        soapMessage.getInterceptorChain().add(new SecurityInEndingInterceptor());
    }

    @Override
    public Set<QName> getUnderstoodHeaders() {
        return HEADERS;
    }

    public static class SecurityInEndingInterceptor extends AbstractPhaseInterceptor<Message> {

        public SecurityInEndingInterceptor() {
            super(Phase.PRE_INVOKE);
            getBefore().add("org.apache.cxf.jaxws.interceptors.SwAInInterceptor");
        }

        @Override
        public void handleMessage(Message message) throws Fault {
            try {
                XMLStreamReader xmlStreamReader = message.getContent(XMLStreamReader.class);
                if (xmlStreamReader != null) {
                    while (xmlStreamReader.hasNext()) {
                        xmlStreamReader.next();
                    }
                    xmlStreamReader.close();
                    message.removeContent(XMLStreamReader.class);
                }
            } catch (XMLStreamException e) {
                throw new Fault(e);
            }
        }
    }
}
