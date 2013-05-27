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
import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.binding.soap.interceptor.AbstractSoapInterceptor;
import org.apache.cxf.interceptor.*;
import org.apache.cxf.message.Attachment;
import org.apache.cxf.message.Exchange;
import org.apache.cxf.message.Message;
import org.apache.cxf.phase.AbstractPhaseInterceptor;
import org.apache.cxf.phase.Phase;

import org.apache.wss4j.common.ext.AttachmentRequestCallback;
import org.apache.wss4j.common.ext.AttachmentResultCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.stax.WSSec;
import org.apache.wss4j.stax.ext.OutboundWSSec;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;

import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEventListener;

import javax.activation.DataHandler;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.util.*;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SecurityOutInterceptor extends AbstractSoapInterceptor {

    //public static final SecurityOutInterceptorEndingInterceptor ENDING = new SecurityOutInterceptorEndingInterceptor();
    public static final String OUTPUT_STREAM_HOLDER = SecurityOutInterceptor.class.getName() + ".outputstream";
    public static final String FORCE_START_DOCUMENT = "org.apache.cxf.stax.force-start-document";

    private WSSSecurityProperties wssSecurityProperties;

    public SecurityOutInterceptor(String p, WSSSecurityProperties wssSecurityProperties) throws Exception {
        super(p);
        getAfter().add(StaxOutInterceptor.class.getName());
        this.wssSecurityProperties = wssSecurityProperties;
    }

    @Override
    public void handleMessage(final SoapMessage soapMessage) throws Fault {

        //OutputStream os = soapMessage.getContent(OutputStream.class);
        XMLStreamWriter xwriter = soapMessage.getContent(XMLStreamWriter.class);

        String encoding = getEncoding(soapMessage);

        final List<SecurityEvent> outgoingSecurityEventList = new ArrayList<SecurityEvent>();
        SecurityEventListener securityEventListener = new SecurityEventListener() {
            @Override
            public void registerSecurityEvent(SecurityEvent securityEvent) throws WSSecurityException {
                outgoingSecurityEventList.add(securityEvent);
            }
        };
        soapMessage.getExchange().put(SecurityEvent.class.getName() + ".out", outgoingSecurityEventList);

        XMLStreamWriter newXMLStreamWriter;
        try {
            final List<SecurityEvent> requestSecurityEvents = (List<SecurityEvent>) soapMessage.getExchange().get(SecurityEvent.class.getName() + ".in");

            WSSSecurityProperties wssSecurityProperties = new WSSSecurityProperties(this.wssSecurityProperties);
            wssSecurityProperties.setAttachmentCallbackHandler(new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    for (int i = 0; i < callbacks.length; i++) {
                        Callback callback = callbacks[i];
                        if (callback instanceof AttachmentRequestCallback) {
                            AttachmentRequestCallback attachmentRequestCallback = (AttachmentRequestCallback) callback;

                            List<org.apache.wss4j.common.ext.Attachment> attachmentList =
                                    new ArrayList<org.apache.wss4j.common.ext.Attachment>();
                            attachmentRequestCallback.setAttachments(attachmentList);

                            final Collection<Attachment> attachments = soapMessage.getAttachments();
                            for (Iterator<org.apache.cxf.message.Attachment> iterator = attachments.iterator(); iterator.hasNext(); ) {
                                org.apache.cxf.message.Attachment attachment = iterator.next();

                                org.apache.wss4j.common.ext.Attachment att =
                                        new org.apache.wss4j.common.ext.Attachment();
                                att.setMimeType(attachment.getDataHandler().getContentType());
                                att.setId(attachment.getId());
                                att.setSourceStream(attachment.getDataHandler().getInputStream());
                                //todo workaround for Content-ID header. it isn't stored as header...
                                //todo misssing other headers too?
                                att.addHeader("Content-ID", "<" + attachment.getId() + ">");
                                Iterator<String> headerIterator = attachment.getHeaderNames();
                                while (headerIterator.hasNext()) {
                                    String next = headerIterator.next();
                                    att.addHeader(next, attachment.getHeader(next));
                                }
                                attachmentList.add(att);

                                iterator.remove();
                            }

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
            final OutboundWSSec outboundWSSec = WSSec.getOutboundWSSec(wssSecurityProperties);
            newXMLStreamWriter = outboundWSSec.processOutMessage(xwriter, encoding, requestSecurityEvents, securityEventListener);
            soapMessage.setContent(XMLStreamWriter.class, newXMLStreamWriter);
        } catch (WSSecurityException e) {
            throw new Fault(e);
        }

        soapMessage.put(AbstractOutDatabindingInterceptor.DISABLE_OUTPUTSTREAM_OPTIMIZATION,
                Boolean.TRUE);
        soapMessage.put(FORCE_START_DOCUMENT, Boolean.TRUE);

        StaxOutEndingInterceptor staxOutEndingInterceptor = null;
        Iterator<Interceptor<? extends Message>> interceptorIterator = soapMessage.getInterceptorChain().iterator();
        while (interceptorIterator.hasNext()) {
            Interceptor<? extends Message> interceptor = interceptorIterator.next();
            if (interceptor.getClass().equals(StaxOutEndingInterceptor.class)) {
                staxOutEndingInterceptor = (StaxOutEndingInterceptor)interceptor;
                break;
            }
        }
        if (staxOutEndingInterceptor != null) {
            soapMessage.getInterceptorChain().remove(staxOutEndingInterceptor);
            staxOutEndingInterceptor.getAfter().clear();
            staxOutEndingInterceptor.getBefore().add(AttachmentOutInterceptor.AttachmentOutEndingInterceptor.class.getName());
            soapMessage.getInterceptorChain().add(staxOutEndingInterceptor);
        }

        /*if (MessageUtils.getContextualBoolean(soapMessage, FORCE_START_DOCUMENT, false)) {
            try {
                newXMLStreamWriter.writeStartDocument(encoding, "1.0");
            } catch (XMLStreamException e) {
                throw new Fault(e);
            }
            //soapMessage.removeContent(OutputStream.class);
            soapMessage.put(OUTPUT_STREAM_HOLDER, os);
        }

        // Add a final interceptor to write end elements
        soapMessage.getInterceptorChain().add(ENDING);*/
    }

    private String getEncoding(Message message) {
        Exchange ex = message.getExchange();
        String encoding = (String) message.get(Message.ENCODING);
        if (encoding == null && ex.getInMessage() != null) {
            encoding = (String) ex.getInMessage().get(Message.ENCODING);
            message.put(Message.ENCODING, encoding);
        }

        if (encoding == null) {
            encoding = "UTF-8";
            message.put(Message.ENCODING, encoding);
        }
        return encoding;
    }

    public static class SecurityOutInterceptorEndingInterceptor extends AbstractPhaseInterceptor<Message> {

        public SecurityOutInterceptorEndingInterceptor() {
            super(Phase.PRE_STREAM_ENDING);
            getAfter().add(AttachmentOutInterceptor.AttachmentOutEndingInterceptor.class.getName());
        }

        @Override
        public void handleMessage(Message message) throws Fault {
            try {
                XMLStreamWriter xtw = message.getContent(XMLStreamWriter.class);
                if (xtw != null) {
                    xtw.writeEndDocument();
                    xtw.flush();
                    xtw.close();
                }

                OutputStream os = (OutputStream) message.get(OUTPUT_STREAM_HOLDER);
                if (os != null) {
                    message.setContent(OutputStream.class, os);
                }
                message.removeContent(XMLStreamWriter.class);
            } catch (XMLStreamException e) {
                throw new Fault(e);
            }
        }
    }
}