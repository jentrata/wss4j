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

package org.apache.wss4j.dom.action;

import java.util.List;

import javax.security.auth.callback.CallbackHandler;

import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSEncryptionPart;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandler;
import org.apache.wss4j.dom.message.WSSecSignature;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

public class SignatureAction implements Action {
    public void execute(WSHandler handler, int actionToDo, Document doc, RequestData reqData)
            throws WSSecurityException {
        CallbackHandler callbackHandler = 
            handler.getPasswordCallbackHandler(reqData);
        WSPasswordCallback passwordCallback = 
            handler.getPasswordCB(reqData.getSignatureUser(), actionToDo, callbackHandler, reqData);
        WSSecSignature wsSign = new WSSecSignature(reqData.getWssConfig());

        if (reqData.getSigKeyId() != 0) {
            wsSign.setKeyIdentifierType(reqData.getSigKeyId());
        }
        if (reqData.getSigAlgorithm() != null) {
            wsSign.setSignatureAlgorithm(reqData.getSigAlgorithm());
        }
        if (reqData.getSigDigestAlgorithm() != null) {
            wsSign.setDigestAlgo(reqData.getSigDigestAlgorithm());
        }

        wsSign.setUserInfo(reqData.getSignatureUser(), passwordCallback.getPassword());
        wsSign.setUseSingleCertificate(reqData.isUseSingleCert());
        if (reqData.getSignatureParts().size() > 0) {
            wsSign.setParts(reqData.getSignatureParts());
        }
        
        if (passwordCallback.getKey() != null) {
            wsSign.setSecretKey(passwordCallback.getKey());
        }

        wsSign.setAttachmentCallbackHandler(reqData.getAttachmentCallbackHandler());

        try {
            wsSign.prepare(doc, reqData.getSigCrypto(), reqData.getSecHeader());

            Element siblingElementToPrepend = null;
            for (WSEncryptionPart part : reqData.getSignatureParts()) {
                if ("STRTransform".equals(part.getName()) && part.getId() == null) {
                    part.setId(wsSign.getSecurityTokenReferenceURI());
                } else if (reqData.isAppendSignatureAfterTimestamp()
                        && WSConstants.WSU_NS.equals(part.getNamespace())
                        && "Timestamp".equals(part.getName())) {
                    int originalSignatureActionIndex = 
                        reqData.getOriginalSignatureActionPosition();
                    // Need to figure out where to put the Signature Element in the header
                    if (originalSignatureActionIndex > 0) {
                        Element secHeader = reqData.getSecHeader().getSecurityHeader();
                        Node lastChild = secHeader.getLastChild();
                        int count = 0;
                        while (lastChild != null && count < originalSignatureActionIndex) {
                            while (lastChild != null && lastChild.getNodeType() != Node.ELEMENT_NODE) {
                                lastChild = lastChild.getPreviousSibling();
                            }
                            count++;
                        }
                        if (lastChild instanceof Element) {
                            siblingElementToPrepend = (Element)lastChild;
                        }
                    }
                }
            }

            List<javax.xml.crypto.dsig.Reference> referenceList =
                wsSign.addReferencesToSign(reqData.getSignatureParts(), reqData.getSecHeader());

            if (reqData.isAppendSignatureAfterTimestamp() && siblingElementToPrepend == null) {
                wsSign.computeSignature(referenceList, false, null);
            } else {
                wsSign.computeSignature(referenceList, true, siblingElementToPrepend);
            }

            wsSign.prependBSTElementToHeader(reqData.getSecHeader());
            reqData.getSignatureValues().add(wsSign.getSignatureValue());
        } catch (WSSecurityException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "empty", e, "Error during Signature: ");
        }
    }

}
