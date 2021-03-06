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

import javax.security.auth.callback.CallbackHandler;

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.saml.SAMLCallback;
import org.apache.wss4j.common.saml.SAMLUtil;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandler;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.dom.saml.WSSecSignatureSAML;

import org.w3c.dom.Document;

public class SAMLTokenSignedAction implements Action {
    
    private static org.slf4j.Logger log = 
        org.slf4j.LoggerFactory.getLogger(SAMLTokenSignedAction.class);

    public void execute(WSHandler handler, int actionToDo, Document doc, RequestData reqData)
            throws WSSecurityException {
        Crypto crypto = null;
        /*
        * it is possible and legal that we do not have a signature
        * crypto here - thus ignore the exception. This is usually
        * the case for the SAML option "sender vouches". In this case
        * no user crypto is required.
        */
        try {
            crypto = handler.loadSignatureCrypto(reqData);
        } catch (Exception ex) {
            if (log.isDebugEnabled()) {
                log.debug(ex.getMessage(), ex);
            }
        }

        CallbackHandler samlCallbackHandler = 
                handler.getCallbackHandler(
                    WSHandlerConstants.SAML_CALLBACK_CLASS,
                    WSHandlerConstants.SAML_CALLBACK_REF, 
                    reqData
                );
        if (samlCallbackHandler == null) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.FAILURE, 
                "noSAMLCallbackHandler"
            );
        }
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(samlCallbackHandler, samlCallback);
        
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);
        if (samlCallback.isSignAssertion()) {
            Crypto signingCrypto = samlCallback.getIssuerCrypto();
            if (signingCrypto == null) {
                signingCrypto = handler.loadSignatureCrypto(reqData);
            }
            
            samlAssertion.signAssertion(
                samlCallback.getIssuerKeyName(),
                samlCallback.getIssuerKeyPassword(), 
                samlCallback.getIssuerCrypto(),
                samlCallback.isSendKeyValue(),
                samlCallback.getCanonicalizationAlgorithm(),
                samlCallback.getSignatureAlgorithm()
            );
        }
        WSSecSignatureSAML wsSign = new WSSecSignatureSAML(reqData.getWssConfig());

        CallbackHandler callbackHandler = 
            handler.getPasswordCallbackHandler(reqData);
        WSPasswordCallback passwordCallback = 
            handler.getPasswordCB(reqData.getUsername(), actionToDo, callbackHandler, reqData);
        wsSign.setUserInfo(reqData.getUsername(), passwordCallback.getPassword());
        
        if (reqData.getSigKeyId() != 0) {
            wsSign.setKeyIdentifierType(reqData.getSigKeyId());
        }
        if (reqData.getSigAlgorithm() != null) {
            wsSign.setSignatureAlgorithm(reqData.getSigAlgorithm());
        }
        if (reqData.getSigDigestAlgorithm() != null) {
            wsSign.setDigestAlgo(reqData.getSigDigestAlgorithm());
        }

         /*
         * required to add support for the 
         * signatureParts parameter.
         * If not set WSSecSignatureSAML
         * defaults to only sign the body.
         */
        if (reqData.getSignatureParts().size() > 0) {
            wsSign.setParts(reqData.getSignatureParts());
        }

        try {
            wsSign.build(
                    doc,
                    crypto,
                    samlAssertion,
                    samlCallback.getIssuerCrypto(),
                    samlCallback.getIssuerKeyName(),
                    samlCallback.getIssuerKeyPassword(),
                    reqData.getSecHeader());
            reqData.getSignatureValues().add(wsSign.getSignatureValue());
        } catch (WSSecurityException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "empty", e, "Error when signing the SAML token: ");
        }
    }

}
