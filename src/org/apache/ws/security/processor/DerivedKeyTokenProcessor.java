/*
 * Copyright  2003-2004 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.apache.ws.security.processor;

import java.util.Vector;

import javax.security.auth.callback.CallbackHandler;

import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.conversation.ConversationConstants;
import org.apache.ws.security.conversation.dkalgo.AlgoFactory;
import org.apache.ws.security.conversation.dkalgo.DerivationAlgorithm;
import org.apache.ws.security.message.token.DerivedKeyToken;
import org.apache.ws.security.message.token.Reference;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.util.Base64;
import org.w3c.dom.Element;

/**
 *
 * @author Ruchith Fernando (ruchith.fernando@gmail.com)
 */
public class DerivedKeyTokenProcessor implements Processor {

    private String id;
    private byte[] keyBytes;
    
    private byte[] secret;
    private int length;
    private int offset;
    private byte[] nonce;
    private String label;
    private String algorithm;
    
    public void handleToken(Element elem, Crypto crypto, Crypto decCrypto,
            CallbackHandler cb, WSDocInfo wsDocInfo, Vector returnResults,
            WSSConfig config) throws WSSecurityException {
        
        //Deserialize the DKT
        DerivedKeyToken dkt = new DerivedKeyToken(elem);
        
        this.extractSecret(wsDocInfo, dkt);
        
        String tempNonce = dkt.getNonce();
        if(tempNonce == null) {
            throw new WSSecurityException("Missing wsc:Nonce value");
        }
        this.nonce = Base64.decode(tempNonce);
        
        this.length = dkt.getLength();
    
        this.label = dkt.getLabel();
        
        this.algorithm = dkt.getAlgorithm();
        
        this.id = dkt.getID();

        if(length > 0) {
            this.deriveKey();
        }
    }

    private void deriveKey() throws WSSecurityException{
        try {
            DerivationAlgorithm algo = AlgoFactory.getInstance(this.algorithm);
            byte[] labelBytes = null;
            if(label == null || (label != null && label.length() == 0)) {
                labelBytes = ConversationConstants.DEFAULT_LABEL.getBytes("UTF-8");
            } else {
                labelBytes = this.label.getBytes("UTF-8");
            }
            
            byte[] seed = new byte[labelBytes.length + nonce.length];
            System.arraycopy(labelBytes, 0, seed, 0, labelBytes.length);
            System.arraycopy(nonce, 0, seed, labelBytes.length, nonce.length);
            
            this.keyBytes = algo.createKey(this.secret, seed, offset, length);
            
        } catch (Exception e) {
            throw new WSSecurityException(e.getMessage(), e);
        }
    }

    /**
     * @param wsDocInfo
     * @param dkt
     * @throws WSSecurityException
     */
    private void extractSecret(WSDocInfo wsDocInfo, DerivedKeyToken dkt) throws WSSecurityException {
        SecurityTokenReference str = dkt.getSecuityTokenReference();
        if(str != null) {
            Reference ref = str.getReference();
            String uri = ref.getURI();
            Processor processor = wsDocInfo.getProcessor(uri);
            if(processor instanceof EncryptedKeyProcessor) {
                this.secret = ((EncryptedKeyProcessor)processor).getDecryptedBytes();
            }
        }
    }

    /**
     * Returns the wsu:Id of the DerivedKeyToken
     * @see org.apache.ws.security.processor.Processor#getId()
     */
    public String getId() {
        return this.id;
    }

    /**
     * @return Returns the keyBytes.
     */
    public byte[] getKeyBytes() {
        return keyBytes;
    }
    
    /**
     * Get the derived key bytes for a given length
     * @return Returns the keyBytes.
     */
    public byte[] getKeyBytes(int length) throws WSSecurityException {
        this.length = length;
        this.deriveKey();
        return keyBytes;
    } 

}