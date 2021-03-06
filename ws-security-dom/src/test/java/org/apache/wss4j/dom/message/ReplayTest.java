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

import java.util.ArrayList;
import java.util.List;

import javax.security.auth.callback.CallbackHandler;

import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSEncryptionPart;
import org.apache.wss4j.dom.WSSConfig;
import org.apache.wss4j.dom.WSSecurityEngine;
import org.apache.wss4j.dom.WSSecurityEngineResult;
import org.apache.wss4j.dom.common.KeystoreCallbackHandler;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.common.UsernamePasswordCallbackHandler;
import org.apache.wss4j.common.cache.MemoryReplayCache;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Some test-cases for replay attacks.
 */
public class ReplayTest extends org.junit.Assert {
    private static final org.slf4j.Logger LOG = 
        org.slf4j.LoggerFactory.getLogger(ReplayTest.class);
    
    private CallbackHandler callbackHandler = new KeystoreCallbackHandler();
    private Crypto crypto = null;
    
    public ReplayTest() throws Exception {
        crypto = CryptoFactory.getInstance();
    }

    @org.junit.Test
    public void testReplayedTimestamp() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        WSSecTimestamp timestamp = new WSSecTimestamp();
        timestamp.setTimeToLive(300);
        Document createdDoc = timestamp.build(doc, secHeader);
        
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        
        List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
        WSEncryptionPart encP =
            new WSEncryptionPart(
                "Timestamp", WSConstants.WSU_NS, "");
        parts.add(encP);
        builder.setParts(parts);
        
        builder.prepare(createdDoc, crypto, secHeader);
        
        List<javax.xml.crypto.dsig.Reference> referenceList = 
            builder.addReferencesToSign(parts, secHeader);

        builder.computeSignature(referenceList, false, null);

        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(createdDoc);
            LOG.debug(outputString);
        }
        
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        RequestData data = new RequestData();
        data.setWssConfig(wssConfig);
        data.setCallbackHandler(callbackHandler);
        data.setTimestampReplayCache(new MemoryReplayCache());
        
        // Successfully verify timestamp
        verify(createdDoc, wssConfig, data);
        
        // Now try again - a replay attack should be detected
        try {
            verify(createdDoc, wssConfig, data);
            fail("Expected failure on a replay attack");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY); 
        }   
    }
    
    @org.junit.Test
    public void testEhCacheReplayedTimestamp() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        WSSecTimestamp timestamp = new WSSecTimestamp();
        timestamp.setTimeToLive(300);
        Document createdDoc = timestamp.build(doc, secHeader);
        
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        
        List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
        WSEncryptionPart encP =
            new WSEncryptionPart(
                "Timestamp", WSConstants.WSU_NS, "");
        parts.add(encP);
        builder.setParts(parts);
        
        builder.prepare(createdDoc, crypto, secHeader);
        
        List<javax.xml.crypto.dsig.Reference> referenceList = 
            builder.addReferencesToSign(parts, secHeader);

        builder.computeSignature(referenceList, false, null);

        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(createdDoc);
            LOG.debug(outputString);
        }
        
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        RequestData data = new RequestData();
        data.setWssConfig(wssConfig);
        data.setCallbackHandler(callbackHandler);
        
        // Successfully verify timestamp
        verify(createdDoc, wssConfig, data);
        
        // Now try again - a replay attack should be detected
        try {
            verify(createdDoc, wssConfig, data);
            fail("Expected failure on a replay attack");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY); 
        }   
    }
    
    @org.junit.Test
    public void testReplayedTimestampBelowSignature() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        WSSecTimestamp timestamp = new WSSecTimestamp();
        timestamp.setTimeToLive(300);
        Document createdDoc = timestamp.build(doc, secHeader);
        
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        
        List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
        WSEncryptionPart encP =
            new WSEncryptionPart(
                "Timestamp", WSConstants.WSU_NS, "");
        parts.add(encP);
        builder.setParts(parts);
        
        builder.build(createdDoc, crypto, secHeader);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(createdDoc);
            LOG.debug(outputString);
        }
        
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        RequestData data = new RequestData();
        data.setWssConfig(wssConfig);
        data.setCallbackHandler(callbackHandler);
        data.setTimestampReplayCache(new MemoryReplayCache());
        
        // Successfully verify timestamp
        verify(createdDoc, wssConfig, data);
        
        // Now try again - a replay attack should be detected
        try {
            verify(createdDoc, wssConfig, data);
            fail("Expected failure on a replay attack");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY); 
        }   
    }
    
    @org.junit.Test
    public void testEhCacheReplayedTimestampBelowSignature() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        WSSecTimestamp timestamp = new WSSecTimestamp();
        timestamp.setTimeToLive(300);
        Document createdDoc = timestamp.build(doc, secHeader);
        
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        
        List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
        WSEncryptionPart encP =
            new WSEncryptionPart(
                "Timestamp", WSConstants.WSU_NS, "");
        parts.add(encP);
        builder.setParts(parts);
        
        builder.build(createdDoc, crypto, secHeader);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(createdDoc);
            LOG.debug(outputString);
        }
        
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        RequestData data = new RequestData();
        data.setWssConfig(wssConfig);
        data.setCallbackHandler(callbackHandler);
        
        // Successfully verify timestamp
        verify(createdDoc, wssConfig, data);
        
        // Now try again - a replay attack should be detected
        try {
            verify(createdDoc, wssConfig, data);
            fail("Expected failure on a replay attack");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY); 
        }   
    }
    
    @org.junit.Test
    public void testReplayedTimestampNoExpires() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        WSSecTimestamp timestamp = new WSSecTimestamp();
        timestamp.setTimeToLive(0);
        Document createdDoc = timestamp.build(doc, secHeader);
        
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        
        List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
        WSEncryptionPart encP =
            new WSEncryptionPart(
                "Timestamp", WSConstants.WSU_NS, "");
        parts.add(encP);
        builder.setParts(parts);
        
        builder.prepare(createdDoc, crypto, secHeader);
        
        List<javax.xml.crypto.dsig.Reference> referenceList = 
            builder.addReferencesToSign(parts, secHeader);

        builder.computeSignature(referenceList, false, null);

        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(createdDoc);
            LOG.debug(outputString);
        }
        
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        RequestData data = new RequestData();
        data.setWssConfig(wssConfig);
        data.setCallbackHandler(callbackHandler);
        data.setTimestampReplayCache(new MemoryReplayCache());
        
        // Successfully verify timestamp
        verify(createdDoc, wssConfig, data);
        
        // Now try again - a replay attack should be detected
        try {
            verify(createdDoc, wssConfig, data);
            fail("Expected failure on a replay attack");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY); 
        }   
    }
    
    @org.junit.Test
    public void testEhCacheReplayedTimestampNoExpires() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        WSSecTimestamp timestamp = new WSSecTimestamp();
        timestamp.setTimeToLive(0);
        Document createdDoc = timestamp.build(doc, secHeader);
        
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        
        List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
        WSEncryptionPart encP =
            new WSEncryptionPart(
                "Timestamp", WSConstants.WSU_NS, "");
        parts.add(encP);
        builder.setParts(parts);
        
        builder.prepare(createdDoc, crypto, secHeader);
        
        List<javax.xml.crypto.dsig.Reference> referenceList = 
            builder.addReferencesToSign(parts, secHeader);

        builder.computeSignature(referenceList, false, null);

        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(createdDoc);
            LOG.debug(outputString);
        }
        
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        RequestData data = new RequestData();
        data.setWssConfig(wssConfig);
        data.setCallbackHandler(callbackHandler);
        
        // Successfully verify timestamp
        verify(createdDoc, wssConfig, data);
        
        // Now try again - a replay attack should be detected
        try {
            verify(createdDoc, wssConfig, data);
            fail("Expected failure on a replay attack");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY); 
        }   
    }
    
    @org.junit.Test
    public void testReplayedUsernameToken() throws Exception {
        WSSecUsernameToken builder = new WSSecUsernameToken();
        builder.setUserInfo("wernerd", "verySecret");
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        RequestData data = new RequestData();
        data.setCallbackHandler(new UsernamePasswordCallbackHandler());
        data.setWssConfig(wssConfig);
        data.setNonceReplayCache(new MemoryReplayCache());
        
        // Successfully verify UsernameToken
        verify(signedDoc, wssConfig, data);
        
        // Now try again - a replay attack should be detected
        try {
            verify(signedDoc, wssConfig, data);
            fail("Expected failure on a replay attack");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY); 
        }   
    }
    
    @org.junit.Test
    public void testEhCacheReplayedUsernameToken() throws Exception {
        WSSecUsernameToken builder = new WSSecUsernameToken();
        builder.setUserInfo("wernerd", "verySecret");
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        RequestData data = new RequestData();
        data.setCallbackHandler(new UsernamePasswordCallbackHandler());
        data.setWssConfig(wssConfig);
        
        // Successfully verify UsernameToken
        verify(signedDoc, wssConfig, data);
        
        // Now try again - a replay attack should be detected
        try {
            verify(signedDoc, wssConfig, data);
            fail("Expected failure on a replay attack");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY); 
        }   
    }
    
    /**
     * Verifies the soap envelope
     * 
     * @param env soap envelope
     * @param wssConfig
     * @throws java.lang.Exception Thrown when there is a problem in verification
     */
    private List<WSSecurityEngineResult> verify(
        Document doc, WSSConfig wssConfig, RequestData data
    ) throws Exception {
        WSSecurityEngine secEngine = new WSSecurityEngine();
        secEngine.setWssConfig(wssConfig);
        Element elem = WSSecurityUtil.getSecurityHeader(doc, null);
        data.setSigVerCrypto(crypto);
        return secEngine.processSecurityHeader(elem, data);
    }
    
    
}
