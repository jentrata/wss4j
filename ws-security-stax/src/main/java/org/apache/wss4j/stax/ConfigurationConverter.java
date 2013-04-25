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
package org.apache.wss4j.stax;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.xml.namespace.QName;

import org.apache.wss4j.common.ConfigurationConstants;
import org.apache.wss4j.common.util.StringUtil;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSConstants.UsernameTokenPasswordType;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.xml.security.stax.ext.SecurePart;
import org.apache.xml.security.stax.ext.XMLSecurityConstants.Action;

/**
 * This utility class converts between a Map<String, Object> and a WSSSecurityProperties class
 */
public final class ConfigurationConverter {
    
    private ConfigurationConverter() {
        // complete
    }
    
    public static WSSSecurityProperties convert(Map<String, Object> config) {
        WSSSecurityProperties properties = new WSSSecurityProperties();
        
        if (config == null) {
            return properties;
        }
        
        parseActions(config, properties);
        parseUserProperties(config, properties);
        // parseCallbackCrypto(config, properties);
        parseBooleanProperties(config, properties);
        parseNonBooleanProperties(config, properties);
        
        return properties;
    }
    
    private static void parseActions(
        Map<String, Object> config, 
        WSSSecurityProperties properties
    ) {
        String action = getString(ConfigurationConstants.ACTION, config);
        
        if (action == null) {
            return;
        }
        
        String single[] = StringUtil.split(action, ' ');
        List<Action> actions = new ArrayList<Action>();
        for (int i = 0; i < single.length; i++) {
            if (single[i].equals(ConfigurationConstants.USERNAME_TOKEN)) {
                actions.add(WSSConstants.USERNAMETOKEN);
            } /* else if (single[i].equals(ConfigurationConstants.USERNAME_TOKEN_NO_PASSWORD)) {
                actions.add(WSConstants.UT_NOPASSWORD);
            } */else if (single[i].equals(ConfigurationConstants.SIGNATURE)) {
                actions.add(WSSConstants.SIGNATURE);
            } else if (single[i].equals(ConfigurationConstants.ENCRYPT)) {
                actions.add(WSSConstants.ENCRYPT);
            } else if (single[i].equals(ConfigurationConstants.SAML_TOKEN_UNSIGNED)) {
                actions.add(WSSConstants.SAML_TOKEN_UNSIGNED);
            } else if (single[i].equals(ConfigurationConstants.SAML_TOKEN_SIGNED)) {
                actions.add(WSSConstants.SAML_TOKEN_SIGNED);
            } else if (single[i].equals(ConfigurationConstants.TIMESTAMP)) {
                actions.add(WSSConstants.TIMESTAMP);
            } else if (single[i].equals(ConfigurationConstants.USERNAME_TOKEN_SIGNATURE)) {
                actions.add(WSSConstants.USERNAMETOKEN_SIGNED);
            }
        }
        
        Action[] actionArray = new Action[actions.size()];
        properties.setOutAction(actions.toArray(actionArray));
    }
    
    private static void parseUserProperties(
        Map<String, Object> config, 
        WSSSecurityProperties properties
    ) {
        String user = getString(ConfigurationConstants.USER, config);
        properties.setTokenUser(user);
        
        String actor = getString(ConfigurationConstants.ACTOR, config);
        properties.setActor(actor);
        
        String encUser = getString(ConfigurationConstants.ENCRYPTION_USER, config);
        properties.setEncryptionUser(encUser);
        if (ConfigurationConstants.USE_REQ_SIG_CERT.equals(encUser)) {
            properties.setUseReqSigCertForEncryption(true);
        }
        
        String sigUser = getString(ConfigurationConstants.SIGNATURE_USER, config);
        properties.setSignatureUser(sigUser);
    }
    
    // TODO
    /*
    private static void parseCallbackCrypto(
        Map<String, Object> config, 
        WSSSecurityProperties properties
    ) {
        String sigPropRef = getString(ConfigurationConstants.SIG_PROP_REF_ID, config);
        if (sigPropRef != null) {
            
        }
        
        String sigPropFile = getString(ConfigurationConstants.SIG_PROP_FILE, config);
        if (sigPropFile != null) {
            
        }
    }
    */
    
    private static void parseBooleanProperties(
        Map<String, Object> config, 
        WSSSecurityProperties properties
    ) {
        boolean sigConf = 
            decodeBooleanConfigValue(ConfigurationConstants.ENABLE_SIGNATURE_CONFIRMATION, false, config);
        properties.setEnableSignatureConfirmation(sigConf);
        // TODO verification as well?
        
        boolean bspCompliant = 
            decodeBooleanConfigValue(ConfigurationConstants.IS_BSP_COMPLIANT, true, config);
        properties.setDisableBSPEnforcement(!bspCompliant);
        
        boolean inclPrefixes = 
            decodeBooleanConfigValue(ConfigurationConstants.ADD_INCLUSIVE_PREFIXES, true, config);
        properties.setAddExcC14NInclusivePrefixes(inclPrefixes);
        
        boolean nonce = 
            decodeBooleanConfigValue(ConfigurationConstants.ADD_USERNAMETOKEN_NONCE, false, config);
        properties.setAddUsernameTokenNonce(nonce);
        
        boolean created = 
            decodeBooleanConfigValue(ConfigurationConstants.ADD_USERNAMETOKEN_CREATED, false, config);
        properties.setAddUsernameTokenCreated(created);
        
        boolean customPasswordTypes = 
            decodeBooleanConfigValue(ConfigurationConstants.HANDLE_CUSTOM_PASSWORD_TYPES, false, config);
        properties.setHandleCustomPasswordTypes(customPasswordTypes);
        
        boolean allowNoPassword = 
            decodeBooleanConfigValue(ConfigurationConstants.ALLOW_USERNAMETOKEN_NOPASSWORD, false, config);
        properties.setAllowUsernameTokenNoPassword(allowNoPassword);
        
        boolean enableRevocation = 
            decodeBooleanConfigValue(ConfigurationConstants.ENABLE_REVOCATION, false, config);
        properties.setEnableRevocation(enableRevocation);
        
        boolean singleCert = 
            decodeBooleanConfigValue(ConfigurationConstants.USE_SINGLE_CERTIFICATE, true, config);
        properties.setUseSingleCert(singleCert);
        
        boolean derivedKeyMAC = 
            decodeBooleanConfigValue(ConfigurationConstants.USE_DERIVED_KEY_FOR_MAC, true, config);
        properties.setUseDerivedKeyForMAC(derivedKeyMAC);
        
        boolean timestampStrict = 
            decodeBooleanConfigValue(ConfigurationConstants.TIMESTAMP_STRICT, true, config);
        properties.setStrictTimestampCheck(timestampStrict);
        
        boolean allowRSA15 = 
            decodeBooleanConfigValue(ConfigurationConstants.ALLOW_RSA15_KEY_TRANSPORT_ALGORITHM, false, config);
        properties.setAllowRSA15KeyTransportAlgorithm(allowRSA15);
        
        boolean validateSamlSubjectConf = 
            decodeBooleanConfigValue(ConfigurationConstants.VALIDATE_SAML_SUBJECT_CONFIRMATION, true, config);
        properties.setValidateSamlSubjectConfirmation(validateSamlSubjectConf);
    }
    
    private static void parseNonBooleanProperties(
        Map<String, Object> config, 
        WSSSecurityProperties properties
    ) {
        String pwType = getString(ConfigurationConstants.PASSWORD_TYPE, config);
        if ("PasswordDigest".equals(pwType)) {
            properties.setUsernameTokenPasswordType(UsernameTokenPasswordType.PASSWORD_DIGEST);
        } else if ("PasswordText".equals(pwType)) {
            properties.setUsernameTokenPasswordType(UsernameTokenPasswordType.PASSWORD_TEXT);
        } else if ("PasswordNone".equals(pwType)) {
            properties.setUsernameTokenPasswordType(UsernameTokenPasswordType.PASSWORD_NONE);
        }
        
        String signatureKeyIdentifier = getString(ConfigurationConstants.SIG_KEY_ID, config);
        WSSecurityTokenConstants.KeyIdentifier convSigKeyIdentifier = 
            convertKeyIdentifier(signatureKeyIdentifier);
        if (convSigKeyIdentifier != null) {
            properties.setSignatureKeyIdentifier(convSigKeyIdentifier);
        }
        
        String sigAlgo = getString(ConfigurationConstants.SIG_ALGO, config);
        properties.setSignatureAlgorithm(sigAlgo);
        
        String sigDigestAlgo = getString(ConfigurationConstants.SIG_DIGEST_ALGO, config);
        properties.setSignatureDigestAlgorithm(sigDigestAlgo);
        
        String sigParts = getString(ConfigurationConstants.SIGNATURE_PARTS, config);
        if (sigParts != null) {
            List<SecurePart> parts = new ArrayList<SecurePart>();
            // TODO Soap NS
            splitEncParts(sigParts, parts, "http://schemas.xmlsoap.org/soap/envelope/");
            for (SecurePart part : parts) {
                properties.addSignaturePart(part);
            }
        }
        
        String iterations = getString(ConfigurationConstants.DERIVED_KEY_ITERATIONS, config);
        if (iterations != null) {
            int iIterations = Integer.parseInt(iterations);
            properties.setDerivedKeyIterations(iIterations);
        }
        
        String encKeyIdentifier = getString(ConfigurationConstants.ENC_KEY_ID, config);
        WSSecurityTokenConstants.KeyIdentifier convEncKeyIdentifier = 
            convertKeyIdentifier(encKeyIdentifier);
        if (convEncKeyIdentifier != null) {
            properties.setEncryptionKeyIdentifier(convEncKeyIdentifier);
        }
        
        String encParts = getString(ConfigurationConstants.ENCRYPTION_PARTS, config);
        if (encParts != null) {
            List<SecurePart> parts = new ArrayList<SecurePart>();
            // TODO Soap NS
            splitEncParts(encParts, parts, "http://schemas.xmlsoap.org/soap/envelope/");
            for (SecurePart part : parts) {
                properties.addEncryptionPart(part);
            }
        }
        
        String encSymcAlgo = getString(ConfigurationConstants.ENC_SYM_ALGO, config);
        properties.setEncryptionSymAlgorithm(encSymcAlgo);
        
        String encKeyTransport = getString(ConfigurationConstants.ENC_KEY_TRANSPORT, config);
        properties.setEncryptionKeyTransportAlgorithm(encKeyTransport);
        
        String encDigestAlgo = getString(ConfigurationConstants.ENC_DIGEST_ALGO, config);
        properties.setEncryptionKeyTransportDigestAlgorithm(encDigestAlgo);
        
        String encMGFAlgo = getString(ConfigurationConstants.ENC_MGF_ALGO, config);
        properties.setEncryptionKeyTransportMGFAlgorithm(encMGFAlgo);
        
        // TODO SIG_SUBJECT_CERT_CONSTRAINTS
        
        properties.setUtTTL(decodeTimeToLive(config, false));
        properties.setUtFutureTTL(decodeFutureTimeToLive(config, false));
        properties.setTimestampTTL(decodeTimeToLive(config, true));
        properties.setTimeStampFutureTTL(decodeFutureTimeToLive(config, true));
    }
    
    private static WSSecurityTokenConstants.KeyIdentifier convertKeyIdentifier(String keyIdentifier) {
        if ("IssuerSerial".equals(keyIdentifier)) {
           return WSSecurityTokenConstants.KeyIdentifier_IssuerSerial;
        } else if ("DirectReference".equals(keyIdentifier)) {
            return WSSecurityTokenConstants.KeyIdentifier_SecurityTokenDirectReference;
        } else if ("X509KeyIdentifier".equals(keyIdentifier)) {
            return WSSecurityTokenConstants.KeyIdentifier_X509KeyIdentifier;
        } else if ("Thumbprint".equals(keyIdentifier)) {
            return WSSecurityTokenConstants.KeyIdentifier_ThumbprintIdentifier;
        } else if ("SKIKeyIdentifier".equals(keyIdentifier)) {
            return WSSecurityTokenConstants.KeyIdentifier_SkiKeyIdentifier;
        } else if ("EncryptedKeySHA1".equals(keyIdentifier)) {
            return WSSecurityTokenConstants.KeyIdentifier_EncryptedKeySha1Identifier;
        }
        return null;
    }
        
    private static int decodeTimeToLive(Map<String, Object> config, boolean timestamp) {
        String tag = ConfigurationConstants.TTL_TIMESTAMP;
        if (!timestamp) {
            tag = ConfigurationConstants.TTL_USERNAMETOKEN;
        }
        String ttl = getString(tag, config);
        int defaultTimeToLive = 300;
        if (ttl != null) {
            try {
                int ttlI = Integer.parseInt(ttl);
                if (ttlI < 0) {
                    return defaultTimeToLive;
                }
                return ttlI;
            } catch (NumberFormatException e) {
                return defaultTimeToLive;
            }
        }
        return defaultTimeToLive;
    }
    
    private static int decodeFutureTimeToLive(Map<String, Object> config, boolean timestamp) {
        String tag = ConfigurationConstants.TTL_FUTURE_TIMESTAMP;
        if (!timestamp) {
            tag = ConfigurationConstants.TTL_FUTURE_USERNAMETOKEN;
        }
        String ttl = getString(tag, config);
        int defaultFutureTimeToLive = 60;
        if (ttl != null) {
            try {
                int ttlI = Integer.parseInt(ttl);
                if (ttlI < 0) {
                    return defaultFutureTimeToLive;
                }
                return ttlI;
            } catch (NumberFormatException e) {
                return defaultFutureTimeToLive;
            }
        }
        return defaultFutureTimeToLive;
    }

    private static String getString(String tag, Map<String, Object> config) {
        Object value = config.get(tag);
        if (value instanceof String) {
            return (String)value;
        }
        return null;
    }
    
    private static boolean decodeBooleanConfigValue(
        String tag, boolean defaultToTrue, Map<String, Object> config
    ) {
        String value = getString(tag, config);

        if ("0".equals(value) || "false".equals(value)) {
            return false;
        } 
        if ("1".equals(value) || "true".equals(value)) {
            return true;
        }
        
        return defaultToTrue;
    }
    
    private static void splitEncParts(String tmpS, List<SecurePart> parts, String soapNS) {
        SecurePart encPart = null;
        String[] rawParts = StringUtil.split(tmpS, ';');

        for (int i = 0; i < rawParts.length; i++) {
            String[] partDef = StringUtil.split(rawParts[i], '}');

            if (partDef.length == 1) {
                QName qname = new QName(soapNS, partDef[0].trim());
                encPart = new SecurePart(qname, SecurePart.Modifier.Content);
            } else if (partDef.length == 3) {
                String mode = partDef[0].trim();
                if (mode.length() <= 1) {
                    mode = "Content";
                } else {
                    mode = mode.substring(1);
                }
                String nmSpace = partDef[1].trim();
                if (nmSpace.length() <= 1) {
                    nmSpace = soapNS;
                } else {
                    nmSpace = nmSpace.substring(1);
                    if ("Null".equals(nmSpace)) {
                        nmSpace = null;
                    }
                }
                String element = partDef[2].trim();
                
                QName qname = new QName(nmSpace, element);
                if ("Content".equals(mode)) {
                    encPart = new SecurePart(qname, SecurePart.Modifier.Content);
                } else {
                    encPart = new SecurePart(qname, SecurePart.Modifier.Element);
                }
            }
        
            parts.add(encPart);
        }
    }

}
