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

package org.apache.wss4j.dom.handler;

import org.apache.wss4j.common.ConfigurationConstants;
import org.apache.wss4j.dom.WSConstants;

import java.util.HashMap;
import java.util.Map;

/**
 * This class defines the names, actions, and other string for the deployment
 * data of the WS handler.
 */
public final class WSHandlerConstants {
    
    //
    // Action configuration tags
    //
    
    private WSHandlerConstants() {
        // Complete
    }
    
    /**
     * The action parameter. The handlers use the value of this parameter to determine how
     * to process the SOAP Envelope. It is a blank separated list of actions to perform.
     * <p/>
     * The application may set this parameter using the following method:
     * <pre>
     * call.setProperty(WSHandlerConstants.ACTION, WSHandlerConstants.USERNAME_TOKEN);
     * </pre>
     */
    public static final String ACTION = ConfigurationConstants.ACTION;

    /**
     * Perform no action.
     */
    public static final String NO_SECURITY = "NoSecurity";

    /**
     * Perform a UsernameToken action.
     */
    public static final String USERNAME_TOKEN = ConfigurationConstants.USERNAME_TOKEN;
    
    /**
     * Perform a UsernameTokenSignature action.
     */
    public static final String USERNAME_TOKEN_SIGNATURE = 
        ConfigurationConstants.USERNAME_TOKEN_SIGNATURE;
    
    /**
     * Perform a UsernameToken action with no password.
     */
    public static final String USERNAME_TOKEN_NO_PASSWORD = 
        ConfigurationConstants.USERNAME_TOKEN_NO_PASSWORD;

    /**
     * Perform an unsigned SAML Token action.
     */
    public static final String SAML_TOKEN_UNSIGNED = ConfigurationConstants.SAML_TOKEN_UNSIGNED;
    
    /**
     * Perform a signed SAML Token action.
     */
    public static final String SAML_TOKEN_SIGNED = ConfigurationConstants.SAML_TOKEN_SIGNED;

    /**
     * Perform a Signature action. The signature specific parameters define how
     * to sign, which keys to use, and so on.
     */
    public static final String SIGNATURE = ConfigurationConstants.SIGNATURE;

    /**
     * Perform an Encryption action. The encryption specific parameters define how 
     * to encrypt, which keys to use, and so on.
     */
    public static final String ENCRYPT = ConfigurationConstants.ENCRYPT;

    /**
     * Add a timestamp to the security header.
     */
    public static final String TIMESTAMP = ConfigurationConstants.TIMESTAMP;
    
    //
    // User properties
    //

    /**
     * The actor or role name of the <code>wsse:Security</code> header. If this parameter 
     * is omitted, the actor name is not set.
     * <p/>
     * The value of the actor or role has to match the receiver's setting
     * or may contain standard values.
     * <p/>
     * The application may set this parameter using the following method:
     * <pre>
     * call.setProperty(WSHandlerConstants.ACTOR, "ActorName");
     * </pre>
     */
    public static final String ACTOR = ConfigurationConstants.ACTOR;

    /**
     * The user's name. It is used differently by each of the WS-Security functions.
     * <ul>
     * <li>The <i>UsernameToken</i> function sets this name in the
     * <code>UsernameToken</code>.
     * </li>
     * <li>The <i>Signing</i> function uses this name as the alias name
     * in the keystore to get user's certificate and private key to
     * perform signing if {@link #SIGNATURE_USER} is not used.
     * </li>
     * <li>The <i>encryption</i>
     * functions uses this parameter as fallback if {@link #ENCRYPTION_USER}
     * is not used.
     * </li>
     * </ul>
     */
    public static final String USER = ConfigurationConstants.USER;
    
    /**
     * The user's name for encryption. The encryption functions use the public key of 
     * this user's certificate to encrypt the generated symmetric key.
     * <p/>
     * If this parameter is not set, then the encryption
     * function falls back to the {@link #USER} parameter to get the
     * certificate.
     * <p/>
     * If <b>only</b> encryption of the SOAP body data is requested,
     * it is recommended to use this parameter to define the username.
     * <p/>
     * The application may set this parameter using the following method:
     * <pre>
     * call.setProperty(WSHandlerConstants.ENCRYPTION_USER, "encryptionUser");
     * </pre>
     */
    public static final String ENCRYPTION_USER = ConfigurationConstants.ENCRYPTION_USER;
    
    /**
     * The user's name for signature. This name is used as the alias name in the keystore 
     * to get user's certificate and private key to perform signing.
     * <p/>
     * If this parameter is not set, then the signature
     * function falls back to the {@link #USER} parameter.
     * <p/>
     * The application may set this parameter using the following method:
     * <pre>
     * call.setProperty(WSHandlerConstants.SIGNATURE_USER, "signatureUser");
     * </pre>
     */
    public static final String SIGNATURE_USER = ConfigurationConstants.SIGNATURE_USER;

    /**
     * Specifying this name as {@link #ENCRYPTION_USER}
     * triggers a special action to get the public key to use for encryption.
     * <p/>
     * The handler uses the public key of the sender's certificate. Using this
     * way to define an encryption key simplifies certificate management to
     * a large extend.
     */
    public static final String USE_REQ_SIG_CERT = ConfigurationConstants.USE_REQ_SIG_CERT;

    
    //
    // Callback class and property file properties
    //

    /**
     * This tag refers to the CallbackHandler implementation class used to obtain passwords. 
     * The value of this tag must be the class name of a 
     * {@link javax.security.auth.callback.CallbackHandler} instance.
     * </p>
     * The callback function
     * {@link javax.security.auth.callback.CallbackHandler#handle(
     * javax.security.auth.callback.Callback[])} gets an array of 
     * {@link org.apache.wss4j.common.ext.WSPasswordCallback} objects. Only the first entry of the
     * array is used. This object contains the username/keyname as identifier. The callback
     * handler must set the password or key associated with this identifier before it returns.
     * <p/>
     * The application may set this parameter using the following method:
     * <pre>
     * call.setProperty(WSHandlerConstants.PW_CALLBACK_CLASS, "PWCallbackClass");
     * </pre>
     */
    public static final String PW_CALLBACK_CLASS = ConfigurationConstants.PW_CALLBACK_CLASS;
    
    /**
     * This tag refers to the CallbackHandler implementation object used to obtain
     * passwords. The value of this tag must be a
     * {@link javax.security.auth.callback.CallbackHandler} instance.
     * </p>
     * Refer to {@link #PW_CALLBACK_CLASS} for further information about password callback 
     * handling.
     */
    public static final String PW_CALLBACK_REF = ConfigurationConstants.PW_CALLBACK_REF;
    
    /**
     * This tag refers to the SAML CallbackHandler implementation class used to construct
     * SAML Assertions. The value of this tag must be the class name of a 
     * {@link javax.security.auth.callback.CallbackHandler} instance.
     */
    public static final String SAML_CALLBACK_CLASS = ConfigurationConstants.SAML_CALLBACK_CLASS;
    
    /**
     * This tag refers to the SAML CallbackHandler implementation object used to construct
     * SAML Assertions. The value of this tag must be a
     * {@link javax.security.auth.callback.CallbackHandler} instance.
     */
    public static final String SAML_CALLBACK_REF = ConfigurationConstants.SAML_CALLBACK_REF;

    /**
     * This tag refers to the CallbackHandler implementation class used to get the key
     * associated with a key name. The value of this tag must be the class name of a 
     * {@link javax.security.auth.callback.CallbackHandler} instance.
     */
    public static final String ENC_CALLBACK_CLASS = ConfigurationConstants.ENC_CALLBACK_CLASS;

    /**
     * This tag refers to the  CallbackHandler implementation object used to get the key
     * associated with a key name. The value of this tag must be a
     * {@link javax.security.auth.callback.CallbackHandler} instance.
     */
    public static final String ENC_CALLBACK_REF = ConfigurationConstants.ENC_CALLBACK_REF;
    
    /**
     * The path of the crypto property file to use for Signature creation. The classloader 
     * loads this file. Therefore it must be accessible via the classpath.
     * <p/>
     * To locate the implementation of the
     * {@link org.apache.wss4j.common.crypto.Crypto Crypto}
     * interface implementation the property file must contain the property
     * <code>org.apache.wss4j.crypto.provider</code>. The value of
     * this property is the classname of the implementation class.
     * <p/>
     * The following line defines the standard implementation:
     * <pre>
     * org.apache.wss4j.crypto.provider=org.apache.wss4j.common.crypto.Merlin
     * </pre>
     * The other contents of the property file depend on the implementation
     * of the {@link org.apache.wss4j.common.crypto.Crypto Crypto}
     * interface. Please see the WSS4J website for more information on the Merlin property 
     * tags and values.
     * </p>
     * The application may set this parameter using the following method:
     * <pre>
     * call.setProperty(WSHandlerConstants.SIG_PROP_FILE, "myCrypto.properties");
     * </pre>
     */
    public static final String SIG_PROP_FILE = ConfigurationConstants.SIG_PROP_FILE;

    /**
     * The key that holds a reference to the object holding complete information about 
     * the signature Crypto implementation. This object can either be a Crypto instance or a
     * <code>java.util.Properties</code> file, which should contain all information that 
     * would contain in an equivalent properties file which includes the Crypto implementation
     * class name.
     * 
     * Refer to documentation of {@link #SIG_PROP_FILE}.
     */
    public static final String SIG_PROP_REF_ID = ConfigurationConstants.SIG_PROP_REF_ID;
    
    /**
     * The path of the crypto property file to use for Signature verification. The 
     * classloader loads this file. Therefore it must be accessible via the classpath.
     * <p/>
     * Refer to documentation of {@link #SIG_PROP_FILE}.
     */
    public static final String SIG_VER_PROP_FILE = ConfigurationConstants.SIG_VER_PROP_FILE;
    
    /**
     * The key that holds a reference to the object holding complete information about 
     * the signature verification Crypto implementation. This object can either be a Crypto
     * instance or a <code>java.util.Properties</code> file, which should contain all 
     * information that would contain in an equivalent properties file which includes the 
     * Crypto implementation class name.
     * 
     * Refer to documentation of {@link #SIG_VER_PROP_FILE}.
     */
    public static final String SIG_VER_PROP_REF_ID = ConfigurationConstants.SIG_VER_PROP_REF_ID;
    
    /**
     * The path of the crypto property file to use for Decryption. The classloader loads this 
     * file. Therefore it must be accessible via the classpath. Refer to documentation of 
     * {@link #SIG_PROP_FILE} for more information about the contents of the Properties file.
     * <p/>
     * The application may set this parameter using the following method:
     * <pre>
     * call.setProperty(WSHandlerConstants.DEC_PROP_FILE, "myCrypto.properties");
     * </pre>
     */
    public static final String DEC_PROP_FILE = ConfigurationConstants.DEC_PROP_FILE;
    
    /**
     * The key that holds a reference to the object holding complete information about 
     * the decryption Crypto implementation. This object can either be a Crypto instance or a
     * <code>java.util.Properties</code> file, which should contain all information that 
     * would contain in an equivalent properties file which includes the Crypto implementation
     * class name.
     * 
     * Refer to documentation of {@link #DEC_PROP_FILE}.
     */
    public static final String DEC_PROP_REF_ID = ConfigurationConstants.DEC_PROP_REF_ID;
    
    /**
     * The path of the crypto property file to use for Encryption. The classloader loads this 
     * file. Therefore it must be accessible via the classpath. Refer to documentation of 
     * {@link #SIG_PROP_FILE} for more information about the contents of the Properties file.
     * <p/>
     * The application may set this parameter using the following method:
     * <pre>
     * call.setProperty(WSHandlerConstants.ENC_PROP_FILE, "myCrypto.properties");
     * </pre>
     */
    public static final String ENC_PROP_FILE = ConfigurationConstants.ENC_PROP_FILE;
    
    /**
     * The key that holds a reference to the object holding complete information about 
     * the encryption Crypto implementation. This object can either be a Crypto instance or a
     * <code>java.util.Properties</code> file, which should contain all information that 
     * would contain in an equivalent properties file which includes the Crypto implementation
     * class name.
     * 
     * Refer to documentation of {@link #ENC_PROP_FILE}.
     */
    public static final String ENC_PROP_REF_ID = ConfigurationConstants.ENC_PROP_REF_ID;
    
    //
    // Boolean configuration tags, e.g. the value should be "true" or "false".
    //
    
    /**
     * Whether to enable signatureConfirmation or not. The default value is "false".
     */
    public static final String ENABLE_SIGNATURE_CONFIRMATION = 
        ConfigurationConstants.ENABLE_SIGNATURE_CONFIRMATION;
    
    /**
     * Whether to set the mustUnderstand flag on an outbound message or not. The default 
     * setting is "true".
     * <p/>
     * The application may set this parameter using the following method:
     * <pre>
     * call.setProperty(WSHandlerConstants.MUST_UNDERSTAND, "false");
     * </pre>
     */
    public static final String MUST_UNDERSTAND = ConfigurationConstants.MUST_UNDERSTAND;
    
    /**
     * Whether to ensure compliance with the Basic Security Profile (BSP) 1.1 or not. The
     * default value is "true".
     * <p/>
     * The application may set this parameter using the following method:
     * <pre>
     * call.setProperty(WSHandlerConstants.IS_BSP_COMPLIANT, "false");
     * </pre>
     */
    public static final String IS_BSP_COMPLIANT = ConfigurationConstants.IS_BSP_COMPLIANT;
    
    /**
     * Whether to add an InclusiveNamespaces PrefixList as a CanonicalizationMethod
     * child when generating Signatures using WSConstants.C14N_EXCL_OMIT_COMMENTS.
     * The default is true.
     */
    public static final String ADD_INCLUSIVE_PREFIXES = 
        ConfigurationConstants.ADD_INCLUSIVE_PREFIXES;
    
    /**
     * Whether to add a Nonce Element to a UsernameToken. This only applies when the
     * password type is of type "text". A Nonce is automatically added for the "digest"
     * case. The default is false.
     */
    public static final String ADD_USERNAMETOKEN_NONCE = 
        ConfigurationConstants.ADD_USERNAMETOKEN_NONCE;
    
    /**
     * Whether to add a Created Element to a UsernameToken. This only applies when the
     * password type is of type "text". A Created is automatically added for the "digest"
     * case. The default is false.
     */
    public static final String ADD_USERNAMETOKEN_CREATED = 
        ConfigurationConstants.ADD_USERNAMETOKEN_CREATED;
    
    /**
     * This variable controls whether types other than PasswordDigest or PasswordText
     * are allowed when processing UsernameTokens. The default value is "false".
     */
    public static final String HANDLE_CUSTOM_PASSWORD_TYPES = 
        ConfigurationConstants.HANDLE_CUSTOM_PASSWORD_TYPES;
    
    /**
     * This variable controls whether a UsernameToken with no password element is allowed. 
     * The default value is "false". Set it to "true" to allow deriving keys from UsernameTokens 
     * or to support UsernameTokens for purposes other than authentication.
     */
    public static final String ALLOW_USERNAMETOKEN_NOPASSWORD = 
        ConfigurationConstants.ALLOW_USERNAMETOKEN_NOPASSWORD;
    
    /**
     * This variable controls whether (wsse) namespace qualified password types are
     * accepted when processing UsernameTokens. The default value is "false".
     */
    public static final String ALLOW_NAMESPACE_QUALIFIED_PASSWORD_TYPES 
        = ConfigurationConstants.ALLOW_NAMESPACE_QUALIFIED_PASSWORD_TYPES;
    
    /**
     * This variable controls whether to enable Certificate Revocation List (CRL) checking
     * or not when verifying trust in a certificate. The default value is "false".
     */
    public static final String ENABLE_REVOCATION = ConfigurationConstants.ENABLE_REVOCATION;
    
    /**
     * Set the value of this parameter to true to treat passwords as binary values
     * for Username Tokens. The default value is "false".
     * 
     * This is needed to properly handle password equivalence for UsernameToken
     * passwords.  Binary passwords are Base64 encoded so they can be treated as 
     * strings in most places, but when the password digest is calculated or a key
     * is derived from the password, the password will be Base64 decoded before 
     * being used. This is most useful for hashed passwords as password equivalents.
     */
    public static final String USE_ENCODED_PASSWORDS = "useEncodedPasswords";
    
    /**
     * This parameter sets whether to use a single certificate or a whole certificate
     * chain when constructing a BinarySecurityToken used for direct reference in
     * signature. The default is "true", meaning that only a single certificate is used.
     */
    public static final String USE_SINGLE_CERTIFICATE = ConfigurationConstants.USE_SINGLE_CERTIFICATE;
    
    /**
     * This parameter sets whether to use the Username Token derived key for a MAC
     * or not. The default is "true".
     */
    public static final String USE_DERIVED_KEY_FOR_MAC = ConfigurationConstants.USE_DERIVED_KEY_FOR_MAC;
    
    /**
     * Set whether Timestamps have precision in milliseconds. This applies to the
     * creation of Timestamps only. The default value is "true".
     */
    public static final String TIMESTAMP_PRECISION = ConfigurationConstants.TIMESTAMP_PRECISION;
    
    /**
     * Set the value of this parameter to true to enable strict timestamp
     * handling. The default value is "true".
     * 
     * Strict Timestamp handling: throw an exception if a Timestamp contains
     * an <code>Expires</code> element and the semantics of the request are
     * expired, i.e. the current time at the receiver is past the expires time.
     */
    public static final String TIMESTAMP_STRICT = ConfigurationConstants.TIMESTAMP_STRICT;
    
    /**
     * Defines whether to encrypt the symmetric encryption key or not. If true
     * (the default), the symmetric key used for encryption is encrypted in turn,
     * and inserted into the security header in an "EncryptedKey" structure. If
     * set to false, no EncryptedKey structure is constructed.
     * <p/>
     * The application may set this parameter using the following method:
     * <pre>
     * call.setProperty(WSHandlerConstants.ENC_SYM_ENC_KEY, "false");
     * </pre>
     */
    public static final String ENC_SYM_ENC_KEY = ConfigurationConstants.ENC_SYM_ENC_KEY;
    
    /**
     * Whether the engine needs to enforce EncryptedData elements are
     * in a signed subtree of the document. This can be used to prevent
     * some wrapping based attacks when encrypt-before-sign token
     * protection is selected.
     */
    public static final String REQUIRE_SIGNED_ENCRYPTED_DATA_ELEMENTS = 
        ConfigurationConstants.REQUIRE_SIGNED_ENCRYPTED_DATA_ELEMENTS;
    
    /**
     * Whether to allow the RSA v1.5 Key Transport Algorithm or not. Use of this algorithm
     * is discouraged, and so the default is "false".
     */
    public static final String ALLOW_RSA15_KEY_TRANSPORT_ALGORITHM = 
        ConfigurationConstants.ALLOW_RSA15_KEY_TRANSPORT_ALGORITHM;

    /**
     * Whether to validate the SubjectConfirmation requirements of a received SAML Token
     * (sender-vouches or holder-of-key). The default is true.
     */
    public static final String VALIDATE_SAML_SUBJECT_CONFIRMATION = 
        ConfigurationConstants.VALIDATE_SAML_SUBJECT_CONFIRMATION;
    
    //
    // (Non-boolean) Configuration parameters for the actions/processors
    //
    
    /**
     * Text of the embedded key name to be sent in the KeyInfo for encryption.
     */
    public static final String ENC_KEY_NAME = "embeddedKeyName";

    /**
     * Specific parameter for UsernameTokens to define the encoding of the password. It can
     * be used on either the outbound or inbound side. The valid values are:
     * 
     * - {@link WSConstants#PW_DIGEST}
     * - {@link WSConstants#PW_TEXT}
     * - {@link WSConstants#PW_NONE}
     * 
     * On the Outbound side, the default value is PW_DIGEST. There is no default value on
     * the inbound side. If a value is specified on the inbound side, the password type of
     * the received UsernameToken must match the specified type, or an exception will be
     * thrown.
     */
    public static final String PASSWORD_TYPE = ConfigurationConstants.PASSWORD_TYPE;
    
    /**
     * Defines which key identifier type to use for signature. The WS-Security specifications
     * recommends to use the identifier type <code>IssuerSerial</code>. For possible signature 
     * key identifier types refer to {@link #getKeyIdentifier(String)}. 
     * For signature <code>IssuerSerial</code>, <code>DirectReference</code>,
     * <code>X509KeyIdentifier</code>, <code>Thumbprint</code>, <code>SKIKeyIdentifier</code>
     * and <code>KeyValue</code> are valid only. 
     * <p/>
     * The default is <code>IssuerSerial</code>.
     * <p/>
     * The application may set this parameter using the following method:
     * <pre>
     * call.setProperty(WSHandlerConstants.SIG_KEY_ID, "DirectReference");
     * </pre>
     */
    public static final String SIG_KEY_ID = ConfigurationConstants.SIG_KEY_ID;

    /**
     * Defines which signature algorithm to use. The default is set by the data in the 
     * certificate, i.e. one of the following:
     * 
     * "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
     * "http://www.w3.org/2000/09/xmldsig#dsa-sha1"
     * 
     * <p/>
     * The application may set this parameter using the following method:
     * <pre>
     * call.setProperty(
     *     WSHandlerConstants.SIG_ALGO, 
     *     "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
     * );
     * </pre>
     */
    public static final String SIG_ALGO = ConfigurationConstants.SIG_ALGO;
    
    /**
     * Defines which signature digest algorithm to use. The default is:
     * 
     * "http://www.w3.org/2000/09/xmldsig#sha1"
     * 
     * <p/>
     * The application may set this parameter using the following method:
     * <pre>
     * call.setProperty(
     *    WSHandlerConstants.SIG_DIGEST_ALGO, "http://www.w3.org/2001/04/xmlenc#sha256"
     * );
     * </pre>
     */
    public static final String SIG_DIGEST_ALGO = ConfigurationConstants.SIG_DIGEST_ALGO;

    /**
     * Parameter to define which parts of the request shall be signed.
     * <p/>
     * Refer to {@link #ENCRYPTION_PARTS} for a detailed description of
     * the format of the value string.
     * <p/>
     * If this parameter is not specified the handler signs the SOAP Body
     * by default, i.e.:
     * <pre>
     * &lt;parameter name="signatureParts"
     *   value="{}{http://schemas.xmlsoap.org/soap/envelope/}Body;" />
     * </pre>
     * To specify an element without a namespace use the string
     * <code>Null</code> as the namespace name (this is a case sensitive
     * string)
     * <p/>
     * If there is no other element in the request with a local name of
     * <code>Body</code> then the SOAP namespace identifier can be empty
     * (<code>{}</code>).
     */
    public static final String SIGNATURE_PARTS = ConfigurationConstants.SIGNATURE_PARTS;
    
    /**
     * This parameter sets the number of iterations to use when deriving a key
     * from a Username Token. The default is 1000. 
     */
    public static final String DERIVED_KEY_ITERATIONS = ConfigurationConstants.DERIVED_KEY_ITERATIONS;

    /**
     * Defines which key identifier type to use for encryption. The WS-Security specifications
     * recommends to use the identifier type <code>IssuerSerial</code>. For
     * possible encryption key identifier types refer to
     * {@link #getKeyIdentifier(String)}. For encryption <code>IssuerSerial</code>,
     * <code>DirectReference</code>, <code>X509KeyIdentifier</code>, 
     * <code>Thumbprint</code>, <code>SKIKeyIdentifier</code>, <code>EncryptedKeySHA1</code>
     * and <code>EmbeddedKeyName</code> are valid only.
     * <p/>
     * The default is <code>IssuerSerial</code>.
     * <p/>
     * The application may set this parameter using the following method:
     * <pre>
     * call.setProperty(WSHandlerConstants.ENC_KEY_ID, "X509KeyIdentifier");
     * </pre>
     */
    public static final String ENC_KEY_ID = ConfigurationConstants.ENC_KEY_ID;

    /**
     * Defines which symmetric encryption algorithm to use. WSS4J supports the
     * following algorithms: {@link WSConstants#TRIPLE_DES},
     * {@link WSConstants#AES_128}, {@link WSConstants#AES_256},
     * and {@link WSConstants#AES_192}. Except for AES 192 all of these
     * algorithms are required by the XML Encryption specification.
     * The default algorithm is:
     * 
     * "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
     * 
     * <p/>
     * The application may set this parameter using the following method:
     * <pre>
     * call.setProperty(WSHandlerConstants.ENC_SYM_ALGO, WSConstants.AES_256);
     * </pre>
     */
    public static final String ENC_SYM_ALGO = ConfigurationConstants.ENC_SYM_ALGO;

    /**
     * Defines which algorithm to use to encrypt the generated symmetric key.
     * The default algorithm is:
     * 
     * "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
     * 
     * <p/>
     * The application may set this parameter using the following method:
     * <pre>
     * call.setProperty(WSHandlerConstants.ENC_KEY_TRANSPORT, WSConstants.KEYTRANSPORT_RSA15);
     * </pre>
     */
    public static final String ENC_KEY_TRANSPORT = ConfigurationConstants.ENC_KEY_TRANSPORT;
    
    /**
     * Parameter to define which parts of the request shall be encrypted.
     * <p/>
     * The value of this parameter is a list of semi-colon separated
     * element names that identify the elements to encrypt. An encryption mode
     * specifier and a namespace identification, each inside a pair of curly
     * brackets, may preceed each element name.
     * <p/>
     * The encryption mode specifier is either <code>{Content}</code> or
     * <code>{Element}</code>. Please refer to the W3C XML Encryption
     * specification about the differences between Element and Content
     * encryption. The encryption mode defaults to <code>Content</code>
     * if it is omitted. Example of a list:
     * <pre>
     * &lt;parameter name="encryptionParts"
     *   value="{Content}{http://example.org/paymentv2}CreditCard;
     *             {Element}{}UserName" />
     * </pre>
     * The the first entry of the list identifies the element
     * <code>CreditCard</code> in the namespace
     * <code>http://example.org/paymentv2</code>, and will encrypt its content.
     * Be aware that the element name, the namespace identifier, and the
     * encryption modifier are case sensitive.
     * <p/>
     * The encryption modifier and the namespace identifier can be ommited.
     * In this case the encryption mode defaults to <code>Content</code> and
     * the namespace is set to the SOAP namespace.
     * <p/>
     * An empty encryption mode defaults to <code>Content</code>, an empty
     * namespace identifier defaults to the SOAP namespace.
     * The second line of the example defines <code>Element</code> as
     * encryption mode for an <code>UserName</code> element in the SOAP
     * namespace.
     * <p/>
     * To specify an element without a namespace use the string
     * <code>Null</code> as the namespace name (this is a case sensitive
     * string)
     * <p/>
     * If no list is specified, the handler encrypts the SOAP Body in
     * <code>Content</code> mode by default.
     */
    public static final String ENCRYPTION_PARTS = ConfigurationConstants.ENCRYPTION_PARTS;
    
    /**
     * Defines which encryption digest algorithm to use with the RSA OAEP Key Transport 
     * algorithm for encryption. The default is SHA-1.
     * <p/>
     * The application may set this parameter using the following method:
     * <pre>
     * call.setProperty(
     *    WSHandlerConstants.ENC_DIGEST_ALGO, "http://www.w3.org/2001/04/xmlenc#sha256"
     * );
     * </pre>
     */
    public static final String ENC_DIGEST_ALGO = ConfigurationConstants.ENC_DIGEST_ALGO;

    /**
     * Defines which encryption mgf algorithm to use with the RSA OAEP Key Transport
     * algorithm for encryption. The default is mgfsha1.
     * <p/>
     * The application may set this parameter using the following method:
     * <pre>
     * call.setProperty(
     *    WSHandlerConstants.ENC_MGF_ALGO, "http://www.w3.org/2009/xmlenc11#mgf1sha256"
     * );
     * </pre>
     */
    public static final String ENC_MGF_ALGO = ConfigurationConstants.ENC_MGF_ALGO;

    /**
     * Time-To-Live is the time difference between creation and expiry time in
     * seconds of the UsernameToken Created value. After this time the SOAP request 
     * is invalid (at least the security data shall be treated this way).
     * <p/>
     * If this parameter is not defined, contains a value less or equal
     * zero, or an illegal format the handlers use a default TTL of
     * 300 seconds (5 minutes).
     */
    public static final String TTL_USERNAMETOKEN = ConfigurationConstants.TTL_USERNAMETOKEN;
    
    /**
     * This configuration tag specifies the time in seconds in the future within which
     * the Created time of an incoming UsernameToken is valid. The default value is "60",
     * to avoid problems where clocks are slightly askew. To reject all future-created
     * UsernameTokens, set this value to "0". 
     */
    public static final String TTL_FUTURE_USERNAMETOKEN = ConfigurationConstants.TTL_FUTURE_USERNAMETOKEN;
    
    /**
     * This configuration tag is a comma separated String of regular expressions which
     * will be applied to the subject DN of the certificate used for signature
     * validation, after trust verification of the certificate chain associated with the 
     * certificate. These constraints are not used when the certificate is contained in
     * the keystore (direct trust).
     */
    public static final String SIG_SUBJECT_CERT_CONSTRAINTS = ConfigurationConstants.SIG_SUBJECT_CERT_CONSTRAINTS;
    
    /**
     * Time-To-Live is the time difference between creation and expiry time in
     * seconds in the WSS Timestamp. After this time the SOAP request is
     * invalid (at least the security data shall be treated this way).
     * <p/>
     * If this parameter is not defined, contains a value less or equal
     * zero, or an illegal format the handlers use a default TTL of
     * 300 seconds (5 minutes).
     */
    public static final String TTL_TIMESTAMP = ConfigurationConstants.TTL_TIMESTAMP;
    
    /**
     * This configuration tag specifies the time in seconds in the future within which
     * the Created time of an incoming Timestamp is valid. The default value is "60",
     * to avoid problems where clocks are slightly askew. To reject all future-created
     * Timestamps, set this value to "0". 
     */
    public static final String TTL_FUTURE_TIMESTAMP = ConfigurationConstants.TTL_FUTURE_TIMESTAMP;
    
    
    //
    // Internal storage constants
    //
    
    /**
     * The WSHandler stores a result <code>List</code> in this property.
     */
    public static final String RECV_RESULTS = "RECV_RESULTS";
    
    /**
     * internally used property names to store values inside the message context
     * that must have the same lifetime as a message (request/response model).
     */
    public static final String SEND_SIGV = "_sendSignatureValues_";
    
    /**
     * 
     */
    public static final String SIG_CONF_DONE = "_sigConfDone_";


    /**
     * Define the parameter values to set the key identifier types. These are:
     * <ul>
     * <li><code>DirectReference</code> for {@link WSConstants#BST_DIRECT_REFERENCE}
     * </li>
     * <li><code>IssuerSerial</code> for {@link WSConstants#ISSUER_SERIAL}
     * </li>
     * <li><code>X509KeyIdentifier</code> for {@link WSConstants#X509_KEY_IDENTIFIER}
     * </li>
     * <li><code>SKIKeyIdentifier</code> for {@link WSConstants#SKI_KEY_IDENTIFIER}
     * </li>
     * <li><code>EmbeddedKeyName</code> for {@link WSConstants#EMBEDDED_KEYNAME}
     * </li>
     * <li><code>Thumbprint</code> for {@link WSConstants#THUMBPRINT}
     * </li>
     * <li><code>EncryptedKeySHA1</code> for {@link WSConstants#ENCRYPTED_KEY_SHA1_IDENTIFIER}
     * </li>
     * </ul>
     * See {@link #SIG_KEY_ID} {@link #ENC_KEY_ID}.
     */
    private static Map<String, Integer> keyIdentifier = new HashMap<String, Integer>();

    static {
        keyIdentifier.put("DirectReference", WSConstants.BST_DIRECT_REFERENCE);
        keyIdentifier.put("IssuerSerial", WSConstants.ISSUER_SERIAL);
        keyIdentifier.put("X509KeyIdentifier", WSConstants.X509_KEY_IDENTIFIER);
        keyIdentifier.put("SKIKeyIdentifier", WSConstants.SKI_KEY_IDENTIFIER);
        keyIdentifier.put("EmbeddedKeyName", WSConstants.EMBEDDED_KEYNAME);
        keyIdentifier.put("Thumbprint", WSConstants.THUMBPRINT_IDENTIFIER);
        keyIdentifier.put("EncryptedKeySHA1", WSConstants.ENCRYPTED_KEY_SHA1_IDENTIFIER);
        keyIdentifier.put("KeyValue", WSConstants.KEY_VALUE);
    }
    
    /**
     * Get the key identifier type corresponding to the parameter. This is intended for internal
     * use only. Valid values for "parameter" are:
     *  - "IssuerSerial"
     *  - "DirectReference"
     *  - "X509KeyIdentifier"
     *  - "Thumbprint"
     *  - "SKIKeyIdentifier"
     *  - "KeyValue"
     *  - "EmbeddedKeyName"
     *  - "EncryptedKeySHA1"
     * 
     * @param parameter
     * @return the key identifier type corresponding to the parameter
     */
    public static Integer getKeyIdentifier(String parameter) {
        return keyIdentifier.get(parameter);
    }
}

