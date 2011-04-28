/*
 * Copyright 2001-2004 The Apache Software Foundation.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.swssf.policy.secpolicybuilder;

import org.apache.axiom.om.OMAttribute;
import org.apache.axiom.om.OMElement;
import org.apache.neethi.Assertion;
import org.apache.neethi.AssertionBuilderFactory;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyEngine;
import org.apache.neethi.builders.AssertionBuilder;
import org.swssf.policy.secpolicy.*;
import org.swssf.policy.secpolicy.model.SecureConversationToken;

import javax.xml.namespace.QName;

/**
 * class lent from apache rampart
 */
public class SecureConversationTokenBuilder implements AssertionBuilder {

    private static final QName[] KNOWN_ELEMENTS = new QName[]{
            SP11Constants.SECURE_CONVERSATION_TOKEN,
            SP12Constants.SECURE_CONVERSATION_TOKEN,
            SP13Constants.SECURE_CONVERSATION_TOKEN
    };

    public Assertion build(OMElement element, AssertionBuilderFactory factory)
            throws IllegalArgumentException {

        SPConstants spConstants = PolicyUtil.getSPVersion(element.getQName().getNamespaceURI());

        SecureConversationToken conversationToken = new SecureConversationToken(spConstants);

        OMAttribute attribute = element.getAttribute(spConstants.getIncludeToken());
        if (attribute == null) {
            throw new IllegalArgumentException(
                    "SecurityContextToken doesn't contain any sp:IncludeToken attribute");
        }

        String inclusionValue = attribute.getAttributeValue().trim();

        conversationToken.setInclusion(spConstants.getInclusionFromAttributeValue(inclusionValue));

        OMElement issuer = element.getFirstChildWithName(spConstants.getIssuer());
        if (issuer != null) {
            conversationToken.setIssuerEpr(issuer.getFirstElement());
        }

        element = element.getFirstChildWithName(SPConstants.POLICY);
        if (element != null) {
            if (element.getFirstChildWithName(spConstants.getRequiredDerivedKeys()) != null) {
                conversationToken.setDerivedKeys(true);
            } else if (element.getFirstChildWithName(spConstants.getRequireImpliedDerivedKeys()) != null) {
                conversationToken.setImpliedDerivedKeys(true);
            } else if (element.getFirstChildWithName(spConstants.getRequireExplicitDerivedKeys()) != null) {
                conversationToken.setExplicitDerivedKeys(true);
            }

            if (element
                    .getFirstChildWithName(spConstants.getRequireExternalUriRefernce()) != null) {
                conversationToken.setRequireExternalUriRef(true);
            }

            if (element
                    .getFirstChildWithName(spConstants.getSc10SecurityContextToken()) != null) {
                conversationToken.setSc10SecurityContextToken(true);
            }

            OMElement bootstrapPolicyElement = element.getFirstChildWithName(spConstants.getBootstrapPolicy());
            if (bootstrapPolicyElement != null) {
                Policy policy = PolicyEngine.getPolicy(bootstrapPolicyElement.getFirstElement());
                conversationToken.setBootstrapPolicy(policy);
            }
        }

        return conversationToken;
    }

    public QName[] getKnownElements() {
        return KNOWN_ELEMENTS;
    }

}