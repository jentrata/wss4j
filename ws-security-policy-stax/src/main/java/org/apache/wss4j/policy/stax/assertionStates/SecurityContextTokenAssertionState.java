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
package org.apache.wss4j.policy.stax.assertionStates;

import org.apache.wss4j.policy.WSSPolicyException;
import org.apache.wss4j.policy.model.AbstractSecurityAssertion;
import org.apache.wss4j.policy.model.AbstractToken;
import org.apache.wss4j.policy.model.SecurityContextToken;
import org.apache.xml.security.stax.securityEvent.SecurityEventConstants;
import org.apache.xml.security.stax.securityEvent.TokenSecurityEvent;
import org.apache.wss4j.stax.securityEvent.SecurityContextTokenSecurityEvent;
import org.apache.wss4j.stax.securityEvent.WSSecurityEventConstants;

/**
 * WSP1.3, 5.4.6 SecurityContextToken Assertion
 */

public class SecurityContextTokenAssertionState extends TokenAssertionState {

    public SecurityContextTokenAssertionState(AbstractSecurityAssertion assertion, boolean asserted) {
        super(assertion, asserted);
    }

    @Override
    public SecurityEventConstants.Event[] getSecurityEventType() {
        return new SecurityEventConstants.Event[]{
                WSSecurityEventConstants.SecurityContextToken
        };
    }

    @Override
    public boolean assertToken(TokenSecurityEvent tokenSecurityEvent, AbstractToken abstractToken) throws WSSPolicyException {
        if (!(tokenSecurityEvent instanceof SecurityContextTokenSecurityEvent)) {
            throw new WSSPolicyException("Expected a SecurityContextTokenSecurityEvent but got " + tokenSecurityEvent.getClass().getName());
        }
        SecurityContextTokenSecurityEvent securityContextTokenSecurityEvent = (SecurityContextTokenSecurityEvent) tokenSecurityEvent;
        SecurityContextToken securityContextToken = (SecurityContextToken) abstractToken;

        if (securityContextToken.getIssuerName() != null && !securityContextToken.getIssuerName().equals(securityContextTokenSecurityEvent.getIssuerName())) {
            setErrorMessage("IssuerName in Policy (" + securityContextToken.getIssuerName() + ") didn't match with the one in the SecurityContextToken (" + securityContextTokenSecurityEvent.getIssuerName() + ")");
            return false;
        }
        if (securityContextToken.isRequireExternalUriReference() && !securityContextTokenSecurityEvent.isExternalUriRef()) {
            setErrorMessage("Policy enforces externalUriRef but we didn't got one");
            return false;
        }
        //todo sp:SC13SecurityContextToken:
        //always return true to prevent false alarm in case additional tokens with the same usage
        //appears in the message but do not fulfill the policy and are also not needed to fulfil the policy.
        return true;
    }
}
