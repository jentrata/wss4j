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
package org.swssf.policy.assertionStates;

import org.apache.ws.secpolicy.WSSPolicyException;
import org.apache.ws.secpolicy.model.AbstractSecurityAssertion;
import org.apache.ws.secpolicy.model.AbstractToken;
import org.apache.ws.secpolicy.model.SpnegoContextToken;
import org.swssf.wss.securityEvent.SecurityEvent;
import org.swssf.wss.securityEvent.SpnegoContextTokenSecurityEvent;
import org.swssf.wss.securityEvent.TokenSecurityEvent;

/**
 * WSP1.3, 5.4.5 SpnegoContextToken Assertion
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */

public class SpnegoContextTokenAssertionState extends TokenAssertionState {

    public SpnegoContextTokenAssertionState(AbstractSecurityAssertion assertion, boolean asserted) {
        super(assertion, asserted);
    }

    @Override
    public SecurityEvent.Event[] getSecurityEventType() {
        return new SecurityEvent.Event[]{
                SecurityEvent.Event.SpnegoContextToken
        };
    }

    @Override
    public boolean assertToken(TokenSecurityEvent tokenSecurityEvent, AbstractToken abstractToken) throws WSSPolicyException {
        if (!(tokenSecurityEvent instanceof SpnegoContextTokenSecurityEvent)) {
            throw new WSSPolicyException("Expected a SpnegoContextTokenSecurityEvent but got " + tokenSecurityEvent.getClass().getName());
        }
        setAsserted(true);

        SpnegoContextToken spnegoContextToken = (SpnegoContextToken) abstractToken;
        SpnegoContextTokenSecurityEvent spnegoContextTokenSecurityEvent = (SpnegoContextTokenSecurityEvent) tokenSecurityEvent;
        //todo MustNotSend*
        return isAsserted();
    }
}