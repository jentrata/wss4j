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
package org.apache.wss4j.cxfIntegration.test.integration;

import org.apache.hello_world_soap_http.Greeter;
import org.apache.hello_world_soap_http.PingMeFault;
import org.apache.hello_world_soap_http.types.GreetMeResponseType;
import org.apache.hello_world_soap_http.types.GreetMeType;

import javax.annotation.Resource;
import javax.jws.WebParam;
import javax.jws.WebService;
import javax.xml.ws.Holder;
import javax.xml.ws.WebServiceContext;

/**
 * @author $Author: giger $
 * @version $Revision: 1400458 $ $Date: 2012-10-20 16:16:13 +0200 (Sat, 20 Oct 2012) $
 */
@WebService(targetNamespace = "http://apache.org/hello_world_soap_http", serviceName = "SOAPService", endpointInterface = "org.apache.hello_world_soap_http.Greeter")
public class GreeterServiceImpl implements Greeter {

    @Resource
    WebServiceContext context;

    @Override
    public void pingMe() throws PingMeFault {
    }

    @Override
    public String sayHi() {
        return "Hi";
    }

    @Override
    public void greetMeOneWay(@WebParam(name = "requestType", targetNamespace = "http://apache.org/hello_world_soap_http/types") String requestType) {
    }

    @Override
    public GreetMeResponseType greetMe(
            @WebParam(partName = "greetMe", name = "greetMe",
                    targetNamespace = "http://apache.org/hello_world_soap_http/types") GreetMeType greetMe,
            @WebParam(partName = "attachment", mode = WebParam.Mode.INOUT, name = "attachment",
                    targetNamespace = "") Holder<byte[]> attachment) {

        //System.out.println("Server received attachment: " + new String(attachment.value));

        attachment.value = "Response Attachment".getBytes();
        GreetMeResponseType greetMeResponseType = new GreetMeResponseType();
        greetMeResponseType.setResponseType(greetMe.getRequestType());
        return greetMeResponseType;
    }
}
