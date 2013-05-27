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
package org.apache.wss4j.stax.impl.transformer;

import org.apache.wss4j.common.util.AttachmentUtils;
import org.apache.xml.security.utils.MultiInputStream;

import javax.xml.stream.XMLStreamException;
import java.io.*;

public class AttachmentCompleteSignatureTransform extends AttachmentContentSignatureTransform {

    @Override
    public void transform(InputStream inputStream) throws XMLStreamException {
        InputStream is = inputStream;
        try {
            OutputStream outputStream = getOutputStream();
            if (outputStream == null) {
                outputStream = new ByteArrayOutputStream();
                is = new MultiInputStream(
                        new ByteArrayInputStream(
                                ((ByteArrayOutputStream) outputStream).toByteArray()),
                        inputStream
                );
            }
            AttachmentUtils.canonizeMimeHeaders(outputStream, getAttachment().getHeaders());
        } catch (IOException e) {
            throw new XMLStreamException(e);
        }
        super.transform(is);
    }
}
