/*
 *  Copyright (c) 2021 - 2022 Daimler TSS GmbH
 *
 *  This program and the accompanying materials are made available under the
 *  terms of the Apache License, Version 2.0 which is available at
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Contributors:
 *       Daimler TSS GmbH - Initial API and Implementation
 *       Fraunhofer Institute for Software and Systems Engineering - Improvements, refactoring
 *       Microsoft Corporation - Use IDS Webhook address for JWT audience claim
 *
 */

package org.eclipse.edc.protocol.ids.api.multipart.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.fraunhofer.iais.eis.DynamicAttributeToken;
import de.fraunhofer.iais.eis.DynamicAttributeTokenBuilder;
import de.fraunhofer.iais.eis.Message;
import de.fraunhofer.iais.eis.TokenFormat;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import org.eclipse.edc.protocol.ids.api.multipart.handler.Handler;
import org.eclipse.edc.protocol.ids.spi.service.DynamicAttributeTokenService;
import org.eclipse.edc.protocol.ids.spi.types.IdsId;
import org.eclipse.edc.spi.EdcException;
import org.eclipse.edc.spi.monitor.Monitor;
import org.glassfish.jersey.media.multipart.FormDataBodyPart;
import org.glassfish.jersey.media.multipart.FormDataMultiPart;
import org.jetbrains.annotations.NotNull;

import java.util.List;

@Consumes({MediaType.MULTIPART_FORM_DATA})
@Produces({MediaType.MULTIPART_FORM_DATA})
public abstract class AbstractMultipartController {

    protected static final String HEADER = "header";
    protected static final String PAYLOAD = "payload";

    protected final Monitor monitor;
    protected final IdsId connectorId;
    protected final List<Handler> multipartHandlers;
    protected final ObjectMapper objectMapper;
    protected final DynamicAttributeTokenService tokenService;
    protected final String idsWebhookAddress;

    protected AbstractMultipartController(@NotNull Monitor monitor,
                                          @NotNull IdsId connectorId,
                                          @NotNull ObjectMapper objectMapper,
                                          @NotNull DynamicAttributeTokenService tokenService,
                                          @NotNull List<Handler> multipartHandlers,
                                          @NotNull String idsWebhookAddress) {
        this.monitor = monitor;
        this.connectorId = connectorId;
        this.objectMapper = objectMapper;
        this.multipartHandlers = multipartHandlers;
        this.tokenService = tokenService;
        this.idsWebhookAddress = idsWebhookAddress;
    }

    /**
     * Builds a form-data multipart body with the given header and payload.
     *
     * @param header the header.
     * @param payload the payload.
     * @return a multipart body.
     */
    protected FormDataMultiPart createFormDataMultiPart(Message header, Object payload) {
        var multiPart = createFormDataMultiPart(header);

        if (payload != null) {
            multiPart.bodyPart(new FormDataBodyPart(PAYLOAD, toJson(payload), MediaType.APPLICATION_JSON_TYPE));
        }

        return multiPart;
    }

    /**
     * Builds a form-data multipart body with the given header.
     *
     * @param header the header.
     * @return a multipart body.
     */
    protected FormDataMultiPart createFormDataMultiPart(Message header) {
        var multiPart = new FormDataMultiPart();
        if (header != null) {
            multiPart.bodyPart(new FormDataBodyPart(HEADER, toJson(header), MediaType.APPLICATION_JSON_TYPE));
        }
        return multiPart;
    }

    /**
     * Retrieves an identity token for the given message. Returns a token with value "invalid" if
     * obtaining an identity token fails.
     *
     * @param header the message.
     * @return the token.
     */
    protected DynamicAttributeToken getToken(Message header) {
        if (header.getRecipientConnector() != null && !header.getRecipientConnector().isEmpty()) {
            var recipient = header.getRecipientConnector().get(0);
            var tokenResult = tokenService.obtainDynamicAttributeToken(recipient.toString());
            if (tokenResult.succeeded()) {
                return tokenResult.getContent();
            }
        }

        return new DynamicAttributeTokenBuilder()
                ._tokenFormat_(TokenFormat.JWT)
                ._tokenValue_("invalid")
                .build();
    }

    protected String toJson(Object object) {
        try {
            return objectMapper.writeValueAsString(object);
        } catch (JsonProcessingException e) {
            throw new EdcException(e);
        }
    }
}
