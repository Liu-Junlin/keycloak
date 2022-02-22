/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cn.tdsj.keycloak.provider.captcha;

import com.google.code.kaptcha.impl.DefaultKaptcha;
import org.jboss.logging.Logger;
import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

import javax.imageio.ImageIO;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.CacheControl;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Map;

/**
 * @author liujunlin
 * @date 2020/02/05
 */
public class CaptchaResourceProvider implements RealmResourceProvider {
    private static final Logger logger = Logger.getLogger(CaptchaResourceProvider.class);

    private static final String CAPTCHA_ATTRIBUTE_KEY = "CAPTCHA_CODE";
    private static final String PICTURE_TYPE = "gif";
    private final DefaultKaptcha defaultKaptcha;
    private final KeycloakSession session;
    private final CacheControl cacheControl;
    private final MediaType mediaType;

    public CaptchaResourceProvider(KeycloakSession session, DefaultKaptcha defaultKaptcha) {
        this.session = session;
        this.defaultKaptcha = defaultKaptcha;
        this.cacheControl = new CacheControl();
        this.cacheControl.setMustRevalidate(true);
        this.cacheControl.setNoCache(true);
        this.cacheControl.setNoStore(true);
        this.cacheControl.setNoTransform(true);
        this.mediaType = new MediaType("image", PICTURE_TYPE);
    }

    @Override
    public Object getResource() {
        return this;
    }

    @GET
    @Path("")
    @NoCache
    public Response getCaptcha() throws IOException {
        String text = this.defaultKaptcha.createText();
        BufferedImage bufferedImage = this.defaultKaptcha.createImage(text);
        createCaptcha(text);
        return Response.ok(imageToBytes(bufferedImage))
                .type(mediaType)
                .cacheControl(cacheControl).build();
    }

    private void createCaptcha(String captchaText) {
        logger.debugf("set captcha code:%s", captchaText);
        RealmModel realmModel = session.getContext().getRealm();
        RootAuthenticationSessionModel rootAuthenticationSessionModel = new AuthenticationSessionManager(session).getCurrentRootAuthenticationSession(realmModel);
        if (rootAuthenticationSessionModel != null) {
            Map<String, AuthenticationSessionModel> authenticationSessions = rootAuthenticationSessionModel.getAuthenticationSessions();
            authenticationSessions.values().forEach(authenticationSessionModel -> authenticationSessionModel.setAuthNote(CAPTCHA_ATTRIBUTE_KEY, captchaText));
            logger.debugf("authenticationSessions size:%d", authenticationSessions.values().size());
        } else {
            logger.warn("rootAuthenticationSessionModel is null");
        }

    }

    @Override
    public void close() {
    }

    private byte[] imageToBytes(BufferedImage bImage) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ImageIO.write(bImage, CaptchaResourceProvider.PICTURE_TYPE, out);

        return out.toByteArray();
    }
}
