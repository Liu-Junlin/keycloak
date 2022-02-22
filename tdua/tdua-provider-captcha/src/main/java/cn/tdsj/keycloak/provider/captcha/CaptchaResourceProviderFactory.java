package cn.tdsj.keycloak.provider.captcha;

import com.google.code.kaptcha.impl.DefaultKaptcha;
import com.google.code.kaptcha.util.Config;
import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

import java.util.Properties;

/**
 * @author liujunlin
 * @date 2020/02/05
 */
public class CaptchaResourceProviderFactory implements RealmResourceProviderFactory {
    public static final String ID = "captcha";

    private DefaultKaptcha defaultKaptcha;

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new CaptchaResourceProvider(session, defaultKaptcha);
    }

    @Override
    public void init(Scope config) {
        this.defaultKaptcha = createDefaultKaptcha();
    }

    private DefaultKaptcha createDefaultKaptcha() {
        DefaultKaptcha defaultKaptcha = new DefaultKaptcha();
        Properties properties = new Properties();
        properties.setProperty("kaptcha.textproducer.char.string", "3456789");
        defaultKaptcha.setConfig(new Config(properties));
        return defaultKaptcha;
    }


    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
        this.defaultKaptcha = null;
    }
}
