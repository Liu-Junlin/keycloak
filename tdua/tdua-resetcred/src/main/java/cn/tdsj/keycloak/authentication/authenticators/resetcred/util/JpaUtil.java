package cn.tdsj.keycloak.authentication.authenticators.resetcred.util;

import org.keycloak.authentication.AbstractAuthenticationFlowContext;
import org.keycloak.connections.jpa.JpaConnectionProvider;

import javax.persistence.EntityManager;

/**
 * @author liujunlin
 */
public class JpaUtil {
    public static EntityManager getEntityManager(AbstractAuthenticationFlowContext context) {
        return context.getSession().getProvider(JpaConnectionProvider.class).getEntityManager();
    }
}
