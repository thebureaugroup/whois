package net.ripe.db.whois.update.sso;

import com.google.common.base.Splitter;
import com.google.common.collect.Maps;
import net.ripe.db.whois.common.rpsl.AttributeType;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.RpslAttribute;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.common.rpsl.RpslObjectBuilder;
import net.ripe.db.whois.common.sso.AuthTranslator;
import net.ripe.db.whois.common.sso.CrowdClient;
import net.ripe.db.whois.common.sso.SsoHelper;
import net.ripe.db.whois.update.domain.Update;
import net.ripe.db.whois.update.domain.UpdateContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Iterator;
import java.util.Map;

@Component
public class SsoTranslator {
    private final CrowdClient crowdClient;

    @Autowired
    public SsoTranslator(final CrowdClient crowdClient) {
        this.crowdClient = crowdClient;
    }

    public void populate(final Update update, final UpdateContext updateContext) {
        final RpslObject submittedObject = update.getSubmittedObject();
        SsoHelper.translateAuth(submittedObject, new AuthTranslator() {
            @Override
            public RpslAttribute translate(String authType, String authToken, RpslAttribute originalAttribute) {
                if (authType.equals("SSO")) {
                    if (!updateContext.hasSsoTranslationResult(authToken)) {
                        updateContext.addSsoTranslationResult(authToken, crowdClient.getUuid(authToken));
                    }
                }
                return null;
            }
        });
    }

    public RpslObject translateAuthToUuid(UpdateContext updateContext, RpslObject rpslObject) {
        return translateAuth(updateContext, rpslObject);
    }

    public RpslObject translateAuthToUsername(final UpdateContext updateContext, final RpslObject rpslObject) {
        return translateAuth(updateContext, rpslObject);
    }

    private RpslObject translateAuth(final UpdateContext updateContext, final RpslObject rpslObject) {
        return SsoHelper.translateAuth(rpslObject, new AuthTranslator() {
            @Override
            public RpslAttribute translate(String authType, String authToken, RpslAttribute originalAttribute) {
                if (authType.equals("SSO")) {
                    String authValue = "SSO " + updateContext.getSsoTranslationResult(authToken);
                    return new RpslAttribute(originalAttribute.getKey(), authValue);
                }
                return null;
            }
        });
    }
}