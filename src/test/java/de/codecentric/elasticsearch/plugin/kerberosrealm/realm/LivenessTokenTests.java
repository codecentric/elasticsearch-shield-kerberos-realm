package de.codecentric.elasticsearch.plugin.kerberosrealm.realm;

import org.junit.Test;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertThat;

public class LivenessTokenTests {

    @Test
    public void should_not_clear_credentials() {
        LivenessToken token = LivenessToken.INSTANCE;
        token.clearCredentials();

        assertThat(token.credentials(), is(notNullValue()));
    }
}
