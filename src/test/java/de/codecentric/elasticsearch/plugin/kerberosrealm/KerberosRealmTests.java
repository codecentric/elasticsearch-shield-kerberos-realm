package de.codecentric.elasticsearch.plugin.kerberosrealm;

import de.codecentric.elasticsearch.plugin.kerberosrealm.realm.*;
import org.elasticsearch.action.admin.cluster.health.ClusterHealthRequest;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.env.Environment;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.shield.InternalSystemUser;
import org.elasticsearch.shield.User;
import org.elasticsearch.shield.authc.RealmConfig;
import org.elasticsearch.shield.authc.support.UsernamePasswordToken;
import org.elasticsearch.test.rest.FakeRestRequest;
import org.elasticsearch.transport.TransportMessage;
import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.util.HashMap;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.*;

public class KerberosRealmTests {

    private KerberosRealm kerberosRealm;
    private RolesProvider mockedRolesProvider;
    private KerberosAuthenticator mockedAuthenticator;

    @Before
    public void before() {
        RealmConfig config = new RealmConfig("test", Settings.EMPTY, Settings.EMPTY, mock(Environment.class));
        mockedRolesProvider = mock(RolesProvider.class);
        mockedAuthenticator = mock(KerberosAuthenticator.class);

        kerberosRealm = new KerberosRealm(config, mockedAuthenticator, mockedRolesProvider);
    }

    @Test
    public void should_not_support_user_lookup() {
        assertThat(kerberosRealm.userLookupSupported(), is(false));
        assertThat(kerberosRealm.lookupUser("user"), is(nullValue()));
    }

    @Test
    public void should_support_only_kerberos_tokens() {
        KerberosToken kerberosToken = new KerberosToken(new byte[0]);
        UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken(null, null);

        assertThat(kerberosRealm.supports(kerberosToken), is(true));
        assertThat(kerberosRealm.supports(usernamePasswordToken), is(false));
    }

    @Test
    public void should_authenticate_liveness_token_as_interal_system_user() {
        assertThat(kerberosRealm.authenticate(LivenessToken.INSTANCE), Matchers.<User>is(InternalSystemUser.INSTANCE));
    }

    @Test
    public void should_not_authenticate_invalid_kerberos_tokens() {
        KerberosToken token = new KerberosToken(new byte[0]);
        when(mockedAuthenticator.authenticate(token)).thenReturn(null);

        assertThat(kerberosRealm.authenticate(token), is(nullValue()));
    }

    @Test
    public void should_return_null_when_rest_request_has_no_authorization_header() throws IOException {
        RestRequest request = new FakeRestRequest(new HashMap<String, String>(), new HashMap<String, String>());

        assertThat(kerberosRealm.token(request), is(nullValue()));
    }

    @Test
    public void should_return_null_when_transport_message_has_no_authorization_header() throws IOException {
        TransportMessage message = new ClusterHealthRequest();

        assertThat(kerberosRealm.token(message), is(nullValue()));
    }

    @Test
    public void should_authenticate_valid_kerberos_tokens() {
        String principal = "principal";
        KerberosToken token = new KerberosToken(new byte[0]);
        when(mockedAuthenticator.authenticate(token)).thenReturn(principal);
        String[] roles = new String[]{"role 1", "role 2"};
        when(mockedRolesProvider.getRoles(principal)).thenReturn(roles);

        User user = kerberosRealm.authenticate(token);

        verify(mockedRolesProvider).getRoles(principal);
        assertThat(user.principal(), is(principal));
        assertThat(user.roles(), arrayContainingInAnyOrder(roles));
    }
}
