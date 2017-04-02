package de.codecentric.elasticsearch.plugin.kerberosrealm;

import de.codecentric.elasticsearch.plugin.kerberosrealm.realm.KerberosRealm;
import de.codecentric.elasticsearch.plugin.kerberosrealm.realm.KerberosToken;
import de.codecentric.elasticsearch.plugin.kerberosrealm.realm.KerberosTokenExtractor;
import de.codecentric.elasticsearch.plugin.kerberosrealm.realm.RolesProvider;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.env.Environment;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.shield.InternalSystemUser;
import org.elasticsearch.shield.User;
import org.elasticsearch.shield.authc.RealmConfig;
import org.elasticsearch.shield.authc.support.UsernamePasswordToken;
import org.elasticsearch.transport.TransportRequest;
import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

public class KerberosRealmTests {

    private KerberosRealm kerberosRealm;
    private RolesProvider mockedRolesProvider;
    private KerberosTokenExtractor mockedTokenExtractor;

    @Before
    public void before() {
        RealmConfig config = new RealmConfig("test", Settings.EMPTY, Settings.EMPTY, mock(Environment.class));
        mockedRolesProvider = mock(RolesProvider.class);
        mockedTokenExtractor = mock(KerberosTokenExtractor.class);

        kerberosRealm = new KerberosRealm(config, mockedTokenExtractor, mockedRolesProvider);
    }

    @Test
    public void should_not_support_user_lookup() {
        assertThat(kerberosRealm.userLookupSupported(), is(false));
        assertThat(kerberosRealm.lookupUser("user"), is(nullValue()));
    }

    @Test
    public void should_support_only_kerberos_tokens() {
        KerberosToken kerberosToken = new KerberosToken(new byte[0], "");
        UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken(null, null);

        assertThat(kerberosRealm.supports(kerberosToken), is(true));
        assertThat(kerberosRealm.supports(usernamePasswordToken), is(false));
    }

    @Test
    public void should_redirect_the_token_extraction_for_rest_requests() {
        RestRequest mockedRequest = mock(RestRequest.class);
        kerberosRealm.token(mockedRequest);
        verify(mockedTokenExtractor).extractToken(mockedRequest);
    }

    @Test
    public void should_redirect_the_token_extraction_for_transport_requests() {
        TransportRequest mockedRequest = mock(TransportRequest.class);
        kerberosRealm.token(mockedRequest);

        verify(mockedTokenExtractor).extractToken(mockedRequest);
    }

    @Test
    public void should_authenticate_liveness_token_as_interal_system_user() {
        assertThat(kerberosRealm.authenticate(KerberosToken.LIVENESS_TOKEN), Matchers.<User>is(InternalSystemUser.INSTANCE));
    }

    @Test
    public void should_not_authenticate_invalid_kerberos_tokens() {
        KerberosToken token = new KerberosToken(new byte[0], "");

        assertThat(kerberosRealm.authenticate(token), is(nullValue()));
    }

    @Test
    public void should_authenticate_valid_kerberos_tokens() {
        String principal = "principal";
        String[] roles = new String[]{"role 1", "role 2"};
        Mockito.when(mockedRolesProvider.getRoles(principal)).thenReturn(roles);
        KerberosToken token = new KerberosToken(new byte[0], principal);

        User user = kerberosRealm.authenticate(token);

        verify(mockedRolesProvider).getRoles(principal);
        assertThat(user.principal(), is(principal));
        assertThat(user.roles(), arrayContainingInAnyOrder(roles));
    }
}
