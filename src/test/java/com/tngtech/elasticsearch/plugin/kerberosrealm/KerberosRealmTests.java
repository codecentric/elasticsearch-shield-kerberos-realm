package com.tngtech.elasticsearch.plugin.kerberosrealm;

import com.tngtech.elasticsearch.plugin.kerberosrealm.realm.KerberosRealm;
import com.tngtech.elasticsearch.plugin.kerberosrealm.realm.KerberosToken;
import com.tngtech.elasticsearch.plugin.kerberosrealm.realm.KerberosTokenExtractor;
import com.tngtech.elasticsearch.plugin.kerberosrealm.realm.RolesProvider;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.env.Environment;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.shield.InternalSystemUser;
import org.elasticsearch.shield.User;
import org.elasticsearch.shield.authc.RealmConfig;
import org.elasticsearch.shield.authc.support.UsernamePasswordToken;
import org.elasticsearch.transport.TransportRequest;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import static org.junit.Assert.assertEquals;
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
        assertEquals(false, kerberosRealm.userLookupSupported());
        assertEquals(null, kerberosRealm.lookupUser("user"));
    }

    @Test
    public void should_support_only_kerberos_tokens() {
        KerberosToken kerberosToken = new KerberosToken(new byte[0], "");
        UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken(null, null);

        assertEquals(true, kerberosRealm.supports(kerberosToken));
        assertEquals(false, kerberosRealm.supports(usernamePasswordToken));
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
        assertEquals(InternalSystemUser.INSTANCE, kerberosRealm.authenticate(KerberosToken.LIVENESS_TOKEN));
    }

    @Test
    public void should_not_authenticate_invalid_kerberos_tokens() {
        KerberosToken token = new KerberosToken(new byte[0], "");

        assertEquals(null, kerberosRealm.authenticate(token));
    }

    @Test
    public void should_authenticate_valid_kerberos_tokens() {
        String principal = "principal";
        String[] roles = new String[]{"role 1", "role 2"};
        Mockito.when(mockedRolesProvider.getRoles(principal)).thenReturn(roles);
        KerberosToken token = new KerberosToken(new byte[0], principal);

        User user = kerberosRealm.authenticate(token);

        verify(mockedRolesProvider).getRoles(principal);
        assertEquals(principal, user.principal());
        assertEquals(roles, user.roles());
    }
}
