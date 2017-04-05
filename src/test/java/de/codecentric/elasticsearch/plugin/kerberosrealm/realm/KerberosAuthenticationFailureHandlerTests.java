package de.codecentric.elasticsearch.plugin.kerberosrealm.realm;

import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.action.admin.cluster.health.ClusterHealthRequest;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.test.rest.FakeRestRequest;
import org.elasticsearch.transport.TransportMessage;
import org.junit.Before;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.hasItem;
import static org.junit.Assert.assertThat;

public class KerberosAuthenticationFailureHandlerTests {

    private static final String NEGOTIATE = "Negotiate";
    private static final String WWW_AUTHENTICATE = "WWW-Authenticate";

    private KerberosAuthenticationFailureHandler failureHandler;

    @Before
    public void before() {
        failureHandler = new KerberosAuthenticationFailureHandler();
    }

    @Test
    public void should_add_www_authenticate_header_after_unsucessful_authentication_of_rest_request() {
        KerberosToken token = new KerberosToken(new byte[0]);
        RestRequest request = new FakeRestRequest();

        ElasticsearchSecurityException securityException = failureHandler.unsuccessfulAuthentication(request, token);

        assertThat(securityException.getHeader(WWW_AUTHENTICATE), hasItem(NEGOTIATE));
    }

    @Test
    public void should_add_www_authenticate_header_when_token_is_missing_in_rest_request() {
        RestRequest request = new FakeRestRequest();

        ElasticsearchSecurityException securityException = failureHandler.missingToken(request);

        assertThat(securityException.getHeader(WWW_AUTHENTICATE), hasItem(NEGOTIATE));
    }

    @Test
    public void should_add_www_authenticate_header_when_exception_occures_in_processing_a_rest_request() {
        RestRequest request = new FakeRestRequest();
        Exception exception = new Exception();

        ElasticsearchSecurityException securityException = failureHandler.exceptionProcessingRequest(request, exception);

        assertThat(securityException.getHeader(WWW_AUTHENTICATE), hasItem(NEGOTIATE));
    }

    @Test
    public void should_add_www_authenticate_header_when_authentication_is_required() {
        ElasticsearchSecurityException securityException = failureHandler.authenticationRequired("some action");

        assertThat(securityException.getHeader(WWW_AUTHENTICATE), hasItem(NEGOTIATE));
    }

    @Test
    public void should_add_www_authenticate_header_when_exception_occures_in_processing_a_transport_message() {
        TransportMessage message = new ClusterHealthRequest();
        Exception exception = new Exception();

        ElasticsearchSecurityException securityException = failureHandler.exceptionProcessingRequest(message, exception);

        assertThat(securityException.getHeader(WWW_AUTHENTICATE), hasItem(NEGOTIATE));
    }

    @Test
    public void should_add_www_authenticate_header_when_token_is_missing_in_transport_message() {
        TransportMessage message = new ClusterHealthRequest();

        ElasticsearchSecurityException securityException = failureHandler.missingToken(message, "action");

        assertThat(securityException.getHeader(WWW_AUTHENTICATE), hasItem(NEGOTIATE));
    }

    @Test
    public void should_add_www_authenticate_header_after_unsucessful_authentication_of_transport_message() {
        KerberosToken token = new KerberosToken(new byte[0]);
        TransportMessage message = new ClusterHealthRequest();

        ElasticsearchSecurityException securityException = failureHandler.unsuccessfulAuthentication(message, token, "action");

        assertThat(securityException.getHeader(WWW_AUTHENTICATE), hasItem(NEGOTIATE));
    }
}
