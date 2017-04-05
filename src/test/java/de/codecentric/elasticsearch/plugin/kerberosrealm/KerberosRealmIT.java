package de.codecentric.elasticsearch.plugin.kerberosrealm;

import de.codecentric.elasticsearch.plugin.kerberosrealm.realm.KerberosRealm;
import org.codelibs.spnego.SpnegoHttpURLConnection;
import org.codelibs.spnego.SpnegoProvider;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.action.admin.cluster.health.ClusterHealthResponse;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.cluster.health.ClusterHealthStatus;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.InetSocketTransportAddress;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.json.JsonXContent;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.shield.ShieldPlugin;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.junit.Test;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.PrivilegedActionException;

import static java.net.HttpURLConnection.HTTP_OK;
import static java.net.HttpURLConnection.HTTP_UNAUTHORIZED;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.*;

public class KerberosRealmIT {

    private String getToken(LoginContext loginContext) throws PrivilegedActionException, MalformedURLException, GSSException {
        GSSCredential credential = SpnegoProvider.getClientCredential(loginContext.getSubject());
        GSSContext context = SpnegoProvider.getGSSContext(credential, new URL("http://" + System.getProperty("elasticsearch.host")));

        context.requestMutualAuth(true);
        context.requestConf(true);
        context.requestInteg(true);

        return DatatypeConverter.printBase64Binary(context.initSecContext(new byte[0], 0, 0));
    }

    @Test
    public void should_initially_responds_with_unauthorized() throws IOException {
        URL url = new URL(System.getProperty("elasticsearch.rest.url"));
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();

        connection.connect();

        assertThat(connection.getResponseCode(), is(HTTP_UNAUTHORIZED));
        assertThat(connection.getHeaderField("WWW-Authenticate"), is("Negotiate"));
    }

    @Test
    public void should_authenticate_a_rest_request() throws LoginException, IOException, PrivilegedActionException, GSSException {
        String url = System.getProperty("elasticsearch.rest.url");
        SpnegoHttpURLConnection connection = new SpnegoHttpURLConnection("client", "user@LOCALHOST", "password");

        connection.requestCredDeleg(true);
        connection.connect(new URL(url + "/_shield/authenticate"));

        assertThat(connection.getResponseCode(), is(HTTP_OK));
    }

    @Test
    public void should_authenticate_a_transport_client() throws IOException, LoginException, PrivilegedActionException, GSSException {
        InetAddress address = InetAddress.getByName(System.getProperty("elasticsearch.host"));
        int port = Integer.valueOf(System.getProperty("elasticsearch.transport.port"));

        Settings settings = Settings.builder().put("cluster.name", "elasticsearch").build();

        CallbackHandler handler = SpnegoProvider.getUsernamePasswordHandler("user@LOCALHOST", "password");
        LoginContext loginContext = new LoginContext("client", handler);
        loginContext.login();

        try (TransportClient client = TransportClient.builder().settings(settings).addPlugin(ShieldPlugin.class).build()) {
            client.addTransportAddress(new InetSocketTransportAddress(address, port));

            ClusterHealthResponse response = client.admin().cluster().prepareHealth()
                    .putHeader("Authorization", "Negotiate " + getToken(loginContext))
                    .execute().actionGet();
            assertThat(response.isTimedOut(), is(false));
            assertThat(response.status(), is(RestStatus.OK));
            assertThat(response.getStatus(), is(ClusterHealthStatus.GREEN));
        }

        loginContext.logout();
    }

    @Test(expected = ElasticsearchSecurityException.class)
    public void should_not_authenticate_a_transport_client_without_a_token() throws Exception {
        InetAddress address = InetAddress.getByName(System.getProperty("elasticsearch.host"));
        int port = Integer.valueOf(System.getProperty("elasticsearch.transport.port"));

        Settings settings = Settings.builder().put("cluster.name", "elasticsearch").build();

        try (TransportClient client = TransportClient.builder().settings(settings).addPlugin(ShieldPlugin.class).build()) {
            client.addTransportAddress(new InetSocketTransportAddress(address, port));
            client.admin().cluster().prepareHealth().execute().actionGet();
        }
    }

    @Test
    public void should_filter_settings() throws Exception {
        String url = System.getProperty("elasticsearch.rest.url");

        SpnegoHttpURLConnection connection = new SpnegoHttpURLConnection("client", "user@LOCALHOST", "password");

        connection.requestCredDeleg(true);
        connection.connect(new URL(url + "/_cluster/health"));
        assertThat(connection.getResponseCode(), is(HTTP_OK));

        connection = new SpnegoHttpURLConnection("client", "user@LOCALHOST", "password");
        connection.requestCredDeleg(true);
        connection.connect(new URL(url + "/_nodes/settings"));
        assertThat(connection.getResponseCode(), is(HTTP_OK));

        final XContentParser parser = JsonXContent.jsonXContent.createParser(connection.getInputStream());
        XContentParser.Token token;
        Settings settings = null;
        while ((token = parser.nextToken()) != null) {
            if (token == XContentParser.Token.FIELD_NAME && parser.currentName().equals("settings")) {
                parser.nextToken();
                final XContentBuilder builder = XContentBuilder.builder(parser.contentType().xContent());
                settings = Settings.builder().loadFromSource(builder.copyCurrentStructure(parser).bytes().toUtf8()).build();
                break;
            }
        }
        assertTrue(settings != null);
        assertFalse(settings.getAsMap().isEmpty());
        assertTrue(settings.getGroups("shield.authc.realms." + KerberosRealm.TYPE).isEmpty());
    }
}