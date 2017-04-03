package de.codecentric.elasticsearch.plugin.kerberosrealm;

import de.codecentric.elasticsearch.plugin.kerberosrealm.client.KerberizedClient;
import de.codecentric.elasticsearch.plugin.kerberosrealm.realm.KerberosRealm;
import org.codelibs.spnego.SpnegoHttpURLConnection;
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
import org.ietf.jgss.GSSException;
import org.junit.Test;

import javax.security.auth.login.LoginException;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.security.PrivilegedActionException;

import static java.net.HttpURLConnection.HTTP_OK;
import static java.net.HttpURLConnection.HTTP_UNAUTHORIZED;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.*;

public class KerberosRealmIT {

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
        SpnegoHttpURLConnection connection = new SpnegoHttpURLConnection("restClient", "user@LOCALHOST", "password");

        connection.requestCredDeleg(true);
        connection.connect(new URL(url + "/_shield/authenticate"));

        assertThat(connection.getResponseCode(), is(HTTP_OK));
    }

    @Test
    public void should_authenticate_a_transport_client() throws IOException, LoginException, GSSException {
        InetAddress address = InetAddress.getByName(System.getProperty("elasticsearch.host"));
        int port = Integer.valueOf(System.getProperty("elasticsearch.transport.port"));

        Settings settings = Settings.builder()
                .put("cluster.name", "elasticsearch")
                .put("de.codecentric.realm.cc-kerberos.krb5.file_path", System.getProperty("krb5.conf"))
                .build();

        try (TransportClient client = TransportClient.builder().settings(settings).build()) {
            client.addTransportAddress(new InetSocketTransportAddress(address, port));
            try (KerberizedClient kc = new KerberizedClient(client, "user@LOCALHOST", "password", "HTTP/localhost@LOCALHOST")) {

                ClusterHealthResponse response = kc.admin().cluster().prepareHealth().execute().actionGet();
                assertThat(response.isTimedOut(), is(false));
                assertThat(response.status(), is(RestStatus.OK));
                assertThat(response.getStatus(), is(ClusterHealthStatus.GREEN));
            }
        }
    }

    @Test(expected = LoginException.class)
    public void should_not_authenticate_a_transport_client_with_the_wrong_password() throws Exception {
        int transportPort = Integer.valueOf(System.getProperty("elasticsearch.transport.port"));

        final Settings settings = Settings.builder()
                .put("cluster.name", "elasticsearch")
                .putArray("plugin.types", ShieldPlugin.class.getName())
                .put("de.codecentric.realm.cc-kerberos.krb5.file_path", System.getProperty("krb5.conf"))
                .build();

        try (TransportClient client = TransportClient.builder().settings(settings).build()) {
            client.addTransportAddress(new InetSocketTransportAddress(InetAddress.getByName(System.getProperty("elasticsearch.host")), transportPort));
            new KerberizedClient(client, "user@LOCALHOST", "wrong_password", "HTTP/localhost@LOCALHOST");
        }
    }

    @Test
    public void should_filter_settings() throws Exception {
        String url = System.getProperty("elasticsearch.rest.url");

        SpnegoHttpURLConnection connection = new SpnegoHttpURLConnection("restClient", "user@LOCALHOST", "password");

        connection.requestCredDeleg(true);
        connection.connect(new URL(url + "/_cluster/health"));
        assertThat(connection.getResponseCode(), is(HTTP_OK));

        connection = new SpnegoHttpURLConnection("restClient", "user@LOCALHOST", "password");
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