/*
   Copyright 2015 codecentric AG

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

   Author: Hendrik Saly <hendrik.saly@codecentric.de>
 */
package de.codecentric.elasticsearch.plugin.kerberosrealm;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

import java.io.File;
import java.net.URL;

import javax.security.auth.login.LoginException;

import net.sourceforge.spnego.SpnegoHttpURLConnection;

import org.apache.commons.io.FileUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.kerby.kerberos.kerb.spec.ticket.TgtTicket;
import org.elasticsearch.action.admin.cluster.health.ClusterHealthResponse;
import org.elasticsearch.action.admin.cluster.node.info.NodeInfo;
import org.elasticsearch.action.admin.cluster.node.info.NodesInfoResponse;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.cluster.health.ClusterHealthStatus;
import org.elasticsearch.common.SuppressForbidden;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.json.JsonXContent;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.shield.ShieldPlugin;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import de.codecentric.elasticsearch.plugin.kerberosrealm.client.KerberizedClient;
import de.codecentric.elasticsearch.plugin.kerberosrealm.client.MockingKerberizedClient;
import de.codecentric.elasticsearch.plugin.kerberosrealm.realm.KerberosRealm;
import de.codecentric.elasticsearch.plugin.kerberosrealm.support.PropertyUtil;
import de.codecentric.elasticsearch.plugin.kerberosrealm.support.SettingConstants;

/**
 * Integration test to test authentication with the custom realm. This test is run against an external cluster that is launched
 * by maven and this test is not expected to run within an IDE.
 */

@SuppressForbidden(reason = "unit test")
public class KerberosRealmEmbeddedTests extends AbstractUnitTest {

    @Test
    public void testTransportClient() throws Exception {
        embeddedKrbServer.getSimpleKdcServer().createPrincipal("spock/admin@CCK.COM", "secret");
        embeddedKrbServer.getSimpleKdcServer().createPrincipal("elasticsearch/transport@CCK.COM", "testpwd");
        FileUtils.forceMkdir(new File("testtmp/config/keytab/"));
        embeddedKrbServer.getSimpleKdcServer().exportPrincipal("elasticsearch/transport@CCK.COM",
                new File("testtmp/config/keytab/es_server.keytab")); //server, acceptor

        final Settings esServerSettings = Settings.builder()
                .put(PREFIX + SettingConstants.ACCEPTOR_KEYTAB_PATH, "keytab/es_server.keytab")
                //relative to config
                .put(PREFIX + SettingConstants.ACCEPTOR_PRINCIPAL, "elasticsearch/transport@CCK.COM")
                .put(PREFIX + SettingConstants.STRIP_REALM_FROM_PRINCIPAL, true)
                .putArray(PREFIX + SettingConstants.ROLES+".cc_kerberos_realm_role", "spock/admin@CCK.COM")
                //.put(PREFIX+SettingConstants.KRB5_FILE_PATH,"") //if already set by kerby here
                //.put(PREFIX+SettingConstants.KRB_DEBUG, true)
                .build();

        this.startES(esServerSettings);

        final NodesInfoResponse nodeInfos = client().admin().cluster().prepareNodesInfo().get();
        final NodeInfo[] nodes = nodeInfos.getNodes();
        assertTrue(nodes.length > 2);

        final Settings settings = Settings.builder().put("cluster.name", clustername)
                .putArray("plugin.types", ShieldPlugin.class.getName()).build();

        try (TransportClient client = TransportClient.builder().settings(settings).build()) {
            client.addTransportAddress(nodes[0].getTransport().address().publishAddress());
            try (KerberizedClient kc = new KerberizedClient(client, "spock/admin@CCK.COM", "secret", "elasticsearch/transport@CCK.COM")) {

                ClusterHealthResponse response = kc.admin().cluster().prepareHealth().execute().actionGet();
                assertThat(response.isTimedOut(), is(false));

                response = kc.admin().cluster().prepareHealth().execute().actionGet();
                assertThat(response.isTimedOut(), is(false));

                response = kc.admin().cluster().prepareHealth().execute().actionGet();
                assertThat(response.isTimedOut(), is(false));
                assertThat(response.status(), is(RestStatus.OK));
                assertThat(response.getStatus(), is(ClusterHealthStatus.GREEN));
            }
        }
    }

    @Test
    public void testTransportClientMultiRound() throws Exception {

        //Mock mode, no kerberos involved

        embeddedKrbServer.getSimpleKdcServer().stop();

        final Settings esServerSettings = Settings.builder().put(PREFIX + SettingConstants.ACCEPTOR_KEYTAB_PATH, "mock")
                .put(PREFIX + SettingConstants.ACCEPTOR_PRINCIPAL, "mock").put(PREFIX + "mock_mode", true)
                .putArray(PREFIX + SettingConstants.ROLES+".cc_kerberos_realm_role", "spock/admin@CCK.COM","mock_principal")
                .build();

        this.startES(esServerSettings);

        final NodesInfoResponse nodeInfos = client().admin().cluster().prepareNodesInfo().get();
        final NodeInfo[] nodes = nodeInfos.getNodes();
        assertTrue(nodes.length > 2);

        final Settings settings = Settings.builder().put("cluster.name", clustername)
                .putArray("plugin.types", ShieldPlugin.class.getName()).build();

        try (TransportClient client = TransportClient.builder().settings(settings).build()) {
            client.addTransportAddress(nodes[0].getTransport().address().publishAddress());
            try (KerberizedClient kc = new MockingKerberizedClient(client)) {

                ClusterHealthResponse response = kc.admin().cluster().prepareHealth().execute().actionGet();
                assertThat(response.isTimedOut(), is(false));

                response = kc.admin().cluster().prepareHealth().execute().actionGet();
                assertThat(response.isTimedOut(), is(false));

                response = kc.admin().cluster().prepareHealth().execute().actionGet();
                assertThat(response.isTimedOut(), is(false));
                assertThat(response.status(), is(RestStatus.OK));
                assertThat(response.getStatus(), is(ClusterHealthStatus.GREEN));
            }
        }
    }

    @Test(expected = LoginException.class)
    public void testTransportClientBadUser() throws Exception {
        embeddedKrbServer.getSimpleKdcServer().createPrincipal("spock/admin@CCK.COM", "secret");
        embeddedKrbServer.getSimpleKdcServer().createPrincipal("elasticsearch/transport@CCK.COM", "testpwd");
        FileUtils.forceMkdir(new File("testtmp/config/keytab/"));
        embeddedKrbServer.getSimpleKdcServer().exportPrincipal("elasticsearch/transport@CCK.COM",
                new File("testtmp/config/keytab/es_server.keytab")); //server, acceptor

        final Settings esServerSettings = Settings.builder().put(PREFIX + SettingConstants.ACCEPTOR_KEYTAB_PATH, "keytab/es_server.keytab")
                .put(PREFIX + SettingConstants.ACCEPTOR_PRINCIPAL, "elasticsearch/transport@CCK.COM")
                .put(PREFIX + SettingConstants.STRIP_REALM_FROM_PRINCIPAL, true)
                .putArray(PREFIX + SettingConstants.ROLES+".cc_kerberos_realm_role", "spock/admin@CCK.COM")
                //.put(PREFIX+SettingConstants.KRB5_FILE_PATH,"") //if already set by kerby here
                //.put(PREFIX+SettingConstants.KRB_DEBUG, true)
                .build();

        this.startES(esServerSettings);

        final NodesInfoResponse nodeInfos = client().admin().cluster().prepareNodesInfo().get();
        final NodeInfo[] nodes = nodeInfos.getNodes();
        assertTrue(nodes.length > 2);

        final Settings settings = Settings.builder().put("cluster.name", clustername)
                .putArray("plugin.types", ShieldPlugin.class.getName()).build();

        try (TransportClient client = TransportClient.builder().settings(settings).build()) {
            client.addTransportAddress(nodes[0].getTransport().address().publishAddress());
            try (KerberizedClient kc = new KerberizedClient(client, "spock/admin@CCK.COM_bad", "secret-wrong",
                    "elasticsearch/transport@CCK.COM")) {

                ClusterHealthResponse response = kc.admin().cluster().prepareHealth().execute().actionGet();
                assertThat(response.isTimedOut(), is(false));

                response = kc.admin().cluster().prepareHealth().execute().actionGet();
                assertThat(response.isTimedOut(), is(false));

                response = kc.admin().cluster().prepareHealth().execute().actionGet();
                assertThat(response.isTimedOut(), is(false));
                assertThat(response.status(), is(RestStatus.OK));
                assertThat(response.getStatus(), is(ClusterHealthStatus.GREEN));
            }
        }
    }

    @Test
    public void testSettingsFiltering() throws Exception {
        embeddedKrbServer.getSimpleKdcServer().createPrincipal("spock/admin@CCK.COM", "secret");
        embeddedKrbServer.getSimpleKdcServer().createPrincipal("HTTP/localhost@CCK.COM", "testpwd1");

        FileUtils.forceMkdir(new File("testtmp/config/keytab/"));

        embeddedKrbServer.getSimpleKdcServer().exportPrincipal("HTTP/localhost@CCK.COM",
                new File("testtmp/config/keytab/es_server.keytab")); //server, acceptor

        final TgtTicket tgt = embeddedKrbServer.getSimpleKdcServer().getKrbClient().requestTgtWithPassword("spock/admin@CCK.COM", "secret");
        embeddedKrbServer.getSimpleKdcServer().getKrbClient().storeTicket(tgt, new File("testtmp/tgtcc/spock.cc"));

        final Settings esServerSettings = Settings.builder().put(PREFIX + SettingConstants.ACCEPTOR_KEYTAB_PATH, "keytab/es_server.keytab")
                .put(PREFIX + SettingConstants.ACCEPTOR_PRINCIPAL, "HTTP/localhost@CCK.COM")
                .put(PREFIX + SettingConstants.STRIP_REALM_FROM_PRINCIPAL, true)
                .putArray(PREFIX + SettingConstants.ROLES+".cc_kerberos_realm_role", "spock/admin@CCK.COM")
                //.put(PREFIX+SettingConstants.KRB5_FILE_PATH,"") //if already set by kerby here
                //.put(PREFIX+SettingConstants.KRB_DEBUG, true)
                .build();

        this.startES(esServerSettings);

        net.sourceforge.spnego.SpnegoHttpURLConnection hcon = new SpnegoHttpURLConnection("com.sun.security.jgss.krb5.initiate");

        hcon.requestCredDeleg(true);
        hcon.connect(new URL(getServerUri() + "/_cluster/health"));
        Assert.assertEquals(200, hcon.getResponseCode());

        hcon = new SpnegoHttpURLConnection("com.sun.security.jgss.krb5.initiate");
        hcon.requestCredDeleg(true);
        hcon.connect(new URL(getServerUri() + "/_nodes/settings"));
        Assert.assertEquals(200, hcon.getResponseCode());

        //final CloseableHttpClient httpClient = getHttpClient(true);
        //final CloseableHttpResponse response = httpClient.execute(new HttpGet(new URL(getServerUri() + "/_nodes/settings").toURI()));

        //assertThat(response.getStatusLine().getStatusCode(), is(200));

        final XContentParser parser = JsonXContent.jsonXContent.createParser(hcon.getInputStream());
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
    
    @Test
    public void testRestNoTicketCache() throws Exception {
        embeddedKrbServer.getSimpleKdcServer().createPrincipal("spock/admin@CCK.COM", "secret");
        embeddedKrbServer.getSimpleKdcServer().createPrincipal("HTTP/localhost@CCK.COM", "testpwd1");
        FileUtils.forceMkdir(new File("testtmp/config/keytab/"));
        embeddedKrbServer.getSimpleKdcServer().exportPrincipal("HTTP/localhost@CCK.COM",
                new File("testtmp/config/keytab/es_server.keytab")); //server, acceptor

        final Settings esServerSettings = Settings.builder().put(PREFIX + SettingConstants.ACCEPTOR_KEYTAB_PATH, "keytab/es_server.keytab")
                .put(PREFIX + SettingConstants.ACCEPTOR_PRINCIPAL, "HTTP/localhost@CCK.COM")
                .put(PREFIX + SettingConstants.STRIP_REALM_FROM_PRINCIPAL, true)
                .putArray(PREFIX + SettingConstants.ROLES+".cc_kerberos_realm_role", "spock/admin@CCK.COM")
                //.put(PREFIX+SettingConstants.KRB5_FILE_PATH,"") //if already set by kerby here
                //.put(PREFIX+SettingConstants.KRB_DEBUG, true)
                .build();

        this.startES(esServerSettings);
        
        net.sourceforge.spnego.SpnegoHttpURLConnection hcon = new SpnegoHttpURLConnection("no.ticket.cache","spock/admin@CCK.COM","secret");

        hcon.requestCredDeleg(true);
        hcon.connect(new URL(getServerUri() + "/_nodes/settings"));
        Assert.assertEquals(200, hcon.getResponseCode());

        //final CloseableHttpClient httpClient = getHttpClient(true);
        //final CloseableHttpResponse response = httpClient.execute(new HttpGet(new URL(getServerUri() + "/_nodes/settings").toURI()));

        //assertThat(response.getStatusLine().getStatusCode(), is(401));
    }

    @Test
    @Ignore
    public void testRestNoTicket() throws Exception {
        embeddedKrbServer.getSimpleKdcServer().createPrincipal("spock/admin@CCK.COM", "secret");
        embeddedKrbServer.getSimpleKdcServer().createPrincipal("HTTP/localhost@CCK.COM", "testpwd1");
        FileUtils.forceMkdir(new File("testtmp/config/keytab/"));
        embeddedKrbServer.getSimpleKdcServer().exportPrincipal("HTTP/localhost@CCK.COM",
                new File("testtmp/config/keytab/es_server.keytab")); //server, acceptor

        //final TgtTicket tgt = embeddedKrbServer.getSimpleKdcServer().getKrbClient().requestTgtWithPassword("spock/admin@CCK.COM", "secret");
        //embeddedKrbServer.getSimpleKdcServer().getKrbClient().storeTicket(tgt, new File("testtmp/tgtcc/spock.cc"));

        final Settings esServerSettings = Settings.builder().put(PREFIX + SettingConstants.ACCEPTOR_KEYTAB_PATH, "keytab/es_server.keytab")
                .put(PREFIX + SettingConstants.ACCEPTOR_PRINCIPAL, "HTTP/localhost@CCK.COM")
                .put(PREFIX + SettingConstants.STRIP_REALM_FROM_PRINCIPAL, true)
                .putArray(PREFIX + SettingConstants.ROLES+".cc_kerberos_realm_role", "spock/admin@CCK.COM")
                //.put(PREFIX+SettingConstants.KRB5_FILE_PATH,"") //if already set by kerby here
                //.put(PREFIX+SettingConstants.KRB_DEBUG, true)
                .build();

        this.startES(esServerSettings);
        
        net.sourceforge.spnego.SpnegoHttpURLConnection hcon = new SpnegoHttpURLConnection("no.ticket.cache","1spock/admin@CCK.COM","secret");

        hcon.requestCredDeleg(true);
        hcon.connect(new URL(getServerUri() + "/_nodes/settings"));
        Assert.assertEquals(200, hcon.getResponseCode());

        //final CloseableHttpClient httpClient = getHttpClient(true);
        //final CloseableHttpResponse response = httpClient.execute(new HttpGet(new URL(getServerUri() + "/_nodes/settings").toURI()));

        //assertThat(response.getStatusLine().getStatusCode(), is(401));
    }
    
    @Test
    @Ignore
    public void testRestBadAcceptor() throws Exception {
        embeddedKrbServer.getSimpleKdcServer().createPrincipal("spock/admin@CCK.COM", "secret");
        embeddedKrbServer.getSimpleKdcServer().createPrincipal("HTTP/localhost@CCK.COM", "testpwd1");
        FileUtils.forceMkdir(new File("testtmp/config/keytab/"));
        embeddedKrbServer.getSimpleKdcServer().exportPrincipal("HTTP/localhost@CCK.COM",
                new File("testtmp/config/keytab/es_server.keytab")); //server, acceptor

        final TgtTicket tgt = embeddedKrbServer.getSimpleKdcServer().getKrbClient().requestTgtWithPassword("spock/admin@CCK.COM", "secret");
        embeddedKrbServer.getSimpleKdcServer().getKrbClient().storeTicket(tgt, new File("testtmp/tgtcc/spock.cc"));

        final Settings esServerSettings = Settings.builder().put(PREFIX + SettingConstants.ACCEPTOR_KEYTAB_PATH, "keytab/es_server.keytab")
                .put(PREFIX + SettingConstants.ACCEPTOR_PRINCIPAL, "bad").put(PREFIX + SettingConstants.STRIP_REALM_FROM_PRINCIPAL, true)
                .putArray(PREFIX + SettingConstants.ROLES+".cc_kerberos_realm_role", "spock/admin@CCK.COM")
                //.put(PREFIX+SettingConstants.KRB5_FILE_PATH,"") //if already set by kerby here
                //.put(PREFIX+SettingConstants.KRB_DEBUG, true)
                .build();

        this.startES(esServerSettings);
        
        net.sourceforge.spnego.SpnegoHttpURLConnection hcon = new SpnegoHttpURLConnection("com.sun.security.jgss.krb5.initiate");

        hcon.requestCredDeleg(true);
        hcon.connect(new URL(getServerUri() + "/_nodes/settings"));
        Assert.assertEquals(401, hcon.getResponseCode());

        //final CloseableHttpClient httpClient = getHttpClient(true);
        //final CloseableHttpResponse response = httpClient.execute(new HttpGet(new URL(getServerUri() + "/_nodes/settings").toURI()));

        //assertThat(response.getStatusLine().getStatusCode(), is(401));
    }
}
