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

import static org.elasticsearch.common.settings.Settings.settingsBuilder;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Principal;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import org.apache.commons.io.FileUtils;
import org.apache.http.auth.AuthSchemeProvider;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.NTCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.AuthSchemes;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.config.SocketConfig;
import org.apache.http.impl.auth.NTLMSchemeFactory;
import org.apache.http.impl.auth.SPNegoSchemeFactory;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.kerby.util.NetworkUtil;
import org.elasticsearch.ElasticsearchTimeoutException;
import org.elasticsearch.action.admin.cluster.health.ClusterHealthResponse;
import org.elasticsearch.action.admin.cluster.node.info.NodeInfo;
import org.elasticsearch.action.admin.cluster.node.info.NodesInfoResponse;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.health.ClusterHealthStatus;
import org.elasticsearch.common.SuppressForbidden;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.license.plugin.LicensePlugin;
import org.elasticsearch.node.Node;
import org.elasticsearch.node.NodeBuilder;
import org.elasticsearch.node.PluginEnabledNode;
import org.elasticsearch.shield.ShieldPlugin;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.rules.TestName;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

import com.google.common.collect.Lists;

import de.codecentric.elasticsearch.plugin.kerberosrealm.realm.KerberosRealm;
import de.codecentric.elasticsearch.plugin.kerberosrealm.support.EmbeddedKRBServer;
import de.codecentric.elasticsearch.plugin.kerberosrealm.support.JaasKrbUtil;
import de.codecentric.elasticsearch.plugin.kerberosrealm.support.KrbConstants;
import de.codecentric.elasticsearch.plugin.kerberosrealm.support.PropertyUtil;

@SuppressForbidden(reason = "unit test")
public abstract class AbstractUnitTest {

    public static boolean debugAll = false;
    protected static String PREFIX = "shield.authc.realms.cc-kerberos.";

    static {
        System.out.println("OS: " + System.getProperty("os.name") + " " + System.getProperty("os.arch") + " "
                + System.getProperty("os.version"));
        System.out.println("Java Version: " + System.getProperty("java.version") + " " + System.getProperty("java.vendor"));
        System.out.println("JVM Impl.: " + System.getProperty("java.vm.version") + " " + System.getProperty("java.vm.vendor") + " "
                + System.getProperty("java.vm.name"));

        if (debugAll) {
            System.setProperty("sun.security.krb5.debug", "true");
            System.setProperty("java.security.debug", "all");
            System.setProperty("sun.security.spnego.debug", "true");
            System.setProperty("java.security.auth.debug", "all");
            JaasKrbUtil.ENABLE_DEBUG = true;
        }
    }

    @Rule
    public TestName name = new TestName();
    protected final String clustername = "kerberos_testcluster";
    protected int elasticsearchHttpPort1;
    private int elasticsearchHttpPort2;
    private int elasticsearchHttpPort3;
    //public int elasticsearchNodePort1;
    //public int elasticsearchNodePort2;
    //public int elasticsearchNodePort3;

    private Node esNode1;
    private Node esNode2;
    private Node esNode3;
    private Client client;
    protected final ESLogger log = Loggers.getLogger(this.getClass());
    protected final EmbeddedKRBServer embeddedKrbServer = new EmbeddedKRBServer();

    @Rule
    public final TestWatcher testWatcher = new TestWatcher() {
        @Override
        protected void starting(final Description description) {
            final String methodName = description.getMethodName();
            String className = description.getClassName();
            className = className.substring(className.lastIndexOf('.') + 1);
            System.out.println("---------------- Starting JUnit-test: " + className + " " + methodName + " ----------------");
        }

        @Override
        protected void failed(final Throwable e, final Description description) {
            final String methodName = description.getMethodName();
            String className = description.getClassName();
            className = className.substring(className.lastIndexOf('.') + 1);
            System.out.println(">>>> " + className + " " + methodName + " FAILED due to " + e);
        }

        @Override
        protected void finished(final Description description) {
            //System.out.println("-----------------------------------------------------------------------------------------");
        }

    };

    protected AbstractUnitTest() {
        super();
    }

    private Settings.Builder getDefaultSettingsBuilder(final int nodenum, final int nodePort, final int httpPort, final boolean dataNode,
            final boolean masterNode) {

        // @formatter:off
        return settingsBuilder()
                //.putArray("plugin.types", ShieldPlugin.class.getName(), LicensePlugin.class.getName(), KerberosRealmPlugin.class.getName())
                .putArray("plugin.mandatory",KerberosRealm.TYPE + "-realm","shield","license")
                .put("index.queries.cache.type", "opt_out_cache").put(PREFIX + "order", 0).put(PREFIX + "type", "cc-kerberos")
                .put("path.home", ".").put("node.name", "kerberosrealm_testnode_" + nodenum).put("node.data", dataNode)
                .put("node.master", masterNode).put("cluster.name", clustername).put("path.data", "testtmp/data")
                .put("path.work", "testtmp/work").put("path.logs", "testtmp/logs").put("path.conf", "testtmp/config")
                .put("path.plugins", "testtmp/plugins").put("index.number_of_shards", "2").put("index.number_of_replicas", "1")
                .put("http.host", "localhost")
                .put("http.port", httpPort)
                .put("http.enabled", !dataNode)
                //.put("transport.tcp.port", nodePort) //currently not working
                .put("http.cors.enabled", true)
                //.put("network.host", getNonLocalhostAddress()) //currently not working
                //.put("node.local", true); //do not use
                .put("node.local", false);
        // @formatter:on
    }

    protected final String getServerUri() {
        final String address = "http://localhost:" + elasticsearchHttpPort1;
        log.debug("Connect to {}", address);
        return address;
    }

    public final void startES(final Settings settings) throws Exception {
        FileUtils.copyFileToDirectory(getAbsoluteFilePathFromClassPath("roles.yml").toFile(), new File("testtmp/config/shield"));

        final Set<Integer> ports = new HashSet<>();
        do {
            ports.add(NetworkUtil.getServerPort());
        } while (ports.size() < 7);

        final Iterator<Integer> portIt = ports.iterator();

        elasticsearchHttpPort1 = portIt.next();
        elasticsearchHttpPort2 = portIt.next();
        elasticsearchHttpPort3 = portIt.next();

        //elasticsearchNodePort1 = portIt.next();
        //elasticsearchNodePort2 = portIt.next();
        //elasticsearchNodePort3 = portIt.next();

        esNode1 = new PluginEnabledNode(getDefaultSettingsBuilder(1, 0, elasticsearchHttpPort1, false, true).put(
                settings == null ? Settings.Builder.EMPTY_SETTINGS : settings).build(), Lists.newArrayList(ShieldPlugin.class, LicensePlugin.class, KerberosRealmPlugin.class)).start();
        client = esNode1.client();
        
        esNode2 = new PluginEnabledNode(getDefaultSettingsBuilder(2, 0, elasticsearchHttpPort2, true, true).put(
                settings == null ? Settings.Builder.EMPTY_SETTINGS : settings).build(), Lists.newArrayList(ShieldPlugin.class, LicensePlugin.class, KerberosRealmPlugin.class)).start();
        
        esNode3 = new PluginEnabledNode(getDefaultSettingsBuilder(3, 0, elasticsearchHttpPort3, true, false).put(
                settings == null ? Settings.Builder.EMPTY_SETTINGS : settings).build(), Lists.newArrayList(ShieldPlugin.class, LicensePlugin.class, KerberosRealmPlugin.class)).start();
        
        waitForGreenClusterState();
        final NodesInfoResponse nodeInfos = client().admin().cluster().prepareNodesInfo().get();
        final NodeInfo[] nodes = nodeInfos.getNodes();
        Assert.assertEquals(nodes + "", 3, nodes.length);
    }

    @Before
    public final void startKRBServer() throws Exception {
        FileUtils.deleteDirectory(new File("testtmp"));
        FileUtils.forceMkdir(new File("testtmp/tgtcc/"));
        FileUtils.forceMkdir(new File("testtmp/keytab/"));

        String loginconf = FileUtils.readFileToString(getAbsoluteFilePathFromClassPath("login.conf_template").toFile());

        // @formatter:on
        loginconf = loginconf.replace("${debug}", String.valueOf(debugAll)).replace("${initiator.principal}", "spock/admin@CCK.COM")
                .replace("${initiator.ticketcache}", new File("testtmp/tgtcc/spock.cc").toURI().toString())
                .replace("${keytab}", new File("testtmp/keytab/es_server.keytab").toURI().toString());
        // @formatter:off

        final File loginconfFile = new File("testtmp/jaas/login.conf");
        FileUtils.write(new File("testtmp/jaas/login.conf"), loginconf);
        PropertyUtil.setSystemProperty(KrbConstants.JAAS_LOGIN_CONF_PROP, loginconfFile.getAbsolutePath(), true);

        embeddedKrbServer.start(new File("testtmp/simplekdc/"));

        FileUtils.copyFileToDirectory(new File("testtmp/simplekdc/krb5.conf"), new File("testtmp/config/data/simplekdc/"));
    }

    @After
    public void tearDown() throws Exception {
        if (esNode3 != null) {
            esNode3.close();
        }

        if (esNode2 != null) {
            esNode2.close();
        }

        if (esNode1 != null) {
            esNode1.close();
        }

        if (client != null) {
            client.close();
        }

        if (embeddedKrbServer != null) {
            embeddedKrbServer.getSimpleKdcServer().stop();
        }

    }

    protected final CloseableHttpClient getHttpClient(final boolean useSpnego) throws Exception {

        final CredentialsProvider credsProvider = new BasicCredentialsProvider();
        final HttpClientBuilder hcb = HttpClients.custom();

        if (useSpnego) {
            //SPNEGO/Kerberos setup
            log.debug("SPNEGO activated");
            final AuthSchemeProvider nsf = new SPNegoSchemeFactory(true);//  new NegotiateSchemeProvider();
            final Credentials jaasCreds = new JaasCredentials();
            credsProvider.setCredentials(new AuthScope(null, -1, null, AuthSchemes.SPNEGO), jaasCreds);
            credsProvider.setCredentials(new AuthScope(null, -1, null, AuthSchemes.NTLM), new NTCredentials("Guest", "Guest", "Guest",
                    "Guest"));
            final Registry<AuthSchemeProvider> authSchemeRegistry = RegistryBuilder.<AuthSchemeProvider> create()
                    .register(AuthSchemes.SPNEGO, nsf).register(AuthSchemes.NTLM, new NTLMSchemeFactory()).build();

            hcb.setDefaultAuthSchemeRegistry(authSchemeRegistry);
        }

        hcb.setDefaultCredentialsProvider(credsProvider);
        hcb.setDefaultSocketConfig(SocketConfig.custom().setSoTimeout(10 * 1000).build());
        final CloseableHttpClient httpClient = hcb.build();
        return httpClient;
    }

    protected void waitForGreenClusterState() throws IOException {
        waitForCluster(ClusterHealthStatus.GREEN, TimeValue.timeValueSeconds(30));
    }

    protected void waitForCluster(final ClusterHealthStatus status, final TimeValue timeout) throws IOException {
        try {
            log.debug("waiting for cluster state {}", status.name());
            final ClusterHealthResponse healthResponse = client.admin().cluster().prepareHealth().setWaitForStatus(status)
                    .setWaitForNodes(">2").setTimeout(timeout).execute().actionGet();
            if (healthResponse.isTimedOut()) {
                throw new IOException("cluster state is " + healthResponse.getStatus().name() + " and not " + status.name()
                        + ", cowardly refusing to continue with operations");
            } else {
                log.debug("... cluster state ok");
            }
        } catch (final ElasticsearchTimeoutException e) {
            throw new IOException("timeout, cluster does not respond to health request, cowardly refusing to continue with operations");
        }
    }

    private static class JaasCredentials implements Credentials {

        @Override
        public String getPassword() {
            return null;
        }

        @Override
        public Principal getUserPrincipal() {
            return null;
        }
    }

    protected Client client() {
        return client;
    }

    private Path getAbsoluteFilePathFromClassPath(final String fileNameFromClasspath) {
        Path path = null;
        final URL fileUrl = PropertyUtil.class.getClassLoader().getResource(fileNameFromClasspath);
        if (fileUrl != null) {
            try {
                path = Paths.get(fileUrl.toURI());
                if (!Files.isReadable(path) && !Files.isDirectory(path)) {
                    log.error("Cannot read from {}, file does not exist or is not readable", path.toString());
                    return null;
                }

                if (!path.isAbsolute()) {
                    log.warn("{} is not absolute", path.toString());
                }
                return path;
            } catch (final URISyntaxException e) {
                //ignore
            }
        } else {
            log.error("Failed to load " + fileNameFromClasspath);
        }
        return null;
    }
}
