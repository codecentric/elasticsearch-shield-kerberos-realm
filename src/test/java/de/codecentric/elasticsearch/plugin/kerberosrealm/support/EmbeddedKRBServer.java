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
package de.codecentric.elasticsearch.plugin.kerberosrealm.support;

import java.io.File;

import org.apache.commons.io.FileUtils;
import org.apache.kerby.kerberos.kdc.impl.NettyKdcServerImpl;
import org.apache.kerby.kerberos.kerb.server.SimpleKdcServer;
import org.apache.kerby.kerberos.kerb.spec.ticket.TgtTicket;
import org.apache.kerby.util.NetworkUtil;
import org.elasticsearch.common.SuppressForbidden;

@SuppressForbidden(reason = "unit test")
public class EmbeddedKRBServer {

    private SimpleKdcServer simpleKdcServer;
    private String realm = "CCK.COM";

    public void start(final File workDir) throws Exception {
        simpleKdcServer = new SimpleKdcServer();
        simpleKdcServer.enableDebug();
        simpleKdcServer.setKdcTcpPort(NetworkUtil.getServerPort());
        simpleKdcServer.setKdcUdpPort(NetworkUtil.getServerPort());
        simpleKdcServer.setAllowTcp(true);
        simpleKdcServer.setAllowUdp(true);
        simpleKdcServer.setKdcRealm(realm);
        simpleKdcServer.setKdcHost("localhost");
        FileUtils.forceMkdir(workDir);
        simpleKdcServer.setWorkDir(workDir);
        simpleKdcServer.setInnerKdcImpl(new NettyKdcServerImpl(simpleKdcServer.getKdcSetting()));
        simpleKdcServer.init();
        //System.setErr(new PrintStream(new NullOutputStream()));
        simpleKdcServer.start();
    }

    public SimpleKdcServer getSimpleKdcServer() {
        return simpleKdcServer;
    }

    public static void main(final String[] args) throws Exception {
        final File workDir = new File(".");
        final EmbeddedKRBServer eks = new EmbeddedKRBServer();
        eks.realm = "DUMMY.COM";
        eks.start(workDir);
        eks.getSimpleKdcServer().createPrincipal("kirk/admin@DUMMY.COM", "kirkpwd");
        eks.getSimpleKdcServer().createPrincipal("uhura@DUMMY.COM", "uhurapwd");
        eks.getSimpleKdcServer().createPrincipal("service/1@DUMMY.COM", "service1pwd");
        eks.getSimpleKdcServer().createPrincipal("service/2@DUMMY.COM", "service2pwd");
        eks.getSimpleKdcServer().exportPrincipal("service/1@DUMMY.COM", new File(workDir, "service1.keytab")); //server, acceptor
        eks.getSimpleKdcServer().exportPrincipal("service/2@DUMMY.COM", new File(workDir, "service2.keytab")); //server, acceptor

        eks.getSimpleKdcServer().createPrincipal("HTTP/localhost@DUMMY.COM", "httplocpwd");
        eks.getSimpleKdcServer().exportPrincipal("HTTP/localhost@DUMMY.COM", new File(workDir, "httploc.keytab")); //server, acceptor

        eks.getSimpleKdcServer().createPrincipal("HTTP/localhost@DUMMY.COM", "httpcpwd");
        eks.getSimpleKdcServer().exportPrincipal("HTTP/localhost@DUMMY.COM",
                new File(workDir, "http.keytab")); //server, acceptor

        final TgtTicket tgt = eks.getSimpleKdcServer().getKrbClient().requestTgtWithPassword("kirk/admin@DUMMY.COM", "kirkpwd");
        eks.getSimpleKdcServer().getKrbClient().storeTicket(tgt, new File(workDir, "kirk.cc"));

        try {
            try {
                FileUtils.copyFile(new File("/etc/krb5.conf"), new File("/etc/krb5.conf.bak"));
            } catch (final Exception e) {
                //ignore
            }
            FileUtils.copyFileToDirectory(new File(workDir, "krb5.conf"), new File("/etc/"));
            System.out.println("Generated krb5.conf copied to /etc");
        } catch (final Exception e) {
            System.out.println("Unable to copy generated krb5.conf to /etc diúe to " + e.getMessage());
        }
    }
}