package de.codecentric.elasticsearch.plugin.kerberosrealm.realm;

import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;

public class TrustAllX509TrustManager implements X509TrustManager {
     public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }

        public void checkClientTrusted(java.security.cert.X509Certificate[] certs,
                String authType) {
        }

        public void checkServerTrusted(java.security.cert.X509Certificate[] certs,
                String authType) {
        }

}

