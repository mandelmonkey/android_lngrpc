import io.grpc.Attributes;
import io.grpc.CallCredentials;
import io.grpc.ManagedChannel;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import io.grpc.Status;
import io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.NettyChannelBuilder;
import io.grpc.testing.TestUtils;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.KeyStore;
import javax.security.auth.x500.X500Principal;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

import io.grpc.okhttp.OkHttpChannelBuilder;

import com.squareup.okhttp.ConnectionSpec;
import com.squareup.okhttp.TlsVersion;


import io.grpc.internal.GrpcUtil;
import io.grpc.okhttp.internal.CipherSuite;

import io.grpc.okhttp.NegotiationType;
import io.grpc.okhttp.OkHttpChannelBuilder;
import lnrpc.LightningGrpc;
import lnrpc.LightningGrpc.LightningBlockingStub;
import lnrpc.Rpc.GetInfoRequest;
import lnrpc.Rpc.GetInfoResponse;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.concurrent.Executor;


public class Lngrpc {

static class MacaroonCallCredential implements CallCredentials {
private final String macaroon;

MacaroonCallCredential(String macaroon) {
        this.macaroon = macaroon;
}

public void thisUsesUnstableApi() {
}

public void applyRequestMetadata(
        MethodDescriptor < ?, ? > methodDescriptor,
        Attributes attributes,
        Executor executor,
        final MetadataApplier metadataApplier
        ) {
        String authority = attributes.get(ATTR_AUTHORITY);
        System.out.println(authority);
        executor.execute(new Runnable() {
                                public void run() {
                                        try {
                                                Metadata headers = new Metadata();
                                                Metadata.Key < String > macaroonKey = Metadata.Key.of("macaroon", Metadata.ASCII_STRING_MARSHALLER);
                                                headers.put(macaroonKey, macaroon);
                                                metadataApplier.apply(headers);
                                        } catch (Throwable e) {
                                                metadataApplier.fail(Status.UNAUTHENTICATED.withCause(e));
                                        }
                                }
                        });
}
}




private static byte[] hexStringToByteArray(String s) {
        final int len = s.length();
        final byte[] data = new byte[len / 2];

        for (int i = 0; i < len; i += 2) {
                data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) +
                                      Character.digit(s.charAt(i + 1), 16));
        }

        return data;
}
private static X509Certificate convertToX509Cert(String certificateString) throws CertificateException {
        X509Certificate certificate = null;
        CertificateFactory cf = null;
        try {
                if (certificateString != null && !certificateString.trim().isEmpty()) {

                        byte[] certificateData = hexStringToByteArray(certificateString);
                        cf = CertificateFactory.getInstance("X509");
                        certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certificateData));
                }
        } catch (CertificateException e) {
                throw new CertificateException(e);
        }
        return certificate;
}

private static SSLSocketFactory newSslSocketFactoryForCa(String certificateString) throws Exception {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = convertToX509Cert(certificateString);

        X500Principal principal = cert.getSubjectX500Principal();
        ks.setCertificateEntry(principal.getName("RFC2253"), cert);

        TrustManagerFactory trustManagerFactory =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(ks);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, trustManagerFactory.getTrustManagers(), null);
        return context.getSocketFactory();
}


public Lngrpc(){

}


public static String Connect(String host,int port,String cert, String macaroon) throws IOException {


        try{

                OkHttpChannelBuilder builder = OkHttpChannelBuilder.forAddress(host, port)
                                               .connectionSpec(new ConnectionSpec.Builder(OkHttpChannelBuilder.DEFAULT_CONNECTION_SPEC)
                                                               .tlsVersions(ConnectionSpec.MODERN_TLS.tlsVersions().toArray(new TlsVersion[0]))
                                                               .build());


                if(cert != null) {
                        try {

                                builder.sslSocketFactory(newSslSocketFactoryForCa(cert));
                        } catch (Exception e) {

                                throw new RuntimeException(e);
                        }
                }
                ManagedChannel channel = builder.build();




                LightningBlockingStub stub = LightningGrpc
                                             .newBlockingStub( channel)
                                             .withCallCredentials(new MacaroonCallCredential(macaroon));

                GetInfoResponse response = stub.getInfo(GetInfoRequest.getDefaultInstance());

                return response.getIdentityPubkey();
        }
        catch(Exception e) {

                return e.toString();
        }

}



}
