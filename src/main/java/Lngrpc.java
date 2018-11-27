 
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
import lnrpc.Rpc.*;
import lnrpc.Rpc.*;
import java.util.List;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.concurrent.Executor;
import lnrpc.Rpc.NewAddressRequest.AddressType;

import lnrpc.Rpc.PendingChannelsResponse.ClosedChannel;
import lnrpc.Rpc.PendingChannelsResponse.ForceClosedChannel;
import lnrpc.Rpc.PendingChannelsResponse.PendingChannel;
import lnrpc.Rpc.PendingChannelsResponse.PendingOpenChannel;
import lnrpc.Rpc.PendingChannelsResponse.WaitingCloseChannel;
import org.json.JSONObject;
import org.json.JSONArray;

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

private static LightningBlockingStub stub;


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




                stub = LightningGrpc
                       .newBlockingStub( channel)
                       .withCallCredentials(new MacaroonCallCredential(macaroon));
                try{
                        JSONObject json = new JSONObject();
                        json.put("error",false);
                        json.put("response","connected");


                        return json.toString();
                }
                catch(Exception e) {
                        return "";
                }
        }
        catch(Exception e) {
                try{
                        JSONObject json = new JSONObject();
                        json.put("error",true);
                        json.put("response",e.toString());

                        return json.toString();
                }
                catch(Exception e2) {
                        return "";
                }
        }

}

public static String GetInfo() throws IOException {


        try{



                GetInfoResponse response = stub.getInfo(GetInfoRequest.getDefaultInstance());
/*
                identity_pubkey: "0330b017d3d894f93d7b989c1d8d23e1b4a1c7da90ddd5e7aa68df2db410db808c"
   [INFO]  alias: "0330b017d3d894f93d7b"
   [INFO]  num_active_channels: 2
   [INFO]  num_peers: 5
   [INFO]  block_height: 1444076
   [INFO]  block_hash: "000000000000012fb41f96cd65d591d1830fb074b469fb4909e11d36b5a7b5d1"
   [INFO]  synced_to_chain: true
   [INFO]  testnet: true
   [INFO]  chains: "bitcoin"
   [INFO]  uris: "0330b017d3d894f93d7b989c1d8d23e1b4a1c7da90ddd5e7aa68df2db410db808c@35.189.149.73:9735"
   [INFO]  best_header_timestamp: 1542625205
   [INFO]  version: "0.5.0-beta commit=c5241dbb367daf54138e9e745c7a31efcb6a2edd"


 */

                JSONObject resJson = new JSONObject();
                resJson.put("identity_pubkey",response.getIdentityPubkey());
                resJson.put("num_active_channels",response.getNumActiveChannels());


                JSONObject json = new JSONObject();
                json.put("error",false);
                json.put("response",resJson);

                return json.toString();
        }
        catch(Exception e) {
                try{
                        JSONObject json = new JSONObject();
                        json.put("error",true);
                        json.put("response",e.toString());

                        return json.toString();
                }
                catch(Exception e2) {
                        return "";
                }
        }

}

public static String GetWalletBalance() throws IOException {

        try{
                WalletBalanceResponse response = stub.walletBalance(WalletBalanceRequest.getDefaultInstance());

                JSONObject resJson = new JSONObject();
                resJson.put("total_balance",response.getTotalBalance());
                resJson.put("confirmed_balance",response.getConfirmedBalance());
                resJson.put("unconfirmed_balance",response.getUnconfirmedBalance());


                JSONObject json = new JSONObject();
                json.put("error",false);
                json.put("response",resJson);

                return json.toString();
        }
        catch(Exception e) {
                try{
                        JSONObject json = new JSONObject();
                        json.put("error",true);
                        json.put("response",e.toString());

                        return json.toString();
                }
                catch(Exception e2) {
                        return "";
                }
        }

}



public static String GetChannelBalance() throws IOException {

        try{
                ChannelBalanceResponse response = stub.channelBalance(ChannelBalanceRequest.getDefaultInstance());

                JSONObject resJson = new JSONObject();
                resJson.put("balance",response.getBalance());
                resJson.put("pending_open_balance",response.getPendingOpenBalance());

                JSONObject json = new JSONObject();
                json.put("error",false);
                json.put("response",resJson);

                return json.toString();
        }
        catch(Exception e) {
                try{
                        JSONObject json = new JSONObject();
                        json.put("error",true);
                        json.put("response",e.toString());

                        return json.toString();
                }
                catch(Exception e2) {
                        return "";
                }
        }

}

public static String ListPayments() throws IOException {

        try{
                ListPaymentsResponse response = stub.listPayments(ListPaymentsRequest.getDefaultInstance());

                JSONArray resJson = new JSONArray();

                List<Payment> payments = response.getPaymentsList();

                for(int i = 0; i<payments.size(); i++) {
                        Payment aPayment = payments.get(i);
                        JSONObject aPaymentJSON = new JSONObject();
                        aPaymentJSON.put("payment_hash",aPayment.getPaymentHash());
                        aPaymentJSON.put("value",aPayment.getValueSat());
                        aPaymentJSON.put("creation_date",aPayment.getCreationDate());
                        aPaymentJSON.put("payment_preimage",aPayment.getPaymentPreimage());
                        aPaymentJSON.put("value_sat",aPayment.getValueSat());
                        resJson.put(aPaymentJSON);

                }
                
                System.out.println(resJson);
                JSONObject json = new JSONObject();
                json.put("error",false);
                json.put("response",resJson);

                return json.toString();
        }
        catch(Exception e) {
                try{
                        JSONObject json = new JSONObject();
                        json.put("error",true);
                        json.put("response",e.toString());

                        return json.toString();
                }
                catch(Exception e2) {
                        return "";
                }
        }

}

public static String ListChannels() throws IOException {
  /*channels {
[INFO]  active: true
[INFO]  remote_pubkey: "03adf1a17ab83438f23bc6c3b87ed8664757923988d5907c469840ddba1a7d1415"
[INFO]  channel_point: "73235a2edfa9e43a09355f03c6f632eb4ee1129bb3eb4828d5745f6fa1db6af0:1"
[INFO]  chan_id: 1587538659859365889
[INFO]  capacity: 8000000
[INFO]  remote_balance: 7999817
[INFO]  commit_fee: 183
[INFO]  commit_weight: 552
[INFO]  fee_per_kw: 253
[INFO]  csv_delay: 961
[INFO]  }*/

        try{
                ListChannelsResponse response = stub.listChannels(ListChannelsRequest.getDefaultInstance());

                JSONArray resJson = new JSONArray();

                List<Channel> channels = response.getChannelsList();

                for(int i = 0; i<channels.size(); i++) {
                        Channel aChannel = channels.get(i);
                         
                        JSONObject aChannelJSON = new JSONObject();
                        aChannelJSON.put("active",aChannel.getActive());
                        aChannelJSON.put("remote_pubkey",aChannel.getRemotePubkey());
                        aChannelJSON.put("channel_point",aChannel.getChannelPoint());
                        aChannelJSON.put("chan_id",aChannel.getChanId());
                        aChannelJSON.put("capacity",aChannel.getCapacity());
                        
                        aChannelJSON.put("local_balance",aChannel.getLocalBalance());
                        aChannelJSON.put("remote_balance",aChannel.getRemoteBalance());
                        
                        resJson.put(aChannelJSON);

                }

               
                JSONObject json = new JSONObject();
                json.put("error",false);
                json.put("response",resJson);

                return json.toString();
        }
        catch(Exception e) {
                try{
                        JSONObject json = new JSONObject();
                        json.put("error",true);
                        json.put("response",e.toString());

                        return json.toString();
                }
                catch(Exception e2) {
                        return "";
                }
        }

}

static JSONObject getPendingChannelJSON(PendingChannel pendingChannel){
    
     try{
     JSONObject pendingChannelJSON = new JSONObject();
     
     /*remote_node_pub	string	
channel_point	string	
capacity	int64	
local_balance	int64	
remote_balance	*/
                        pendingChannelJSON.put("remote_node_pub",pendingChannel.getRemoteNodePub());
                        pendingChannelJSON.put("channel_point",pendingChannel.getChannelPoint());
                        pendingChannelJSON.put("capacity",pendingChannel.getCapacity());
                         pendingChannelJSON.put("local_balance",pendingChannel.getLocalBalance());
                           pendingChannelJSON.put("remote_balance",pendingChannel.getRemoteBalance());
                         
                       return pendingChannelJSON;
                        }
        catch(Exception e) {
            
            return null;
        }
}

public static String PendingChannels() throws IOException {

        try{
                PendingChannelsResponse response = stub.pendingChannels(PendingChannelsRequest.getDefaultInstance());
                JSONObject resJSON = new JSONObject();
                resJSON.put("total_limbo_balance",response.getTotalLimboBalance());
                JSONArray pendingOpenChannelsArray = new JSONArray();

                List<PendingOpenChannel> pendingOpenChannels = response.getPendingOpenChannelsList();
         
                for(int i = 0; i<pendingOpenChannels.size(); i++) {
                        PendingOpenChannel aPendingOpenChannels = pendingOpenChannels.get(i);
                        JSONObject aPendingOpenChannelJSON = new JSONObject();
                        aPendingOpenChannelJSON.put("channel",getPendingChannelJSON(aPendingOpenChannels.getChannel()));
                        aPendingOpenChannelJSON.put("confirmation_height",aPendingOpenChannels.getConfirmationHeight());
                        aPendingOpenChannelJSON.put("commit_fee",aPendingOpenChannels.getCommitFee());
                        aPendingOpenChannelJSON.put("commit_weight",aPendingOpenChannels.getCommitWeight());
                        aPendingOpenChannelJSON.put("fee_per_kw",aPendingOpenChannels.getFeePerKw());
                        
                        pendingOpenChannelsArray.put(aPendingOpenChannelJSON);

                }
                
                resJSON.put("pending_open_channels",pendingOpenChannelsArray);
                
                
                
                
                
                
                
                JSONArray pendingClosingChannelsArray = new JSONArray();

                List<ClosedChannel> pendingClosingChannels = response.getPendingClosingChannelsList();
         
                for(int i = 0; i<pendingClosingChannels.size(); i++) {
                        ClosedChannel aClosedChannel = pendingClosingChannels.get(i);
                        JSONObject aClosedChannelJSON = new JSONObject();
                        aClosedChannelJSON.put("channel",getPendingChannelJSON(aClosedChannel.getChannel()));
                        aClosedChannelJSON.put("closing_txid",aClosedChannel.getClosingTxid());
                        pendingClosingChannelsArray.put(aClosedChannelJSON);

                }
                
                resJSON.put("pending_closing_channels",pendingClosingChannelsArray);
               
                
                JSONArray pendingForceClosingChannelsArray = new JSONArray();

                List<ForceClosedChannel> pendingForceClosingChannels = response.getPendingForceClosingChannelsList();
         
                for(int i = 0; i<pendingForceClosingChannels.size(); i++) {
                        ForceClosedChannel aForceClosedChannel = pendingForceClosingChannels.get(i);
                        JSONObject aForceClosedChannelJSON = new JSONObject();
                        aForceClosedChannelJSON.put("channel",getPendingChannelJSON(aForceClosedChannel.getChannel()));
                        aForceClosedChannelJSON.put("closing_txid",aForceClosedChannel.getClosingTxid());
                        aForceClosedChannelJSON.put("limbo_balance",aForceClosedChannel.getLimboBalance());
                        aForceClosedChannelJSON.put("maturity_height",aForceClosedChannel.getMaturityHeight());
                        aForceClosedChannelJSON.put("blocks_til_maturity",aForceClosedChannel.getBlocksTilMaturity());
                        aForceClosedChannelJSON.put("recovered_balance",aForceClosedChannel.getRecoveredBalance());
                        pendingForceClosingChannelsArray.put(aForceClosedChannelJSON);

                }
                
                resJSON.put("pending_force_closing_channels",pendingForceClosingChannelsArray);
               
                
                
                
                JSONArray waitingCloseChannelsArray = new JSONArray();

                List<WaitingCloseChannel> waitingCloseChannels = response.getWaitingCloseChannelsList();
         
                for(int i = 0; i<waitingCloseChannels.size(); i++) {
                        WaitingCloseChannel aWaitingCloseChannel = waitingCloseChannels.get(i);
                        JSONObject aWaitingCloseChannelJSON = new JSONObject();
                        aWaitingCloseChannelJSON .put("channel",getPendingChannelJSON(aWaitingCloseChannel.getChannel()));
                        aWaitingCloseChannelJSON .put("limbo_balance",aWaitingCloseChannel.getLimboBalance());
                         
                        
                        waitingCloseChannelsArray.put(aWaitingCloseChannelJSON);

                }
                
                resJSON.put("waiting_close_channels", waitingCloseChannelsArray);
               
                
                
                

                JSONObject json = new JSONObject();
                json.put("error",false);
                json.put("response",resJSON);

                return json.toString();
        }
        catch(Exception e) {
                try{
                        JSONObject json = new JSONObject();
                        json.put("error",true);
                        json.put("response",e.toString());

                        return json.toString();
                }
                catch(Exception e2) {
                        return "";
                }
        }

}


public static String NewAddress(String type) throws IOException {

        try{

                AddressType addressType = AddressType.WITNESS_PUBKEY_HASH;
                if("np2wkh".equals(type)) {
                        addressType = AddressType.NESTED_PUBKEY_HASH;
                }

                
                NewAddressRequest.Builder req = NewAddressRequest.newBuilder().setType(addressType);
                
                NewAddressResponse response = stub.newAddress(req.build());

                  JSONObject resJson = new JSONObject();
                   resJson.put("address",response.getAddress());
                 


                JSONObject json = new JSONObject();
                json.put("error",false);
                json.put("response",resJson);

                return json.toString();
        }
        catch(Exception e) {
                try{
                        JSONObject json = new JSONObject();
                        json.put("error",true);
                        json.put("response",e.toString());

                        return json.toString();
                }
                catch(Exception e2) {
                        return "";
                }
        }

}


public static String DecodePayReq(String pay_req) throws IOException {

        try{
              PayReqString payReqReq = PayReqString.newBuilder().setPayReq(pay_req).build();
                PayReq response =  stub.decodePayReq(payReqReq);

                  JSONObject resJson = new JSONObject();
                   resJson.put("destination",response.getDestination());
                   resJson.put("payment_hash",response.getPaymentHash());
                   resJson.put("num_satoshis",response.getNumSatoshis());
                   resJson.put("timestamp",response.getTimestamp());
                   resJson.put("expiry",response.getExpiry());
                   resJson.put("description",response.getDescription());
                   resJson.put("description_hash",response.getDescriptionHash());
                   resJson.put("fallback_addr",response.getFallbackAddr());
                   resJson.put("cltv_expiry",response.getCltvExpiry());
                 
 

                JSONObject json = new JSONObject();
                json.put("error",false);
                json.put("response",resJson);

                return json.toString();
        }
        catch(Exception e) {
                try{
                        JSONObject json = new JSONObject();
                        json.put("error",true);
                        json.put("response",e.toString());

                        return json.toString();
                }
                catch(Exception e2) {
                        return "";
                }
        }
        

}





}
