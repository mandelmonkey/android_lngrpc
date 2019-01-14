 import android.os.Handler;
 import android.os.Looper;
import com.google.protobuf.ByteString;
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
 import java.util.Iterator;
 import java.util.concurrent.Executor;
 import lnrpc.Rpc.NewAddressRequest.AddressType;

 import lnrpc.Rpc.PendingChannelsResponse.ClosedChannel;
 import lnrpc.Rpc.PendingChannelsResponse.ForceClosedChannel;
 import lnrpc.Rpc.PendingChannelsResponse.PendingChannel;
 import lnrpc.Rpc.PendingChannelsResponse.PendingOpenChannel;
 import lnrpc.Rpc.PendingChannelsResponse.WaitingCloseChannel;
 import org.json.JSONObject;
 import org.json.JSONArray;

 //import java.lang.Object.android.os.Handler;



 public class Lngrpc {

  static class MacaroonCallCredential implements CallCredentials {
   private final String macaroon;

   MacaroonCallCredential(String macaroon) {
    this.macaroon = macaroon;
   }

   public void thisUsesUnstableApi() {}

   public void applyRequestMetadata(
    MethodDescriptor < ? , ? > methodDescriptor,
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
    data[i / 2] = (byte)((Character.digit(s.charAt(i), 16) << 4) +
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


  public Lngrpc() {

  }

  private static LightningBlockingStub stub;


  public static void Connect(final String host, final int port, final String cert, final String macaroon, final CallbackInterface callback) throws IOException {
   Thread thread = new Thread(new Runnable() {
    @Override
    public void run() {


     try {

      OkHttpChannelBuilder builder = OkHttpChannelBuilder.forAddress(host, port)
       .connectionSpec(new ConnectionSpec.Builder(OkHttpChannelBuilder.DEFAULT_CONNECTION_SPEC)
        .tlsVersions(ConnectionSpec.MODERN_TLS.tlsVersions().toArray(new TlsVersion[0]))
        .build());


      if (cert != null) {
       try {

        builder.sslSocketFactory(newSslSocketFactoryForCa(cert));
       } catch (Exception e) {

        throw new RuntimeException(e);
       }
      }
      ManagedChannel channel = builder.build();




      stub = LightningGrpc
       .newBlockingStub(channel)
       .withCallCredentials(new MacaroonCallCredential(macaroon));
      try {
       JSONObject json = new JSONObject();
       json.put("error", false);
       json.put("response", "connected");


       callback.eventFired(json.toString());
      } catch (Exception e) {
       callback.eventFired("");
      }
     } catch (Exception e) {
      try {
       JSONObject json = new JSONObject();
       json.put("error", true);
       json.put("response", e.toString());

       callback.eventFired(json.toString());
      } catch (Exception e2) {
       callback.eventFired("");
      }
     }

    } // This is your code
   });
   thread.start();

  }

  public static void GetInfo(final CallbackInterface callback) throws IOException {
   Thread thread = new Thread(new Runnable() {
    @Override
    public void run() {


     try {



      GetInfoResponse response = stub.getInfo(GetInfoRequest.getDefaultInstance());


      JSONObject resJson = new JSONObject();
      resJson.put("identity_pubkey", response.getIdentityPubkey());
      resJson.put("num_active_channels", response.getNumActiveChannels());


      JSONObject json = new JSONObject();
      json.put("error", false);
      json.put("response", resJson);

      callback.eventFired(json.toString());
     } catch (Exception e) {
      try {
       JSONObject json = new JSONObject();
       json.put("error", true);
       json.put("response", e.toString());

       callback.eventFired(json.toString());
      } catch (Exception e2) {
       callback.eventFired("");
      }
     }

    } // This is your code
   });
   thread.start();

  }

  public static void GetWalletBalance(final CallbackInterface callback) throws IOException {
   Thread thread = new Thread(new Runnable() {
    @Override
    public void run() {
     try {
      WalletBalanceResponse response = stub.walletBalance(WalletBalanceRequest.getDefaultInstance());

      JSONObject resJson = new JSONObject();
      resJson.put("total_balance", response.getTotalBalance());
      resJson.put("confirmed_balance", response.getConfirmedBalance());
      resJson.put("unconfirmed_balance", response.getUnconfirmedBalance());


      JSONObject json = new JSONObject();
      json.put("error", false);
      json.put("response", resJson);

      callback.eventFired(json.toString());
     } catch (Exception e) {
      try {
       JSONObject json = new JSONObject();
       json.put("error", true);
       json.put("response", e.toString());

       callback.eventFired(json.toString());
      } catch (Exception e2) {
       callback.eventFired("");
      }
     }

    } // This is your code
   });
   thread.start();

  }



  public static void GetChannelBalance(final CallbackInterface callback) throws IOException {
   Thread thread = new Thread(new Runnable() {
    @Override
    public void run() {

     try {
      ChannelBalanceResponse response = stub.channelBalance(ChannelBalanceRequest.getDefaultInstance());

      JSONObject resJson = new JSONObject();
      resJson.put("balance", response.getBalance());
      resJson.put("pending_open_balance", response.getPendingOpenBalance());

      JSONObject json = new JSONObject();
      json.put("error", false);
      json.put("response", resJson);

      callback.eventFired(json.toString());
     } catch (Exception e) {
      try {
       JSONObject json = new JSONObject();
       json.put("error", true);
       json.put("response", e.toString());

       callback.eventFired(json.toString());
      } catch (Exception e2) {
       callback.eventFired("");
      }
     }

    } // This is your code
   });
   thread.start();

  }

  public static void ListPayments(final CallbackInterface callback) throws IOException {
   Thread thread = new Thread(new Runnable() {
    @Override
    public void run() {

     try {
      ListPaymentsResponse response = stub.listPayments(ListPaymentsRequest.getDefaultInstance());

      JSONArray resJson = new JSONArray();

      List < Payment > payments = response.getPaymentsList();

      for (int i = 0; i < payments.size(); i++) {
       Payment aPayment = payments.get(i);
       JSONObject aPaymentJSON = new JSONObject();
       aPaymentJSON.put("payment_hash", aPayment.getPaymentHash());
       aPaymentJSON.put("value", aPayment.getValueSat());
       aPaymentJSON.put("creation_date", aPayment.getCreationDate());
       aPaymentJSON.put("payment_preimage", aPayment.getPaymentPreimage());
       aPaymentJSON.put("value_sat", aPayment.getValueSat());
       resJson.put(aPaymentJSON);

      }

      //System.out.println(resJson);
      JSONObject json = new JSONObject();
      json.put("error", false);
      json.put("response", resJson);

      callback.eventFired(json.toString());
     } catch (Exception e) {
      try {
       JSONObject json = new JSONObject();
       json.put("error", true);
       json.put("response", e.toString());

       callback.eventFired(json.toString());
      } catch (Exception e2) {
       callback.eventFired("");
      }
     }

    } // This is your code
   });
   thread.start();

  }
  public static void ListInvoices(final CallbackInterface callback) throws IOException {
   Thread thread = new Thread(new Runnable() {
    @Override
    public void run() {

     try {

      ListInvoiceResponse response = stub.listInvoices(ListInvoiceRequest.getDefaultInstance());

      JSONArray resJson = new JSONArray();

      List < Invoice > invoices = response.getInvoicesList();

      for (int i = 0; i < invoices.size(); i++) {
       Invoice anInvoice = invoices.get(i);
       JSONObject anInvoiceJSON = new JSONObject();
       anInvoiceJSON.put("creation_date", anInvoice.getCreationDate());
       anInvoiceJSON.put("memo", anInvoice.getMemo()); //deprecated check api lnd
       anInvoiceJSON.put("amt_paid", anInvoice.getAmtPaid()); //deprecated check api lnd

       resJson.put(anInvoiceJSON);

      }

      //System.out.println(resJson);
      JSONObject json = new JSONObject();
      json.put("error", false);
      json.put("response", resJson);

      callback.eventFired(json.toString());
     } catch (Exception e) {
      try {
       JSONObject json = new JSONObject();
       json.put("error", true);
       json.put("response", e.toString());

       callback.eventFired(json.toString());
      } catch (Exception e2) {
       callback.eventFired("");
      }
     }
    } // This is your code
   });
   thread.start();

  }
  public static void ListChannels(final CallbackInterface callback) throws IOException {


   Thread thread = new Thread(new Runnable() {
    @Override
    public void run() {

     try {
      ListChannelsResponse response = stub.listChannels(ListChannelsRequest.getDefaultInstance());

      JSONArray resJson = new JSONArray();

      List < Channel > channels = response.getChannelsList();

      for (int i = 0; i < channels.size(); i++) {
       Channel aChannel = channels.get(i);

       JSONObject aChannelJSON = new JSONObject();
       aChannelJSON.put("active", aChannel.getActive());
       aChannelJSON.put("remote_pubkey", aChannel.getRemotePubkey());
       aChannelJSON.put("channel_point", aChannel.getChannelPoint());
       aChannelJSON.put("chan_id", aChannel.getChanId());
       aChannelJSON.put("capacity", aChannel.getCapacity());

       aChannelJSON.put("local_balance", aChannel.getLocalBalance());
       aChannelJSON.put("remote_balance", aChannel.getRemoteBalance());

       resJson.put(aChannelJSON);

      }


      JSONObject json = new JSONObject();
      json.put("error", false);
      json.put("response", resJson);

      callback.eventFired(json.toString());
     } catch (Exception e) {
      try {
       JSONObject json = new JSONObject();
       json.put("error", true);
       json.put("response", e.toString());

       callback.eventFired(json.toString());
      } catch (Exception e2) {

      }
     }
    } // This is your code
   });
   thread.start();

  }

  static JSONObject getPendingChannelJSON(PendingChannel pendingChannel) {

   try {
    JSONObject pendingChannelJSON = new JSONObject();

    /*remote_node_pub	string	
channel_point	string	
capacity	int64	
local_balance	int64	
remote_balance	*/
    pendingChannelJSON.put("remote_node_pub", pendingChannel.getRemoteNodePub());
    pendingChannelJSON.put("channel_point", pendingChannel.getChannelPoint());
    pendingChannelJSON.put("capacity", pendingChannel.getCapacity());
    pendingChannelJSON.put("local_balance", pendingChannel.getLocalBalance());
    pendingChannelJSON.put("remote_balance", pendingChannel.getRemoteBalance());

    return pendingChannelJSON;
   } catch (Exception e) {

    return null;
   }
  }

  public static void PendingChannels(final CallbackInterface callback) throws IOException {
   Thread thread = new Thread(new Runnable() {
    @Override
    public void run() {
     try {

      PendingChannelsResponse response = stub.pendingChannels(PendingChannelsRequest.getDefaultInstance());
      System.out.println("pending list");
      System.out.println(response.toString());
      JSONObject resJSON = new JSONObject();
      resJSON.put("total_limbo_balance", response.getTotalLimboBalance());
      JSONArray pendingOpenChannelsArray = new JSONArray();

      List < PendingOpenChannel > pendingOpenChannels = response.getPendingOpenChannelsList();

      for (int i = 0; i < pendingOpenChannels.size(); i++) {
       PendingOpenChannel aPendingOpenChannels = pendingOpenChannels.get(i);
       JSONObject aPendingOpenChannelJSON = new JSONObject();
       aPendingOpenChannelJSON.put("channel", getPendingChannelJSON(aPendingOpenChannels.getChannel()));
       aPendingOpenChannelJSON.put("confirmation_height", aPendingOpenChannels.getConfirmationHeight());
       aPendingOpenChannelJSON.put("commit_fee", aPendingOpenChannels.getCommitFee());
       aPendingOpenChannelJSON.put("commit_weight", aPendingOpenChannels.getCommitWeight());
       aPendingOpenChannelJSON.put("fee_per_kw", aPendingOpenChannels.getFeePerKw());

       pendingOpenChannelsArray.put(aPendingOpenChannelJSON);

      }

      resJSON.put("pending_open_channels", pendingOpenChannelsArray);







      JSONArray pendingClosingChannelsArray = new JSONArray();

      List < ClosedChannel > pendingClosingChannels = response.getPendingClosingChannelsList();

      System.out.println("pending size");
      System.out.println(pendingClosingChannels.size());
      for (int i = 0; i < pendingClosingChannels.size(); i++) {

       ClosedChannel aClosedChannel = pendingClosingChannels.get(i);
       System.out.println(aClosedChannel.toString());
       JSONObject aClosedChannelJSON = new JSONObject();
       aClosedChannelJSON.put("channel", getPendingChannelJSON(aClosedChannel.getChannel()));
       aClosedChannelJSON.put("closing_txid", aClosedChannel.getClosingTxid());
       pendingClosingChannelsArray.put(aClosedChannelJSON);

      }

      resJSON.put("pending_closing_channels", pendingClosingChannelsArray);


      JSONArray pendingForceClosingChannelsArray = new JSONArray();

      List < ForceClosedChannel > pendingForceClosingChannels = response.getPendingForceClosingChannelsList();

      for (int i = 0; i < pendingForceClosingChannels.size(); i++) {
       ForceClosedChannel aForceClosedChannel = pendingForceClosingChannels.get(i);
       JSONObject aForceClosedChannelJSON = new JSONObject();
       aForceClosedChannelJSON.put("channel", getPendingChannelJSON(aForceClosedChannel.getChannel()));
       aForceClosedChannelJSON.put("closing_txid", aForceClosedChannel.getClosingTxid());
       aForceClosedChannelJSON.put("limbo_balance", aForceClosedChannel.getLimboBalance());
       aForceClosedChannelJSON.put("maturity_height", aForceClosedChannel.getMaturityHeight());
       aForceClosedChannelJSON.put("blocks_til_maturity", aForceClosedChannel.getBlocksTilMaturity());
       aForceClosedChannelJSON.put("recovered_balance", aForceClosedChannel.getRecoveredBalance());
       pendingForceClosingChannelsArray.put(aForceClosedChannelJSON);

      }

      resJSON.put("pending_force_closing_channels", pendingForceClosingChannelsArray);




      JSONArray waitingCloseChannelsArray = new JSONArray();

      List < WaitingCloseChannel > waitingCloseChannels = response.getWaitingCloseChannelsList();

      for (int i = 0; i < waitingCloseChannels.size(); i++) {
       WaitingCloseChannel aWaitingCloseChannel = waitingCloseChannels.get(i);
       JSONObject aWaitingCloseChannelJSON = new JSONObject();
       aWaitingCloseChannelJSON.put("channel", getPendingChannelJSON(aWaitingCloseChannel.getChannel()));
       aWaitingCloseChannelJSON.put("limbo_balance", aWaitingCloseChannel.getLimboBalance());


       waitingCloseChannelsArray.put(aWaitingCloseChannelJSON);

      }

      resJSON.put("waiting_close_channels", waitingCloseChannelsArray);





      JSONObject json = new JSONObject();
      json.put("error", false);
      json.put("response", resJSON);
      //json.put("verbose",response.toString());

      callback.eventFired(json.toString());
     } catch (Exception e) {
      try {
       JSONObject json = new JSONObject();
       json.put("error", true);
       json.put("response", e.toString());

       callback.eventFired(json.toString());
      } catch (Exception e2) {
       callback.eventFired("");
      }
     }

    } // This is your code
   });
   thread.start();

  }


  public static void NewAddress(final String type, final CallbackInterface callback) throws IOException {
   Thread thread = new Thread(new Runnable() {
    @Override
    public void run() {
     try {

      AddressType addressType = AddressType.WITNESS_PUBKEY_HASH;
      if ("np2wkh".equals(type)) {
       addressType = AddressType.NESTED_PUBKEY_HASH;
      }


      NewAddressRequest.Builder req = NewAddressRequest.newBuilder().setType(addressType);

      NewAddressResponse response = stub.newAddress(req.build());

      JSONObject resJson = new JSONObject();
      resJson.put("address", response.getAddress());



      JSONObject json = new JSONObject();
      json.put("error", false);
      json.put("response", resJson);

      callback.eventFired(json.toString());
     } catch (Exception e) {
      try {
       JSONObject json = new JSONObject();
       json.put("error", true);
       json.put("response", e.toString());

       callback.eventFired(json.toString());
      } catch (Exception e2) {
       callback.eventFired("");
      }
     }

    } // This is your code
   });
   thread.start();

  }


  public static void DecodePayReq(final String pay_req, final CallbackInterface callback) throws IOException {
   Thread thread = new Thread(new Runnable() {
    @Override
    public void run() {

     try {
      PayReqString payReqReq = PayReqString.newBuilder().setPayReq(pay_req).build();
      PayReq response = stub.decodePayReq(payReqReq);

      JSONObject resJson = new JSONObject();
      resJson.put("destination", response.getDestination());
      resJson.put("payment_hash", response.getPaymentHash());
      resJson.put("num_satoshis", response.getNumSatoshis());
      resJson.put("timestamp", response.getTimestamp());
      resJson.put("expiry", response.getExpiry());
      resJson.put("description", response.getDescription());
      resJson.put("description_hash", response.getDescriptionHash());
      resJson.put("fallback_addr", response.getFallbackAddr());
      resJson.put("cltv_expiry", response.getCltvExpiry());



      JSONObject json = new JSONObject();
      json.put("error", false);
      json.put("response", resJson);

      callback.eventFired(json.toString());
     } catch (Exception e) {
      try {
       JSONObject json = new JSONObject();
       json.put("error", true);
       json.put("response", e.toString());

       callback.eventFired(json.toString());
      } catch (Exception e2) {
       callback.eventFired("");
      }
     }

    } // This is your code
   });
   thread.start();


  }


  public static void SendPayment(final String pay_req, final CallbackInterface callback) throws IOException {
   Thread thread = new Thread(new Runnable() {
    @Override
    public void run() {

     try {
      SendRequest sendReq = SendRequest.newBuilder().setPaymentRequest(pay_req).build();

      SendResponse response = stub.sendPaymentSync(sendReq);

      /*
                payment_error	string	
payment_preimage	bytes	
payment_route	Route	
                */
      JSONObject resJson = new JSONObject();
      resJson.put("payment_error", response.getPaymentError());
      resJson.put("payment_preimage", bytesToHex(response.getPaymentPreimage().toByteArray()));
      resJson.put("payment_route", response.getPaymentRoute().toString());


      JSONObject json = new JSONObject();
      json.put("error", false);
      json.put("response", resJson);

      callback.eventFired(json.toString());
     } catch (Exception e) {
      try {
       JSONObject json = new JSONObject();
       json.put("error", true);
       json.put("response", e.toString());

       callback.eventFired(json.toString());
      } catch (Exception e2) {
       callback.eventFired("");
      }
     }

    } // This is your code
   });
   thread.start();


  }

  public static void SendCoins(final long amount, final String address, final long fee, final CallbackInterface callback) throws IOException {
   Thread thread = new Thread(new Runnable() {
    @Override
    public void run() {

     try {
      SendCoinsRequest.Builder sendReqBuilder = SendCoinsRequest.newBuilder();
      sendReqBuilder.setAddr(address);
      sendReqBuilder.setAmount(amount);
      sendReqBuilder.setSatPerByte(fee);

      SendCoinsResponse response = stub.sendCoins(sendReqBuilder.build());

      JSONObject resJson = new JSONObject();
      resJson.put("txid", response.getTxid());


      JSONObject json = new JSONObject();
      json.put("error", false);
      json.put("response", resJson);

      callback.eventFired(json.toString());
     } catch (Exception e) {
      try {
       JSONObject json = new JSONObject();
       json.put("error", true);
       json.put("response", e.toString());

       callback.eventFired(json.toString());
      } catch (Exception e2) {
       callback.eventFired("");
      }
     }

    } // This is your code
   });
   thread.start();


  }

  public static void ConnectPeer(final String pubKey, final String host, final CallbackInterface callback) throws IOException {
   Thread thread = new Thread(new Runnable() {
    @Override
    public void run() {

     try {

      LightningAddress.Builder lightningAddBuilder = LightningAddress.newBuilder().setPubkey(pubKey);
      lightningAddBuilder.setHost(host);
      ConnectPeerRequest connectPeerReq = ConnectPeerRequest.newBuilder().setAddr(lightningAddBuilder.build()).build();

      ConnectPeerResponse response = stub.connectPeer(connectPeerReq);

      JSONObject json = new JSONObject();
      json.put("error", false);
      json.put("response", response.toString());

      callback.eventFired(json.toString());
     } catch (Exception e) {
      try {
       JSONObject json = new JSONObject();
       json.put("error", true);
       json.put("response", e.toString());

       callback.eventFired(json.toString());
      } catch (Exception e2) {
       callback.eventFired("");
      }
     }

    } // This is your code
   });
   thread.start();


  }
  
  public static void AddInvoice(final long amout, final String memo, final CallbackInterface callback) throws IOException {
   Thread thread = new Thread(new Runnable() {
    @Override
    public void run() {
          try {
        Invoice.Builder invoiceReq = Invoice.newBuilder();
      invoiceReq.setValue(amout);
      if(memo != null){
          invoiceReq.setMemo(memo);
      }
      
      AddInvoiceResponse response = stub.addInvoice(invoiceReq.build());
       
      JSONObject resJson = new JSONObject();
      resJson.put("payment_request", response.getPaymentRequest());

      JSONObject json = new JSONObject();
      json.put("error", false);
      json.put("response", resJson);

      callback.eventFired(json.toString());
      
      } catch (Exception e) {
      try {
       JSONObject json = new JSONObject();
       json.put("error", true);
       json.put("response", e.toString());

       callback.eventFired(json.toString());
      } catch (Exception e2) {
       callback.eventFired("");
      }
     }
     
   } // This is your code
   });
   thread.start();

  }
  
  public static void OpenChannel(final String pubKey, final long local_amount, final CallbackInterface callback) throws IOException {
   Thread thread = new Thread(new Runnable() {
    @Override
    public void run() {

     try {
System.out.println("pubKey " + pubKey);

      OpenChannelRequest.Builder openChannelReq = OpenChannelRequest.newBuilder();
      openChannelReq.setNodePubkeyString(pubKey);
   
       openChannelReq.setNodePubkey( ByteString.copyFrom(hexStringToByteArray(pubKey)));
      openChannelReq.setLocalFundingAmount(local_amount);

       
     // ChannelPoint response = stub.openChannel(openChannelReq.build());
      
      
      
      Iterator < OpenStatusUpdate > iterator = stub.openChannel(openChannelReq.build());
      while (iterator.hasNext()) {
       OpenStatusUpdate openStatusUpdate = iterator.next();
       System.out.println("logged " + openStatusUpdate.toString());

      ChannelOpenUpdate channelOpenUpdate = openStatusUpdate.getChanOpen();
      PendingUpdate pendingUpdate = openStatusUpdate.getChanPending();
      ConfirmationUpdate confirmationUpdate = openStatusUpdate.getConfirmation();
       
      
      
      ChannelPoint channelPoint = channelOpenUpdate.getChannelPoint();
      
      JSONObject channelPointJson = new JSONObject();
      channelPointJson.put("funding_txid", channelPoint.getFundingTxidStr());
       channelPointJson.put("output_index", channelPoint.getOutputIndex());
      
      JSONObject channelOpenUpdateJson = new JSONObject(); 
      channelOpenUpdateJson.put("channel_point", channelPointJson);
      
       JSONObject pendingUpdateJson = new JSONObject();
       pendingUpdateJson.put("txid",bytesToHex(pendingUpdate.getTxid().toByteArray())); 
       pendingUpdateJson.put("output_index",pendingUpdate.getOutputIndex());
       
        JSONObject confirmationUpdateJson = new JSONObject();
       confirmationUpdateJson.put("block_height",confirmationUpdate.getBlockHeight());
       
       confirmationUpdateJson.put("num_confs_left",confirmationUpdate.getNumConfsLeft());
       
        confirmationUpdateJson.put("block_sha",bytesToHex(confirmationUpdate.getBlockSha().toByteArray()));
       
        
        
          
      JSONObject jsonCombined = new JSONObject(); 
       jsonCombined.put("channel_open_update", channelOpenUpdateJson);
        jsonCombined.put("pending_update", pendingUpdateJson);
        jsonCombined.put("confirmation_update",  confirmationUpdateJson);

       
     JSONObject json = new JSONObject();
       json.put("error", false);
       json.put("response", jsonCombined);


       callback.eventFired(json.toString()); 

      }


       /*
      JSONObject resJson = new JSONObject();
      resJson.put("funding_txid_str", response.getFundingTxidStr());
      resJson.put("output_index", response.getOutputIndex());
      resJson.put("verbose", response.toString());

      JSONObject json = new JSONObject();
      json.put("error", false);
      json.put("response", resJson);

      callback.eventFired(json.toString());*/
     } catch (Exception e) {
      try {
       JSONObject json = new JSONObject();
       json.put("error", true);
       json.put("response", e.toString());

       callback.eventFired(json.toString());
      } catch (Exception e2) {
       callback.eventFired("");
      }
     }

    } // This is your code
   });
   thread.start();


  }

  
   

  public static void SubscribeInvoices(final CallbackInterface callback) throws IOException {

   Thread thread = new Thread(new Runnable() {
    @Override
    public void run() {

     try {
       InvoiceSubscription request =  InvoiceSubscription.getDefaultInstance();
               
      Iterator < Invoice > iterator =  stub.subscribeInvoices(request);
      while (iterator.hasNext()) {
      Invoice anInvoice = iterator.next();
      
      JSONObject anInvoiceJSON = new JSONObject();
       anInvoiceJSON.put("creation_date", anInvoice.getCreationDate());
       anInvoiceJSON.put("memo", anInvoice.getMemo()); //deprecated check api lnd
       anInvoiceJSON.put("amt_paid", anInvoice.getAmtPaid()); //deprecated check api lnd
        anInvoiceJSON.put("payment_request", anInvoice.getPaymentRequest()); 
         anInvoiceJSON.put("settled", anInvoice.getSettled()); 
          anInvoiceJSON.put("r_hash", bytesToHex(anInvoice.getRHash().toByteArray()));

 callback.eventFired(anInvoiceJSON.toString()); 
      }

 
     } catch (Exception e) {
      try {
       JSONObject json = new JSONObject();
       json.put("error", true);
       json.put("response", e.toString());

       System.out.println("error " + e.toString());

        callback.eventFired(json.toString());
      } catch (Exception e2) {
      
 callback.eventFired(e2.toString()); 
      }
     }

    } // This is your code
   });
   thread.start();
 
  }

  private static String bytesToHex(byte[] bytes) {
   char[] hexArray = "0123456789abcdef".toCharArray();
   char[] hexChars = new char[bytes.length * 2];
   for (int j = 0; j < bytes.length; j++) {
    int v = bytes[j] & 0xFF;
    hexChars[j * 2] = hexArray[v >>> 4];
    hexChars[j * 2 + 1] = hexArray[v & 0x0F];
   }
   return new String(hexChars);
  }





 }