/*
 * Copyright 2017 Stella Filippo.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package Model;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManagerFactory;

/**
 *
 * @author Stella Filippo
 * @version 0.01
 */
public class SecurityManager {
    
    private KeyStore ksKeys,ksTrust;
    private KeyManagerFactory kmf;
    private TrustManagerFactory tmf;
    private SSLContext sslContext;
    private static final ExecutorService EXECUTORS = Executors.newSingleThreadExecutor();;
    private final char[] passphrase;

    public SecurityManager() {
        this.passphrase = "passphrase".toCharArray();
    }
    
    public void setKeys(FileInputStream pub, FileInputStream ca){
        try {
            this.ksKeys = KeyStore.getInstance("PKCS12");
            this.ksKeys.load(pub,this.passphrase); //Chiavi PKCS12
            System.out.println("keystore Ready");
            this.ksTrust = KeyStore.getInstance("PKCS12");
            this.ksTrust.load(ca,this.passphrase); //CA
            System.out.println("Certificates ready");
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException ex) {
            Logger.getLogger(SecurityManager.class.getName()).log(Level.SEVERE, null, ex);
        }
        
    }
    
    public void initSecurity(){
        try {
            this.kmf = KeyManagerFactory.getInstance("SunX509");
            this.kmf.init(this.ksKeys, this.passphrase);
            this.tmf = TrustManagerFactory.getInstance("SunX509");
            this.tmf.init(this.ksTrust);
            
            this.sslContext = SSLContext.getInstance("TLS");
            this.sslContext.init(this.kmf.getKeyManagers(), this.tmf.getTrustManagers(), null);
            
        } catch (NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException | KeyManagementException ex) {
            Logger.getLogger(SecurityManager.class.getName()).log(Level.SEVERE, null, ex);
        }
    
    }
    
    public SSLEngine getEngine(){
        return this.sslContext.createSSLEngine();
    }
    
    public static boolean doHandshake(SocketChannel socketChannel, SSLEngine securityEngine, ByteBuffer outEncrypted, ByteBuffer outDecrypted, ByteBuffer inEncrypted, ByteBuffer inDecrypted) throws IOException {

        SSLEngineResult result;
        SSLEngineResult.HandshakeStatus handshakeStatus;

        // NioSslPeer's fields myAppData and peerAppData are supposed to be large enough to hold all message data the peer
        // will send and expects to receive from the other peer respectively. Since the messages to be exchanged will usually be less
        // than 16KB long the capacity of these fields should also be smaller. Here we initialize these two local buffers
        // to be used for the handshake, while keeping client's buffers at the same size.
        outEncrypted.clear();
        inEncrypted.clear();

        handshakeStatus = securityEngine.getHandshakeStatus();
        while (handshakeStatus != SSLEngineResult.HandshakeStatus.FINISHED && handshakeStatus != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
            switch (handshakeStatus) {
            case NEED_UNWRAP:
                if (socketChannel.read(inEncrypted) < 0) {
                    if (securityEngine.isInboundDone() && securityEngine.isOutboundDone()) {
                        return false;
                    }
                    try {
                        securityEngine.closeInbound();
                    } catch (SSLException e) {
                        //log.log(Level.SEVERE,"This engine was forced to close inbound, without having received the proper SSL/TLS close notification message from the peer, due to end of stream.");
                    }
                    securityEngine.closeOutbound();
                    // After closeOutbound the engine will be set to WRAP state, in order to try to send a close message to the client.
                    handshakeStatus = securityEngine.getHandshakeStatus();
                    break;
                }
                inEncrypted.flip();
                try {
                    result = securityEngine.unwrap(inEncrypted, inDecrypted);
                    inEncrypted.compact();
                    handshakeStatus = result.getHandshakeStatus();
                } catch (SSLException sslException) {
                    //log.log(Level.SEVERE,"A problem was encountered while processing the data that caused the SSLEngine to abort. Will try to properly close connection...");
                    securityEngine.closeOutbound();
                    handshakeStatus = securityEngine.getHandshakeStatus();
                    break;
                }
                switch (result.getStatus()) {
                case OK:
                    break;
                case BUFFER_OVERFLOW:
                    // Will occur when peerAppData's capacity is smaller than the data derived from peerNetData's unwrap.
                    inDecrypted = SecurityManager.handleOverflow(securityEngine.getSession().getApplicationBufferSize(), inDecrypted);
                    break;
                case BUFFER_UNDERFLOW:
                    // Will occur either when no data was read from the peer or when the peerNetData buffer was too small to hold all peer's data.
                    inEncrypted = SecurityManager.handleUnderflow(securityEngine.getSession().getPacketBufferSize(), inEncrypted);
                    break;
                case CLOSED:
                    if (securityEngine.isOutboundDone()) {
                        return false;
                    } else {
                        securityEngine.closeOutbound();
                        handshakeStatus = securityEngine.getHandshakeStatus();
                        break;
                    }
                default:
                    throw new IllegalStateException("Invalid SSL status: " + result.getStatus());
                }
                break;
            case NEED_WRAP:
                outEncrypted.clear();
                try {
                    result = securityEngine.wrap(outDecrypted, outEncrypted);
                    handshakeStatus = result.getHandshakeStatus();
                } catch (SSLException sslException) {
                    //log.log(Level.SEVERE,"A problem was encountered while processing the data that caused the SSLEngine to abort. Will try to properly close connection...");
                    securityEngine.closeOutbound();
                    handshakeStatus = securityEngine.getHandshakeStatus();
                    break;
                }
                switch (result.getStatus()) {
                case OK :
                    outEncrypted.flip();
                    while (outEncrypted.hasRemaining()) {
                        socketChannel.write(outEncrypted);
                    }
                    break;
                case BUFFER_OVERFLOW:
                    // Will occur if there is not enough space in myNetData buffer to write all the data that would be generated by the method wrap.
                    // Since myNetData is set to session's packet size we should not get to this point because SSLEngine is supposed
                    // to produce messages smaller or equal to that, but a general handling would be the following:
                    outEncrypted = SecurityManager.handleOverflow(securityEngine.getSession().getPacketBufferSize(), outEncrypted);
                    break;
                case BUFFER_UNDERFLOW:
                    throw new SSLException("Buffer underflow occured after a wrap. I don't think we should ever get here.");
                case CLOSED:
                    try {
                        outEncrypted.flip();
                        while (outEncrypted.hasRemaining()) {
                            socketChannel.write(outEncrypted);
                        }
                        // At this point the handshake status will probably be NEED_UNWRAP so we make sure that peerNetData is clear to read.
                        inEncrypted.clear();
                    } catch (IOException e) {
                        //log.log(Level.SEVERE,"Failed to send server's CLOSE message due to socket channel's failure.");
                        handshakeStatus = securityEngine.getHandshakeStatus();
                    }
                    break;
                default:
                    throw new IllegalStateException("Invalid SSL status: " + result.getStatus());
                }
                break;
            case NEED_TASK:
                Runnable task;
                while ((task = securityEngine.getDelegatedTask()) != null) {
                    SecurityManager.EXECUTORS.execute(task);
                }
                handshakeStatus = securityEngine.getHandshakeStatus();
                break;
            case FINISHED:
                break;
            case NOT_HANDSHAKING:
                break;
            default:
                throw new IllegalStateException("Invalid SSL status: " + handshakeStatus);
            }
        }

        return true;
    }
    
    public static final boolean encrypt(ByteBuffer outDecrypted, ByteBuffer outEncrypted, SSLEngine securityEngine, SocketChannel channel, ConnectionParameters data) throws SSLException {
        boolean status=true;
        outDecrypted.flip();
        while(outDecrypted.hasRemaining()){
            outEncrypted.clear();
            SSLEngineResult result = securityEngine.wrap(outDecrypted, outEncrypted);
            switch (result.getStatus()){
                case OK:
                    outEncrypted.flip();
                    break;
                    case BUFFER_OVERFLOW:
                        data.setOutEncrypted(SecurityManager.handleOverflow(securityEngine.getSession().getPacketBufferSize(), outEncrypted));
                        break;
                    case BUFFER_UNDERFLOW:
                        data.setOutDecrypted(SecurityManager.handleUnderflow(securityEngine.getSession().getApplicationBufferSize(), outDecrypted));
                        break;
                    case CLOSED:
                        //Connection forcefully closed by remote host
                        SecurityManager.connectionClosed(channel, securityEngine);
                        status=false;
                    default:
                        status=false;
                        throw new IllegalStateException ("Invalid SSL Status: " + result.getStatus());
            }
        }
        return status;
    }
    
    public static final boolean decrypt(ByteBuffer inDecrypted, ByteBuffer inEncrypted, SSLEngine securityEngine, SocketChannel channel, ConnectionParameters data) throws SSLException {
        boolean status = true;
        inEncrypted.flip();
        while(inEncrypted.hasRemaining()){
            inDecrypted.clear();
            SSLEngineResult result = securityEngine.unwrap(inEncrypted, inDecrypted);
            switch (result.getStatus()){
                case OK:
                    inDecrypted.flip();
                    break;
                    case BUFFER_OVERFLOW:
                        data.setInDecrypted(SecurityManager.handleOverflow(securityEngine.getSession().getApplicationBufferSize(), inDecrypted));
                        break;
                    case BUFFER_UNDERFLOW:
                        data.setInEncrypted(SecurityManager.handleUnderflow(securityEngine.getSession().getPacketBufferSize(), inEncrypted));
                        break;
                    case CLOSED:
                        //Connection forcefully closed by remote host
                        SecurityManager.connectionClosed(channel, securityEngine);
                        status=false;
                    default:
                        status=false;
                        throw new IllegalStateException ("Invalid SSL Status: " + result.getStatus());
            }
        }
        return status;
    }
    
    private static ByteBuffer handleOverflow(Integer suggestedSize, ByteBuffer buf){
        if(suggestedSize > buf.capacity()) {return ByteBuffer.allocate(suggestedSize);}
        else                               {return ByteBuffer.allocate(buf.capacity()*2);}
    }
    
    private static ByteBuffer handleUnderflow(Integer suggestedSize, ByteBuffer buf){
        if(suggestedSize > buf.capacity())  {return ByteBuffer.allocate(suggestedSize);}
        else                                {return ByteBuffer.allocate(buf.capacity()*2);}
    }
    
    private static void connectionClosed(SocketChannel channel, SSLEngine securityEngine){
        try {
            try {
                securityEngine.closeInbound();
            } catch (SSLException ex) {
                System.err.println("Connection was closed by remote host uncorrectely: "+channel.getRemoteAddress());
                Logger.getLogger(SecurityManager.class.getName()).log(Level.SEVERE, null, ex);
            }
            ServerTCP.closeConnection(channel, securityEngine);
        } catch (IOException ex) {
            Logger.getLogger(SecurityManager.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
}
