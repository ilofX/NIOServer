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
import java.net.InetSocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLEngine;

/**
 * @author Stella Filippo
 * @version 0.01
 */
public class ServerTCP extends Thread {
    
    private final boolean secure;
    private ServerSocketChannel server;
    private Selector selector;
    private SelectionKey key;
    private final Integer PORT;
    private SecurityManager securityManager;
    private final String caCert, publicCert;

    public ServerTCP(boolean secure, Integer PORT, String caCert, String publicCert) {
        this.secure = secure;
        this.PORT = PORT;
        this.caCert = caCert;
        this.publicCert = publicCert;
                
    }
    
    public void serverInit() throws IOException{
        this.server = ServerSocketChannel.open();
        this.selector = Selector.open();
        this.server.configureBlocking(false);
        this.key = server.register(selector, SelectionKey.OP_ACCEPT);
        
        if(this.secure){
            this.securityManager = new SecurityManager();
            this.securityManager.setKeys(new FileInputStream(this.publicCert), new FileInputStream(this.caCert));
            this.securityManager.initSecurity();
        }
    }

    @Override
    public void run() {
        try {
            this.server.bind(new InetSocketAddress(this.PORT));
            System.out.println("Server started on port: "+this.PORT);
            while(!this.isInterrupted()){
                Integer readyChannels = selector.select();
                if(readyChannels == 0) continue;
                
                Iterator<SelectionKey> keyIterator = selector.selectedKeys().iterator();
                
                while(keyIterator.hasNext()){
                    SelectionKey key = keyIterator.next();
                    
                    if(!key.isValid()) continue;
                
                    if(key.isAcceptable()) {
                        accept(key);
                    } else if(key.isReadable()) {
                        //read(key,(ConnectionParameters)key.attachment());
                    } else if(key.isWritable()) {
                        //write(key, (ConnectionParameters)key.attachment());
                    }
                        
                    keyIterator.remove();
                }
            }
        } catch (IOException ex) {
            Logger.getLogger(ServerTCP.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private void accept(SelectionKey key) throws IOException{
        if(this.secure){
            SocketChannel socketChannel = ((ServerSocketChannel)key.channel()).accept();
            socketChannel.configureBlocking(false);
            
            SSLEngine securityEngine = this.securityManager.getEngine();
            ConnectionParameters param = new ConnectionParameters(securityEngine);
            securityEngine.setUseClientMode(false);
            securityEngine.beginHandshake();
            
            if(SecurityManager.doHandshake(socketChannel, securityEngine, param.getInEncrypted(), param.getOutDecrypted(), param.getInEncrypted(), param.getInDecrypted())){
                socketChannel.register(selector, SelectionKey.OP_READ, param);
            }
            else{
                socketChannel.close();
            }    
        }
        else{
            SocketChannel socketChannel = ((ServerSocketChannel)key.channel()).accept();
            socketChannel.configureBlocking(false);
            ConnectionParameters param = new ConnectionParameters();
            socketChannel.register(selector, SelectionKey.OP_READ, param);
        }
    }
    
    
    
    public static void closeConnection(SocketChannel channel, SSLEngine securityEngine) throws IOException{
        securityEngine.closeOutbound();
        //doHandshake(channel, engine);
        channel.close();
    }
    public static void closeConnection(SelectionKey key) throws IOException{
        key.channel().close();
    }
}

