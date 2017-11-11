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

import java.nio.ByteBuffer;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;

/**
 *
 * @author Stella Filippo
 * @version 0.01
 */
public class ConnectionParameters {
    
    private SSLEngine securityEngine;
    private ByteBuffer inEncrypted,inDecrypted,outEncrypted,outDecrypted;

    public ConnectionParameters(SSLEngine securityEngine) {
        this.securityEngine = securityEngine;
        SSLSession session=this.securityEngine.getSession();
        this.inEncrypted=ByteBuffer.allocate(session.getPacketBufferSize());
        this.outEncrypted=ByteBuffer.allocate(session.getPacketBufferSize());
        this.inDecrypted=ByteBuffer.allocate(session.getApplicationBufferSize());
        this.outDecrypted=ByteBuffer.allocate(session.getApplicationBufferSize());
    }
    
    public ConnectionParameters (){
        this.inEncrypted=ByteBuffer.allocate(1024);
        this.outEncrypted=ByteBuffer.allocate(1024);
        this.inDecrypted=ByteBuffer.allocate(1024);
        this.outDecrypted=ByteBuffer.allocate(1024);
    
    }
    
    public byte[] getDecryptedData(){
        byte[] ris = new byte[this.inDecrypted.capacity()];
        this.inDecrypted.get(ris);
        this.inDecrypted.rewind();
        return ris;
    }
    
    public void setDecryptedData(byte[] data){
        this.outDecrypted.put(data);
    }
    
    public byte[] getEncryptedData(){
        byte[] ris = new byte[this.outEncrypted.capacity()];
        this.outEncrypted.get(ris);
        this.outDecrypted.rewind();
        return ris;
    }
    
    public void setEncryptedData(byte[] data){
        this.inEncrypted.put(data);
    }

    public void setInEncrypted(ByteBuffer inEncrypted) {
        this.inEncrypted = inEncrypted;
    }
    public void setInDecrypted(ByteBuffer inDecrypted) {
        this.inDecrypted = inDecrypted;
    }
    public void setOutEncrypted(ByteBuffer outEncrypted) {
        this.outEncrypted = outEncrypted;
    }
    public void setOutDecrypted(ByteBuffer outDecrypted) {
        this.outDecrypted = outDecrypted;
    }

    public ByteBuffer getInEncrypted() {
        return inEncrypted;
    }
    public ByteBuffer getInDecrypted() {
        return inDecrypted;
    }
    public ByteBuffer getOutEncrypted() {
        return outEncrypted;
    }
    public ByteBuffer getOutDecrypted() {
        return outDecrypted;
    }

    
    
}