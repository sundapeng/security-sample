/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.intel.sundp.sasl;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

/**
 * This is a Demo for SASL Mechanism 简单认证与安全层
 */
public class SimpleSASL {

  /**
   * Java Main
   *
   * @param args
   * @throws javax.security.sasl.SaslException
   */
  public static void main(String[] args) throws SaslException {
    new SimpleSASL().start();
  }

  private static class ClientHandler implements CallbackHandler {

    private String username;
    private String password;

    private ClientHandler(String username, String password) {
      this.username = username;
      this.password = password;
    }

    @Override
    public void handle(Callback[] cbs) throws IOException,
        UnsupportedCallbackException {
      for (Callback cb : cbs) {
        if (cb instanceof NameCallback) {

          System.out.println("Client - NameCallback");

          NameCallback nc = (NameCallback) cb;
          nc.setName(username);
        } else if (cb instanceof PasswordCallback) {

          System.out.println("Client - PasswordCallback");

          PasswordCallback pc = (PasswordCallback) cb;
          pc.setPassword(password.toCharArray());
        }
      }
    }
  }

  private static class ServerHandler implements CallbackHandler {

    private Map<?,String> user_db;

    private ServerHandler(Map db) {
      this.user_db = db;
    }

    public void handle(Callback[] cbs) throws IOException,
        UnsupportedCallbackException {
      String username = "";
      PasswordCallback pc = null;
      for (Callback cb : cbs) {
        if (cb instanceof AuthorizeCallback) {
          System.out.println("Server - AuthorizeCallback");
          AuthorizeCallback ac = (AuthorizeCallback) cb;
          ac.setAuthorized(true);
          return;
        } else if (cb instanceof NameCallback) {
          System.out.println("Server - NameCallback");
          NameCallback nc = (NameCallback) cb;
          username = nc.getDefaultName();
        } else if (cb instanceof PasswordCallback) {
          System.out.println("Server - PasswordCallback");
          pc = (PasswordCallback) cb;
        }
      }
      String pwd = user_db.get(username);
      pc.setPassword(pwd.toCharArray());
    }
  }

  private void start() throws SaslException {

    byte[] challenge;
    byte[] response;
    Map<String, String> db = new HashMap<String, String>(1);
    db.put("username1", "pwd1");
    db.put("username2", "pwd2");
    ClientHandler clientHandler = new ClientHandler("username1", "pwd1");
    ServerHandler serverHandler = new ServerHandler(db);

    SaslClient sc =
        Sasl.createSaslClient(new String[]{"CRAM-MD5"}, null, "my_server", "FQHN",
            null, clientHandler);
    SaslServer ss = Sasl.createSaslServer("CRAM-MD5", "my_server", "FQHN", null,
        serverHandler);

    challenge = ss.evaluateResponse(new byte[0]);
    response = sc.evaluateChallenge(challenge);
    ss.evaluateResponse(response);

    if (ss.isComplete()) {
      System.out.println("Authentication successful. Auth ID : "+ss.getAuthorizationID());
    }
  }
}