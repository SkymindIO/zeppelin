/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.zeppelin.rest;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import io.skymind.auth.model.User;
import io.skymind.skil.daemon.client.SKILDaemonClient;
import io.skymind.skil.daemon.service.ServiceInfo;
import org.apache.shiro.authc.*;
import org.apache.shiro.subject.Subject;
import org.apache.zeppelin.annotation.ZeppelinApi;
import org.apache.zeppelin.notebook.NotebookAuthorization;
import org.apache.zeppelin.server.JsonExclusionStrategy;
import org.apache.zeppelin.server.JsonResponse;
import org.apache.zeppelin.ticket.TicketContainer;
import org.apache.zeppelin.utils.SecurityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.*;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.util.*;

/**
 * Created for org.apache.zeppelin.rest.message on 17/03/16.
 */

@Path("/login")
@Produces("application/json")
public class LoginRestApi {

  /**
   * Enum for Login Source especially in log-in success cases
   * SKIL_TOKEN : login success from SKIL using token
   * SKIL_API : login success from SKIL using user name and password
   * LOGIN_FORM : login success from Zeppelin login form
   */
  public enum LoginSource {
    SKIL_TOKEN("skil_token"),
    SKIL_API("skil_api"),
    LOGIN_FORM("login_form");

    private String name;

    LoginSource(String name) {
      this.name = name;
    }

    public String toString() {
      return this.name;
    }

    public static LoginSource from(String from) {
      if (SKIL_TOKEN.name.equals(from)) {
        return SKIL_TOKEN;
      } else if (SKIL_API.name.equals(from)) {
        return SKIL_API;
      } else if (LOGIN_FORM.name.equals(from)) {
        return LOGIN_FORM;
      } else {
        return null;
      }
    }
  }

  private static final Logger LOG = LoggerFactory.getLogger(LoginRestApi.class);
  private static List<LoginSource> loginSuccessList = new ArrayList<>();

  private static User currentUser = null;
  private static String currentUserToken = null;

  /**
   * Required by Swagger.
   */
  public LoginRestApi() {
    super();
  }

  public void addSource(LoginSource loginSource) {
    if (!loginSuccessList.contains(loginSource)) {
      loginSuccessList.add(loginSource);
    }
  }

  public void removeSource(LoginSource loginSource) {
    if (loginSuccessList.contains(loginSource)) {
      loginSuccessList.remove(loginSource);
    }
  }

  public static boolean existSource(LoginSource loginSource) {
    return loginSuccessList.contains(loginSource);
  }

  private boolean isValidSkilToken(String token) {
    if (currentUserToken != null && currentUserToken.equals(token)) {
      return true;
    }

    try {

      String agentUrl = System.getProperty("service.agentUrl");

      SKILDaemonClient client = new SKILDaemonClient(agentUrl);
      client.setAuthToken(token);
      List<ServiceInfo> services = client.services();

      String serviceId = System.getProperty("service.id");
      for (ServiceInfo service : services) {
        if (serviceId.equalsIgnoreCase(service.getId())) {
          return true;
        }
      }
    } catch (Exception e) {
      LOG.warn("Unable to verify SKIL Token.", e);
    }

    return false;
  }

  @GET
  @ZeppelinApi
  public Response login(@HeaderParam("token") String token1) throws IOException {
    JsonResponse response = null;

    if (token1 != null && isValidSkilToken(token1)) {
      DecodedJWT decodedJWT = JWT.decode(token1);
      String subject = decodedJWT.getSubject();
      GsonBuilder gsonBuilder = new GsonBuilder();
      gsonBuilder.setExclusionStrategies(new JsonExclusionStrategy());
      Gson gson = gsonBuilder.create();
      User user = gson.fromJson(subject, User.class);
      UsernamePasswordToken token = new UsernamePasswordToken(
              user.getUserName(),
              user.getPassword()
      );

      Subject currentUser = org.apache.shiro.SecurityUtils.getSubject();
      currentUser.getSession().stop();
      currentUser.getSession(true);
      currentUser.login(token);
      String principal = SecurityUtils.getPrincipal();

      HashSet<String> roles = new HashSet<>();
      roles.add(user.getRole().toString());
      String ticket = TicketContainer.instance.getTicket(principal);
      Map<String, String> data = new HashMap<>();
      data.put("principal", principal);
      data.put("roles", roles.toString());
      data.put("ticket", ticket);
      response = new JsonResponse(Response.Status.OK, "", data);
      LoginRestApi.currentUser = user;
      this.addSource(LoginSource.SKIL_TOKEN);
    } else {
      response = new JsonResponse(Response.Status.FORBIDDEN, "", "");
    }

    return response.build();
  }

  /**
   * Post Login
   * Returns userName & password
   * for anonymous access, username is always anonymous.
   * After getting this ticket, access through websockets become safe
   *
   * @return 200 response
   */
  @POST
  @ZeppelinApi
  public Response postLogin(@FormParam("userName") String userName,
                            @FormParam("password") String password,
                            @HeaderParam("authorization") String authHeader) {
    JsonResponse response = null;
    // ticket set to anonymous for anonymous user. Simplify testing.
    Subject currentUser = org.apache.shiro.SecurityUtils.getSubject();
    if (currentUser.isAuthenticated()) {
      currentUser.logout();
    }
    if (!currentUser.isAuthenticated()) {
      try {
        UsernamePasswordToken token = new UsernamePasswordToken(userName, password);
        //      token.setRememberMe(true);

        currentUser.getSession().stop();
        currentUser.getSession(true);
        currentUser.login(token);

        HashSet<String> roles = new HashSet<>();
        if (LoginRestApi.currentUser != null) {
          roles.add(LoginRestApi.currentUser.getRole().toString());
        } else {
          roles = SecurityUtils.getRoles();
        }
        String principal = SecurityUtils.getPrincipal();
        String ticket;
        if ("anonymous".equals(principal))
          ticket = "anonymous";
        else
          ticket = TicketContainer.instance.getTicket(principal);

        Map<String, String> data = new HashMap<>();
        data.put("principal", principal);
        data.put("roles", roles.toString());
        data.put("ticket", ticket);

        response = new JsonResponse(Response.Status.OK, "", data);
        //if no exception, that's it, we're done!

        //set roles for user in NotebookAuthorization module
        NotebookAuthorization.getInstance().setRoles(principal, roles);

        // check post login request come from Zeppelin login form or SKIL apis
        if (authHeader == null || authHeader.isEmpty()) {
          this.addSource(LoginSource.LOGIN_FORM);
        } else {
          // check if the auth header is valid or not
          String[] splitAuthHeader = authHeader.split(" ");
          String errMsg = null;
          if (splitAuthHeader.length != 2) {
            errMsg = "NOT a valid authorization header for SKIL apis access";
            throw new AuthenticationException(errMsg);
          } else if (!isValidSkilToken(splitAuthHeader[1])){
            errMsg = "NOT a valid JWT token in the authorization header for SKIL apis access";
            throw new AuthenticationException(errMsg);
          }

          this.addSource(LoginSource.SKIL_API);
        }

      } catch (UnknownAccountException uae) {
        //username wasn't in the system, show them an error message?
        LOG.error("Exception in login: ", uae);
      } catch (IncorrectCredentialsException ice) {
        //password didn't match, try again?
        LOG.error("Exception in login: ", ice);
      } catch (LockedAccountException lae) {
        //account for that username is locked - can't login.  Show them a message?
        LOG.error("Exception in login: ", lae);
      } catch (AuthenticationException ae) {
        //unexpected condition - error?
        LOG.error("Exception in login: ", ae);
      }
    }

    if (response == null) {
      response = new JsonResponse(Response.Status.FORBIDDEN, "", "");
    }

    LOG.warn(response.toString());
    return response.build();
  }

  @POST
  @Path("logout")
  @ZeppelinApi
  public Response logout() {
    JsonResponse response;
    Subject currentUser = org.apache.shiro.SecurityUtils.getSubject();
    TicketContainer.instance.removeTicket(SecurityUtils.getPrincipal());
    currentUser.getSession().stop();
    currentUser.logout();
    response = new JsonResponse(Response.Status.UNAUTHORIZED, "", "");
    LOG.warn(response.toString());
    this.removeSource(LoginSource.LOGIN_FORM);
    return response.build();
  }

  public static User getCurrentUser() {
    return currentUser;
  }

}
