/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.ranger.services.opensearch.client;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientResponse;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpStatus;
import org.apache.ranger.plugin.client.BaseClient;
import org.apache.ranger.plugin.client.HadoopException;
import org.apache.ranger.plugin.util.PasswordUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.ws.rs.core.MediaType;

import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class OpensearchClient extends BaseClient {
    private static final Logger LOG = LoggerFactory.getLogger(OpensearchClient.class);

    private static final String OPENSEARCH_INDEX_API_ENDPOINT = "/_all";

    private final String opensearchUrl;
    private final String userName;
    private final String password;

    public OpensearchClient(String serviceName, Map<String, String> configs) {
        super(serviceName, configs, "opensearch-client");

        this.opensearchUrl = configs.get("opensearch.url");
        this.userName         = configs.get("username");
        this.password         = configs.get("password");

        if (StringUtils.isEmpty(this.opensearchUrl)) {
            LOG.error("No value found for configuration 'opensearch.url'. Opensearch resource lookup will fail.");
        }

        if (StringUtils.isEmpty(this.userName)) {
            LOG.error("No value found for configuration 'username'. Opensearch resource lookup will fail.");
        }

        LOG.debug("Opensearch client is build with url: [{}], user: [{}].", this.opensearchUrl, this.userName);
    }

    public static Map<String, Object> connectionTest(String serviceName, Map<String, String> configs) {
        OpensearchClient opensearchClient = getOpensearchClient(serviceName, configs);
        List<String>        indexList           = opensearchClient.getIndexList(null, null);

        boolean connectivityStatus = false;

        if (CollectionUtils.isNotEmpty(indexList)) {
            LOG.debug("ConnectionTest list size {} opensearch indices.", indexList.size());

            connectivityStatus = true;
        }

        Map<String, Object> responseData = new HashMap<>();

        if (connectivityStatus) {
            String successMsg = "ConnectionTest Successful.";

            BaseClient.generateResponseDataMap(true, successMsg, successMsg, null, null, responseData);
        } else {
            String failureMsg = "Unable to retrieve any opensearch indices using given parameters.";

            BaseClient.generateResponseDataMap(false, failureMsg, failureMsg + DEFAULT_ERROR_MESSAGE, null, null, responseData);
        }

        return responseData;
    }

    public static OpensearchClient getOpensearchClient(String serviceName, Map<String, String> configs) {
        OpensearchClient opensearchClient;

        LOG.debug("Getting opensearchClient for datasource: {}", serviceName);

        if (MapUtils.isEmpty(configs)) {
            String msgDesc = "Could not connect opensearch as connection configMap is empty.";

            LOG.error(msgDesc);

            HadoopException hdpException = new HadoopException(msgDesc);

            hdpException.generateResponseDataMap(false, msgDesc, msgDesc + DEFAULT_ERROR_MESSAGE, null, null);

            throw hdpException;
        } else {
            opensearchClient = new OpensearchClient(serviceName, configs);
        }

        return opensearchClient;
    }

    public List<String> getIndexList(final String indexMatching, final List<String> existingIndices) {
        LOG.debug("Get opensearch index list for indexMatching: {}, existingIndices: {}", indexMatching, existingIndices);

        Subject subj = getLoginSubject();

        if (subj == null) {
            return Collections.emptyList();
        }

        List<String> ret = Subject.doAs(subj, (PrivilegedAction<List<String>>) () -> {
            String indexApi;

            if (StringUtils.isNotEmpty(indexMatching)) {
                indexApi = '/' + indexMatching;

                if (!indexApi.endsWith("*")) {
                    indexApi += "*";
                }
            } else {
                indexApi = OPENSEARCH_INDEX_API_ENDPOINT;
            }

            ClientResponse      response        = getClientResponse(opensearchUrl, indexApi, userName, password);
            Map<String, Object> index2detailMap = getOpensearchResourceResponse(response, new TypeToken<HashMap<String, Object>>() {}.getType());

            if (MapUtils.isEmpty(index2detailMap)) {
                return Collections.emptyList();
            }

            Set<String> indexResponses = index2detailMap.keySet();

            if (CollectionUtils.isEmpty(indexResponses)) {
                return Collections.emptyList();
            }

            return filterResourceFromResponse(indexMatching, existingIndices, new ArrayList<>(indexResponses));
        });

        LOG.debug("Get opensearch index list result: {}", ret);

        return ret;
    }

    private static ClientResponse getClientResponse(String opensearchUrl, String opensearchApi, String userName, String password) {
        String[] opensearchUrls = opensearchUrl.trim().split("[,;]");

        if (ArrayUtils.isEmpty(opensearchUrls)) {
            return null;
        }

        ClientResponse response = null;
        Client         client   = Client.create();

        for (String currentUrl : opensearchUrls) {
            if (StringUtils.isBlank(currentUrl)) {
                continue;
            }

            String url = currentUrl.trim() + opensearchApi;

            try {
                response = getClientResponse(url, client, userName, password);

                if (response != null) {
                    if (response.getStatus() == HttpStatus.SC_OK) {
                        break;
                    } else {
                        response.close();
                    }
                }
            } catch (Throwable t) {
                String msgDesc = "Exception while getting opensearch response, opensearchUrl: " + url;

                LOG.error(msgDesc, t);
            }
        }

        client.destroy();

        return response;
    }

    private static String decryptPass(String encryptedPwd) {

        String password     = null;
        // LOG.info("ABHRADEEP OPENSEARCHCLIENT===================== Getting the encryptedPwd as " + encryptedPwd);
        if (encryptedPwd != null) {
            try {
                password = PasswordUtils.decryptPassword(encryptedPwd);
                // LOG.info("ABHRADEEP OPENSEARCHCLIENT===================== Getting the password as " + password);
            } catch (Exception ex) {
                LOG.info("Password decryption failed; trying connection with received password string");

                password = null;
            } finally {
                if (password == null) {
                    password = encryptedPwd;
                }
            }
        } else {
            LOG.info("Password decryption failed: no password was configured");
        }
        return password;
    }

    private static ClientResponse getClientResponse(String url, Client client, String userName, String password) {
        LOG.debug("getClientResponse():calling {}", url);
        // LOG.info("ABHRADEEP ===================== Getting the password as " + password);
        String decryptedPass = decryptPass(password);
        String auth = userName + ":" + decryptedPass;
        byte[] encodedAuth = Base64.getEncoder().encode(auth.getBytes(StandardCharsets.UTF_8));
        String encodedAuthStr = new String(encodedAuth);
        String authHeader = "Basic "+encodedAuthStr;
        // LOG.info("ABHRADEEP ===================== Passing the auth header as " + authHeader);

        ClientResponse response = client.resource(url).accept(MediaType.APPLICATION_JSON).header("userName", userName).header("Authorization", authHeader).get(ClientResponse.class);

        if (response != null) {
            LOG.debug("getClientResponse():response.getStatus()= {}", response.getStatus());

            if (response.getStatus() != HttpStatus.SC_OK) {
                LOG.warn("getClientResponse():response.getStatus()= {} for URL {}, failed to get opensearch resource list, response= {}", response.getStatus(), url, response.getEntity(String.class));
            }
        }

        return response;
    }

    private <T> T getOpensearchResourceResponse(ClientResponse response, Type type) {
        T resource;

        try {
            if (response != null && response.getStatus() == HttpStatus.SC_OK) {
                String jsonString = response.getEntity(String.class);
                Gson   gson       = new GsonBuilder().setPrettyPrinting().create();

                resource = gson.fromJson(jsonString, type);
            } else {
                String msgDesc = "Unable to get a valid response for " + "expected mime type : [" + MediaType.APPLICATION_JSON + "], opensearchUrl: " + opensearchUrl + " - got null response.";

                LOG.error(msgDesc);

                HadoopException hdpException = new HadoopException(msgDesc);

                hdpException.generateResponseDataMap(false, msgDesc, msgDesc + DEFAULT_ERROR_MESSAGE, null, null);

                throw hdpException;
            }
        } catch (HadoopException he) {
            throw he;
        } catch (Throwable t) {
            String msgDesc = "Exception while getting opensearch resource response, opensearchUrl: " + opensearchUrl;

            HadoopException hdpException = new HadoopException(msgDesc, t);

            LOG.error(msgDesc, t);

            hdpException.generateResponseDataMap(false, BaseClient.getMessage(t), msgDesc + DEFAULT_ERROR_MESSAGE, null, null);

            throw hdpException;
        } finally {
            if (response != null) {
                response.close();
            }
        }

        return resource;
    }

    private static List<String> filterResourceFromResponse(String resourceMatching, List<String> existingResources, List<String> resourceResponses) {
        List<String> resources = new ArrayList<>();

        for (String resourceResponse : resourceResponses) {
            if (CollectionUtils.isNotEmpty(existingResources) && existingResources.contains(resourceResponse)) {
                continue;
            }

            if (StringUtils.isEmpty(resourceMatching) || resourceMatching.startsWith("*") || resourceResponse.toLowerCase().startsWith(resourceMatching.toLowerCase())) {
                LOG.debug("filterResourceFromResponse(): Adding opensearch resource {}", resourceResponse);

                resources.add(resourceResponse);
            }
        }

        return resources;
    }
}
