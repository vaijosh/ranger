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

import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.ranger.plugin.service.ResourceLookupContext;

import java.util.List;
import java.util.Map;

public class OpensearchResourceMgr {
    private static final Logger LOG = LogManager.getLogger(OpensearchResourceMgr.class);

    public static final String INDEX = "index";

    private OpensearchResourceMgr() {
        // to block instantiation
    }

    public static Map<String, Object> validateConfig(String serviceName, Map<String, String> configs) {
        Map<String, Object> ret;

        LOG.debug("==> OpensearchResourceMgr.validateConfig() serviceName: {}, configs: {}", serviceName, configs);

        try {
            ret = OpensearchClient.connectionTest(serviceName, configs);
        } catch (Exception e) {
            LOG.error("<== OpensearchResourceMgr.validateConfig() error: {}", String.valueOf(e));

            throw e;
        }

        LOG.debug("<== OpensearchResourceMgr.validateConfig() result: {}", ret);

        return ret;
    }

    public static List<String> getOpensearchResources(String serviceName, Map<String, String> configs, ResourceLookupContext context) {
        String                    userInput   = context.getUserInput();
        String                    resource    = context.getResourceName();
        Map<String, List<String>> resourceMap = context.getResources();

        LOG.debug("==> OpensearchResourceMgr.getOpensearchResources()  userInput: {}, resource: {}, resourceMap: {}", userInput, resource, resourceMap);

        if (MapUtils.isEmpty(configs)) {
            LOG.error("Connection config is empty!");

            return null;
        }

        if (StringUtils.isEmpty(userInput)) {
            LOG.warn("User input is empty, set default value : *");

            userInput = "*";
        }

        List<String> resultList = null;

        if (StringUtils.isNotEmpty(resource)) {
            if (resource.equals(INDEX)) {
                List<String> existingConnectors = resourceMap.get(INDEX);

                resultList = OpensearchClient.getOpensearchClient(serviceName, configs).getIndexList(userInput, existingConnectors);
            }
        }

        LOG.debug("<== OpensearchResourceMgr.getOpensearchResources() result: {}", resultList);

        return resultList;
    }
}
