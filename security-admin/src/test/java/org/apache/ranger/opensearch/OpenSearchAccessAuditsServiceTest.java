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

package org.apache.ranger.opensearch;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.apache.ranger.audit.destination.OpenSearchAuditDestination;
import org.apache.ranger.audit.model.AuthzAuditEvent;
import org.apache.ranger.common.PropertiesUtil;
import org.apache.ranger.common.RESTErrorUtil;
import org.apache.ranger.common.SearchCriteria;
import org.apache.ranger.common.StringUtil;
import org.apache.ranger.view.VXAccessAuditList;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;

import static org.apache.ranger.audit.destination.OpenSearchAuditDestination.CONFIG_PREFIX;

public class OpenSearchAccessAuditsServiceTest {
    private static final Logger LOGGER = LoggerFactory.getLogger(OpenSearchAccessAuditsServiceTest.class);

    @Test
    @Ignore // For manual execution only
    public void testQuery() {
        OpenSearchAccessAuditsService openSearchAccessAuditsService = new OpenSearchAccessAuditsService();
        Map<String, String>              properties                       = PropertiesUtil.getPropertiesMap();
        properties.put("ranger.audit.opensearch.urls", "localhost");
        properties.put("ranger.audit.opensearch.protocol", "http");
        properties.put("ranger.audit.opensearch.user", "opensearch");
        properties.put("ranger.audit.opensearch.password", "password1");
        properties.put("ranger.audit.opensearch.port", "9200");
        openSearchAccessAuditsService.openSearchMgr             = new OpenSearchMgr();
        openSearchAccessAuditsService.openSearchUtil            = new OpenSearchUtil();
        openSearchAccessAuditsService.openSearchUtil.stringUtil = new StringUtil();
        openSearchAccessAuditsService.setRestErrorUtil(new RESTErrorUtil());
        LOGGER.info("Running searchXAccessAudits:");
        VXAccessAuditList vxAccessAuditList = openSearchAccessAuditsService.searchXAccessAudits(getSearchCriteria());
        LOGGER.info(String.format("searchXAccessAudits results (%d items):", vxAccessAuditList.getListSize()));
        ObjectWriter writer = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT).writer();
        vxAccessAuditList.getVXAccessAudits().forEach(x -> {
            try {
                LOGGER.warn(writer.writeValueAsString(x));
            } catch (JsonProcessingException e) {
                e.printStackTrace();
            }
        });
    }

    @Test
    @Ignore // For manual execution only
    public void testWrite() {
        OpenSearchAuditDestination openSearchAuditDestination = new OpenSearchAuditDestination();
        Properties                    properties                    = new Properties();
        properties.put(CONFIG_PREFIX + "." + OpenSearchAuditDestination.CONFIG_URLS, "localhost");
        properties.put(CONFIG_PREFIX + "." + OpenSearchAuditDestination.CONFIG_USER, "opensearch");
        properties.put(CONFIG_PREFIX + "." + OpenSearchAuditDestination.CONFIG_PWRD, "password1");
        openSearchAuditDestination.init(properties, CONFIG_PREFIX);
        Assert.assertTrue(openSearchAuditDestination.log(Collections.singletonList(getAuthzAuditEvent())));
    }

    private SearchCriteria getSearchCriteria() {
        SearchCriteria searchCriteria = new SearchCriteria();
        searchCriteria.setDistinct(false);
        searchCriteria.setGetChildren(false);
        searchCriteria.setGetCount(true);
        searchCriteria.setMaxRows(25);
        searchCriteria.setOwnerId(null);
        searchCriteria.setSortBy("eventTime");
        searchCriteria.setSortType("desc");
        searchCriteria.setStartIndex(0);
        Calendar calendar = Calendar.getInstance();
        calendar.set(2019, 11, 13);
        searchCriteria.getParamList().put("startDate", calendar.getTime());
        searchCriteria.getParamList().put("-repoType", 7);
        searchCriteria.getParamList().put("-requestUser", new ArrayList<>());
        searchCriteria.getParamList().put("requestUser", new ArrayList<>());
        searchCriteria.getParamList().put("zoneName", new ArrayList<>());
        return searchCriteria;
    }

    private AuthzAuditEvent getAuthzAuditEvent() {
        AuthzAuditEvent event = new AuthzAuditEvent();
        event.setAccessResult((short) 1);
        event.setAccessType("");
        event.setAclEnforcer("");
        event.setAction("");
        event.setAdditionalInfo("");
        event.setAgentHostname("");
        event.setAgentId("");
        event.setClientIP("");
        event.setClusterName("");
        event.setClientType("");
        event.setEventCount(1);
        event.setEventDurationMS(1);
        event.setEventId("");
        event.setEventTime(new Date());
        event.setLogType("");
        event.setPolicyId(1);
        event.setPolicyVersion(1L);
        event.setRepositoryName("");
        event.setRequestData("");
        event.setRepositoryName("");
        event.setRepositoryType(1);
        event.setResourcePath("");
        event.setResultReason("");
        event.setSeqNum(1);
        event.setSessionId("");
        event.setTags(new HashSet<>());
        event.setUser("");
        event.setZoneName("");
        return event;
    }
}
