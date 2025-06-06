/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.ranger.authorization.opensearch.authorizer;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.hadoop.thirdparty.com.google.common.collect.Sets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.ranger.audit.provider.MiscUtil;
import org.apache.ranger.plugin.policyengine.RangerAccessRequestImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResourceImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResult;
import org.apache.ranger.plugin.service.RangerBasePlugin;
import org.apache.ranger.services.opensearch.client.OpensearchResourceMgr;
import org.apache.ranger.services.opensearch.privilege.IndexPrivilegeUtils;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class RangerOpensearchAuthorizer implements RangerOpensearchAccessControl {
    private static final Logger LOG = LogManager.getLogger(RangerOpensearchAccessControl.class);

    private static volatile RangerOpensearchInnerPlugin opensearchPlugin;

    public RangerOpensearchAuthorizer() {
        LOG.debug("==> RangerOpensearchAuthorizer.RangerOpensearchAuthorizer()");

        this.init();

        LOG.debug("<== RangerOpensearchAuthorizer.RangerOpensearchAuthorizer()");
    }

    public void init() {
        LOG.debug("==> RangerOpensearchAuthorizer.init()");

        RangerOpensearchInnerPlugin plugin = opensearchPlugin;

        if (plugin == null) {
            synchronized (RangerOpensearchAuthorizer.class) {
                plugin = opensearchPlugin;

                if (plugin == null) {
                    plugin = new RangerOpensearchInnerPlugin();

                    plugin.init();

                    opensearchPlugin = plugin;
                }
            }
        }

        LOG.debug("<== RangerOpensearchAuthorizer.init()");
    }

    @Override
    public boolean checkPermission(String user, List<String> groups, String index, String action, String clientIPAddress) {
        LOG.debug("==> RangerOpensearchAuthorizer.checkPermission( user={}, groups={}, index={}, action={}, clientIPAddress={})", user, groups, index, action, clientIPAddress);

        boolean ret = false;

        if (opensearchPlugin != null) {
            if (null == groups) {
                groups = new ArrayList<>(MiscUtil.getGroupsForRequestUser(user));
            }

            String                           privilege = IndexPrivilegeUtils.getPrivilegeFromAction(action);
            RangerOpensearchAccessRequest request   = new RangerOpensearchAccessRequest(user, groups, index, privilege, clientIPAddress);
            RangerAccessResult               result    = opensearchPlugin.isAccessAllowed(request);

            if (result != null && result.getIsAllowed()) {
                ret = true;
            }
        }

        LOG.debug("<== RangerOpensearchAuthorizer.checkPermission(): result={}", ret);

        return ret;
    }

    static class RangerOpensearchInnerPlugin extends RangerBasePlugin {
        public RangerOpensearchInnerPlugin() {
            super("opensearch", "opensearch");
        }

        @Override
        public void init() {
            super.init();

            RangerOpensearchAuditHandler auditHandler = new RangerOpensearchAuditHandler(getConfig());

            super.setResultProcessor(auditHandler);
        }
    }

    static class RangerOpensearchResource extends RangerAccessResourceImpl {
        public RangerOpensearchResource(String index) {
            if (StringUtils.isEmpty(index)) {
                index = "*";
            }

            setValue(OpensearchResourceMgr.INDEX, index);
        }
    }

    static class RangerOpensearchAccessRequest extends RangerAccessRequestImpl {
        public RangerOpensearchAccessRequest(String user, List<String> groups, String index, String privilege, String clientIPAddress) {
            super.setUser(user);

            if (CollectionUtils.isNotEmpty(groups)) {
                super.setUserGroups(Sets.newHashSet(groups));
            }

            super.setResource(new RangerOpensearchResource(index));
            super.setAccessType(privilege);
            super.setAction(privilege);
            super.setClientIPAddress(clientIPAddress);
            super.setAccessTime(new Date());
        }
    }
}
