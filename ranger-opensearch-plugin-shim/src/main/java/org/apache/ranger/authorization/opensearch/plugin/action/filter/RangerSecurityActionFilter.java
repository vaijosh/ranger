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

package org.apache.ranger.authorization.opensearch.plugin.action.filter;

import org.apache.commons.lang.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.ranger.authorization.opensearch.authorizer.RangerOpensearchAuthorizer;
import org.apache.ranger.authorization.opensearch.plugin.RangerOpensearchPlugin;
import org.apache.ranger.authorization.opensearch.plugin.utils.RequestUtils;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.support.ActionFilter;
import org.opensearch.action.support.ActionFilterChain;
import org.opensearch.common.lifecycle.AbstractLifecycleComponent;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;

import java.util.Base64;
import java.util.List;

public class RangerSecurityActionFilter extends AbstractLifecycleComponent implements ActionFilter {
    private static final Logger LOG = LogManager.getLogger(RangerOpensearchPlugin.class);
    private final ThreadPool                 threadPool;
    private final RangerOpensearchAuthorizer rangerOpensearchAuthorizer = new RangerOpensearchAuthorizer();

    public RangerSecurityActionFilter(ThreadPool threadPool) {
        super();

        this.threadPool = threadPool;
    }

    @Override
    public int order() {
        return 0;
    }


    @Override
    public <Request extends ActionRequest, Response extends ActionResponse> void apply(Task task, String action, Request request, ActionListener<Response> listener, ActionFilterChain<Request, Response> chain) {
        String user = org.apache.logging.log4j.ThreadContext.get("user");

        // If user is not null, then should check permission of the outside caller.
        if (StringUtils.isNotEmpty(user)) {
            List<String> indexs          = RequestUtils.getIndexFromRequest(request);
            String       clientIPAddress = threadPool.getThreadContext()
                    .getTransient("_opendistro_security_remote_address").toString();

            for (String index : indexs) {
                boolean result = rangerOpensearchAuthorizer.checkPermission(user, null, index, action, clientIPAddress);

                if (!result) {
                    String errorMsg = "Error: User[{}] could not do action[{}] on index[{}]";
                    throw new OpenSearchStatusException(errorMsg, RestStatus.FORBIDDEN, user, action, index);
                }
            }
        } else {
            LOG.debug("User is null, no check permission for opensearch do action[{}] with request[{}]", action, request);
        }

        chain.proceed(task, action, request, listener);
    }

    @Override
    protected void doStart() {
    }

    @Override
    protected void doStop() {
    }

    @Override
    protected void doClose() {
    }
}
