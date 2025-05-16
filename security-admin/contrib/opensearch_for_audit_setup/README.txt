# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

This folder consists of the scripts required to install and configure
Opensearch as an audit destination/source for Apache Ranger.

Scripts:
1. install_os.sh - Downloads and installs the basic single-node opensearch server
2. sudo enable_auth.sh - Configures opensearch to use password authentication
3. create_index.sh - Creates and configures the index
