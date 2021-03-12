# Copyright (c) 2018 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM eu.gcr.io/gardenlinux/gardenlinux:184.0 AS builder

# wireguard-tools
RUN apt-get update && apt-get install -y build-essential git make curl ca-certificates && \
    git clone git://git.zx2c4.com/wireguard-tools && cd  /wireguard-tools/src && make

# userspace wireguard daemon
RUN curl -o go1.16.1.linux-amd64.tar.gz  https://dl.google.com/go/go1.16.1.linux-amd64.tar.gz && \
    tar xfz go1.16.1.linux-amd64.tar.gz && export GOPATH=/go && export PATH=$GOPATH/bin:$PATH && \
    git clone git://git.zx2c4.com/wireguard-go && \
    cd wireguard-go && git checkout tags/0.0.20210212 -b rel && make

#FROM alpine:3.13.2
FROM eu.gcr.io/gardenlinux/gardenlinux:184.0

COPY --from=builder /wireguard-tools/src/wg /usr/bin
COPY --from=builder /wireguard-tools/src/wg-quick/linux.bash /usr/bin/wg-quick
COPY --from=builder /wireguard-go/wireguard-go /usr/bin
RUN apt-get update && apt-get install -y bc iptables iproute2 openvpn

ADD shoot/network-connection.sh shoot/openvpn.config.template /

EXPOSE 1194

# We use "exec" and "trap 'exit' TERM" in the bash script, otherwise,
# the script won't recieve and react to SIGTERM
CMD exec /network-connection.sh
