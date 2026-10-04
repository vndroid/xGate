# 模拟一台 Debian 服务器：systemd + sshd + 按 deploy/ 部署的 xgate。
FROM debian:stable-slim
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      systemd systemd-sysv openssh-server nftables conntrack curl iproute2 procps \
 && rm -rf /var/lib/apt/lists/*
COPY out/xgate /usr/local/bin/xgate
COPY deploy/xgate.service /etc/systemd/system/xgate.service
COPY test/ssh/config.yaml /etc/xgate/config.yaml
RUN systemctl enable ssh xgate \
 && install -d -m 0700 /root/.ssh
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
