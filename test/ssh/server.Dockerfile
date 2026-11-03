# 模拟一台 Debian 服务器：systemd + sshd + 按 deploy/ 部署的 xgate。
FROM debian:stable-slim
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      systemd systemd-sysv openssh-server nftables conntrack curl iproute2 procps \
 && rm -rf /var/lib/apt/lists/*
COPY deploy/xgate.sysusers /usr/lib/sysusers.d/xgate.conf
# 先显式创建 /etc/xgate：COPY --chmod 自动创建父目录时会把同样的 0640 用在目录上，目录就无法进入了。
RUN systemd-sysusers && install -d -m 0755 /etc/xgate
COPY out/xgate /usr/local/bin/xgate
COPY deploy/xgate.service /etc/systemd/system/xgate.service
COPY --chown=root:xgate --chmod=0640 test/ssh/config.yaml /etc/xgate/config.yaml
RUN systemctl enable ssh xgate \
 && install -d -m 0700 /root/.ssh
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
