FROM docker.io/library/ubuntu@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac
ENV DEBIAN_FRONTEND=noninteractive TZ=UTC LANG=C.UTF-8
LABEL guacamole.ssh-fixture.endpoint="1"
COPY --chmod=0644 bootstrap-ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
RUN printf 'Acquire::https::CaInfo "/etc/ssl/certs/ca-certificates.crt";\n' >/etc/apt/apt.conf.d/99-bootstrap-ca && \
    printf '#!/bin/sh\nexit 101\n' >/usr/sbin/policy-rc.d && chmod 755 /usr/sbin/policy-rc.d && \
    sed -i 's|http://archive.ubuntu.com/ubuntu/|https://snapshot.ubuntu.com/ubuntu/20261108T000000Z/|g; s|http://security.ubuntu.com/ubuntu/|https://snapshot.ubuntu.com/ubuntu/20261108T000000Z/|g' /etc/apt/sources.list.d/ubuntu.sources && \
    apt-get -o Acquire::Check-Valid-Until=false -o APT::Update::Error-Mode=any update && \
    apt-get install -y --no-install-recommends ca-certificates openssh-server openssh-client tmux python3 && \
    rm -f /etc/ssh/ssh_host_* && mkdir /run/sshd && \
    dpkg-query -W -f='${Package}\t${Version}\n' >/fixture-packages.tsv && \
    rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["sleep","400"]
