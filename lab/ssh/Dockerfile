# Builds an OpenSSH server that allows password login and two weak algorithms, for the SSH checks.
FROM alpine:3.23@sha256:469c9ea410b9215eaee7976ba6c0639039b444be8e5d638f7abbada189971eb2
# The version isn't pinned, so a new Alpine OpenSSH build changes the version Nmap reports.
RUN apk add --no-cache openssh-server && ssh-keygen -A
COPY sshd_config /etc/ssh/lab_sshd_config
ENTRYPOINT ["/usr/sbin/sshd", "-D", "-e", "-f", "/etc/ssh/lab_sshd_config"]
