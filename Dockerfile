FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive

# Essential packages only
RUN apt-get update && apt-get install -y \
    openssh-server \
    sudo \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Setup SSH
RUN mkdir /var/run/sshd && \
    chmod 0755 /var/run/sshd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Create student user
RUN useradd -m -s /bin/bash student && \
    echo "student:student" | chpasswd && \
    adduser student sudo && \
    echo "student ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Copy and extract MySecretNotes.zip
COPY MySecretNotes.zip /home/student/
RUN unzip /home/student/MySecretNotes.zip -d /home/student/ && \
    chown -R student:student /home/student/MySecretNotes* && \
    rm /home/student/MySecretNotes.zip

# Setup startup script
COPY startup.sh /
RUN chmod +x /startup.sh

CMD ["/startup.sh"]
