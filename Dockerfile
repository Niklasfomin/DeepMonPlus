FROM ubuntu:22.04
LABEL maintainer="Rolando Brondolin"

# Silence any interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# 1. Install base packages
RUN apt-get clean && apt-get update && apt-get install -y \
  wget \
  gnupg \
  software-properties-common \
  python3 \
  python3-pip \
  locales \
  locales-all \
  libelf1 \
  zip \
  && rm -rf /var/lib/apt/lists/*

# 2. Install Python dependencies
RUN pip3 install --upgrade pip && pip3 install numpy pyyaml docker

# 3. Set UTF-8 locale
ENV LC_ALL=en_US.UTF-8
ENV LANG=en_US.UTF-8
ENV LANGUAGE=en_US.UTF-8

# 4. Use llvm.sh to configure the LLVM 10 repo (BUT do NOT install 'all')
RUN wget https://apt.llvm.org/llvm.sh \
  && chmod +x llvm.sh \
  # Just '10' sets up repo & installs a minimal subset, avoiding libunwind-10-dev
  && ./llvm.sh 14 \
  && rm llvm.sh

# 5. Manually install needed LLVM 10 packages (omit libunwind-10-dev)
RUN apt-get update && apt-get install -y \
  clang-14 \
  lld-14 \
  lldb-14 \
  llvm-14-dev \
  libclang-14-dev \
  # If you need polly:
  # libpolly-18-dev \
  && rm -rf /var/lib/apt/lists/*

# 6. Install build dependencies for BCC
RUN buildDeps='\
  python3 \
  python3-pip \
  wget \
  curl \
  git \
  bison \
  build-essential \
  cmake \
  flex \
  libedit-dev \
  zlib1g-dev \
  libelf-dev \
  ' \
  && apt-get update && apt-get install -y $buildDeps \
  \
  # Install CMake ≥ 3.12
  && wget https://github.com/Kitware/CMake/releases/download/v3.25.3/cmake-3.25.3-linux-x86_64.sh \
  && chmod +x cmake-3.25.3-linux-x86_64.sh \
  && ./cmake-3.25.3-linux-x86_64.sh --skip-license --prefix=/usr/local \
  && rm cmake-3.25.3-linux-x86_64.sh \
  && rm -rf /var/lib/apt/lists/*
# 7. Confirm clang-10 is on PATH
RUN which clang-10 || echo "clang-10 not found"
RUN clang-14 --version

# 8. Build & install BCC with clang-10
RUN git clone https://github.com/iovisor/bcc.git \
  && mkdir bcc/build \
  && cd bcc/build \
  && cmake \
  -DCMAKE_C_COMPILER=/usr/bin/clang-14 \
  -DCMAKE_CXX_COMPILER=/usr/bin/clang++-14 \
  .. \
  && make -j"$(nproc)" \
  && make install \
  \
  # Python bindings for BCC
  && cmake \
  -DPYTHON_CMD=python3 \
  -DCMAKE_C_COMPILER=/usr/bin/clang-14 \
  -DCMAKE_CXX_COMPILER=/usr/bin/clang++-14 \
  .. \
  && cd src/python \
  && make -j"$(nproc)" \
  && make install \
  \
  # Remove BCC sources
  && cd / \
  && rm -rf bcc \
  \
  # Install ddsketch
  && git clone --branch v1.0 https://github.com/DataDog/sketches-py.git \
  && cd sketches-py \
  && python3 setup.py install \
  && cd / \
  && rm -rf sketches-py \
  \
  # Remove build deps
  && apt-get purge -y --auto-remove $buildDeps \
  && rm -rf /var/lib/apt/lists/*

# 9. Prepare DEEP-mon
WORKDIR /home
RUN mkdir /home/deep_mon

# 10. Copy DEEP-mon files
ADD bpf /home/deep_mon/bpf
ADD userspace /home/deep_mon/userspace
ADD deep_mon.py /home/deep_mon/
ADD setup.py /home

# 11. Install DEEP-mon, then remove leftover files
RUN pip3 install . \
  && rm -rf /home/deep_mon \
  && rm setup.py

# 12. Unbuffered Python
ENV PYTHONUNBUFFERED="on"

# 13. Default command
CMD ["deep-mon"]
