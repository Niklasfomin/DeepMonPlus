#!/bin/bash

set -e  # Exit on error
export DEBIAN_FRONTEND=noninteractive

echo "Updating package list and installing dependencies..."
sudo apt-get clean
sudo apt-get update
sudo apt-get install -y \
  wget \
  gnupg \
  software-properties-common \
  python3 \
  python3-pip \
  locales \
  locales-all \
  libelf1 \
  zip \
  git \
  bison \
  build-essential \
  cmake \
  flex \
  libedit-dev \
  zlib1g-dev \
  libelf-dev

echo "Setting up UTF-8 locale..."
export LC_ALL=en_US.UTF-8
export LANG=en_US.UTF-8
export LANGUAGE=en_US.UTF-8

echo "Installing Python dependencies..."
pip3 install --upgrade pip
pip3 install numpy pyyaml docker

echo "Downloading and installing LLVM 10..."
wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh 10
rm llvm.sh

echo "Installing LLVM 10 packages..."
sudo apt-get update
sudo apt-get install -y \
  clang-10 \
  lld-10 \
  lldb-10 \
  llvm-10-dev \
  libclang-10-dev

echo "Verifying clang installation..."
which clang-10 || echo "clang-10 not found"
clang-10 --version

echo "Cloning and installing BCC..."

if [ ! -d "bcc" ]; then
    git clone https://github.com/iovisor/bcc.git
else
    echo "BCC repository already exists, skipping clone..."
fi
if [ ! -d "bcc/build" ]; then
    mkdir -p bcc/build
    cd bcc/build
    cmake -DCMAKE_C_COMPILER=/usr/bin/clang-10 -DCMAKE_CXX_COMPILER=/usr/bin/clang++-10 ..
    make -j"$(nproc)"
    sudo make install
    cd ../..
else
    echo "BCC build directory already exists, skipping build..."
fi
# mkdir bcc/build
# cd bcc/build
# cmake -DCMAKE_C_COMPILER=/usr/bin/clang-10 -DCMAKE_CXX_COMPILER=/usr/bin/clang++-10 ..
# make -j"$(nproc)"
# sudo make install
# cmake -DPYTHON_CMD=python3 -DCMAKE_C_COMPILER=/usr/bin/clang-10 -DCMAKE_CXX_COMPILER=/usr/bin/clang++-10 ..
# cd src/python
# make -j"$(nproc)"
# sudo make install
# cd ../../..
sudo chown -R $(whoami):$(whoami) bcc/build
rm -rf bcc

echo "Installing DataDog ddsketch..."
git clone --branch v1.0 https://github.com/DataDog/sketches-py.git
cd sketches-py
# python3 setup.py install
python3 -m venv myenv
source myenv/bin/activate
pip3 install --upgrade pip setuptools wheel
pip install .
cd ..
rm -rf sketches-py

echo "Setting up DEEP-mon..."
# mkdir -p /home/deep_mon
sudo chown $(whoami):$(whoami) ~/dev/
mkdir -p ~/dev/deep_mon
cp -r bpf ~/dev/deep_mon/bpf
cp -r userspace ~/dev/deep_mon/userspace
cp deep_mon.py ~/dev/deep_mon/
cp setup.py ~/dev/deep_mon/

echo "Installing DEEP-mon..."
pip3 install .
rm -rf /home/deep_mon
rm setup.py

echo "Setup complete. You can now run 'deep-mon'."