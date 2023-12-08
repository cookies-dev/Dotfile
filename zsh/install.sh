#!/bin/sh

sudo apt update
sudo apt install curl git

# docker certif
sudo apt-get install ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo \
  "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  "$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# install zsh, keychain, batcat, python3, docker (cli, compose, plugin)
sudo apt update
sudo apt upgrade
sudo apt-get install zsh keychain bat python3-dev python3-pip python3-setuptools -y
# sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# docker group & permission
# sudo groupadd docker
# sudo usermod -aG docker $USER
# newgrp docker

# the fuck
pip3 install thefuck --user

# zplug
curl -sL --proto-redir -all,https https://raw.githubusercontent.com/zplug/installer/master/installer.zsh | zsh

# nvm
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.5/install.sh | bash
nvm install node
nvm use node

# atuin
bash <(curl https://raw.githubusercontent.com/atuinsh/atuin/main/install.sh)

# curl default config
curl https://raw.githubusercontent.com/cookies-dev/Dotfile/main/zsh/.p10k.zsh -o ~/.p10k.zsh
curl https://raw.githubusercontent.com/cookies-dev/Dotfile/main/zsh/.zshrc -o ~/.zshrc

# install ohmyzsh
sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended --keep-zshrc
