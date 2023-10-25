#!/bin/sh

sudo apt update
sudo apt upgrade
sudo apt-get install zsh keychain bat python3-dev python3-pip python3-setuptools -y

# the fuck
pip3 install thefuck --user

# zplug
curl -sL --proto-redir -all,https https://raw.githubusercontent.com/zplug/installer/master/installer.zsh | zsh

# nvm
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.5/install.sh | bash

# atuin
bash <(curl https://raw.githubusercontent.com/atuinsh/atuin/main/install.sh)

# curl default config
curl https://raw.githubusercontent.com/cookies-dev/Dotfile/main/zsh/.p10k.zsh -o ~/.p10k.zsh
curl https://raw.githubusercontent.com/cookies-dev/Dotfile/main/zsh/.zshrc -o ~/.zshrc

# install ohmyzsh
sh -c "$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
