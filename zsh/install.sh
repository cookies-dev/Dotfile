#!/bin/sh

sudo apt update
sudo apt upgrade
sudo apt-get install zsh keychain bat -y
curl -sL --proto-redir -all,https https://raw.githubusercontent.com/zplug/installer/master/installer.zsh | zsh
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.5/install.sh | bash
curl https://raw.githubusercontent.com/cookies-dev/Dotfile/main/zsh/.p10k.zsh -o ~/.p10k.zsh
curl https://raw.githubusercontent.com/cookies-dev/Dotfile/main/zsh/.zshrc -o ~/.zshrc
sh -c "$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
