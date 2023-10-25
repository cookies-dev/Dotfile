typeset -g POWERLEVEL9K_INSTANT_PROMPT=quiet
typeset -g POWERLEVEL9K_INSTANT_PROMPT=off

if [[ -r "${XDG_CACHE_HOME:-$HOME/.cache}/p10k-instant-prompt-${(%):-%n}.zsh" ]]; then
  source "${XDG_CACHE_HOME:-$HOME/.cache}/p10k-instant-prompt-${(%):-%n}.zsh"
fi

export ZSH="/home/maxim/.oh-my-zsh"
export NVM_DIR="$HOME/.nvm"
export MANPATH=$HOME/tools/ripgrep/doc/man:$MANPATH
export FPATH=$HOME/tools/ripgrep/complete:$FPATH
export GO111MODULE=on
export PATH="$HOME/.local/bin:$PATH"

[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"                   # This loads nvm
[ -s "$NVM_DIR/bash_completion" ] && \. "$NVM_DIR/bash_completion" # This loads nvm bash_completion
[[ -r ~/Repos/znap/znap.zsh ]] || git clone --depth 1 -- https://github.com/marlonrichert/zsh-snap.git ~/Repos/znap
[ -f "/home/maxim/.ghcup/env" ] && source "/home/maxim/.ghcup/env" # ghcup-env
[[ ! -f ~/.p10k.zsh ]] || source ~/.p10k.zsh

source ~/.zplug/init.zsh && zplug update > /dev/null
source $ZSH/oh-my-zsh.sh
source ~/Repos/znap/znap.zsh

eval $(keychain --eval id_rsa_git)
eval "$(atuin init zsh)"
eval $(thefuck --alias fuck)
eval $(thefuck --alias f)

zplug romkatv/powerlevel10k, as:theme, depth:1
zplug "plugins/git", from:oh-my-zsh
zplug "zsh-users/zsh-syntax-highlighting", defer:2
zplug "supercrabtree/k"
zplug "zsh-users/zsh-autosuggestions"
zplug "zsh-users/zsh-completions"

if ! zplug check --verbose; then
  printf "Install? [y/N]: "
  if read -q; then
    echo
    zplug install
  fi
fi

zplug load

ZSH_THEME="powerlevel10k/powerlevel10k"

plugins=(git git-auto-fetch gitfast node npm python zsh-autosuggestions zsh-syntax-highlighting k zsh-completions command-not-found zsh-interactive-cd)

# znap source marlonrichert/zsh-autocomplete
autoload -U compinit && compinit

alias sai="sudo apt-get install"
alias g="git"
alias ga="git add"
alias gcm="git commit -m"
alias gs="git switch"
alias gp="git push"
alias gpl="git pull"
alias gs="git status"
alias gd="git diff"
alias gnd="git --no-pager diff"
alias gr="git reset --hard HEAD"
alias -g G="| grep"
alias -g H="| head"
alias -g T="| tail"
alias -g L="| less"
alias -g M="| more"
alias -g C="| cat"
alias -g S="| sort"
alias -g R="| uniq"
alias -g P="| grep -i"
# alias epi="gh repo list EpitechPromo2026 -L 200 | grep "
alias cat="batcat --paging=never"
alias cato="/bin/cat"
# alias style="coding-style.sh . . && cat coding-style-reports.log && rm -f coding-style-reports.log"
# alias clone="~/.clone.sh"
alias sudo='sudo '
alias u='sudo '

autoload -U add-zsh-hook
load-nvmrc() {
  local nvmrc_path="$(nvm_find_nvmrc)"

  if [ -n "$nvmrc_path" ]; then
    local nvmrc_node_version=$(nvm version "$(cat "${nvmrc_path}")")

    if [ "$nvmrc_node_version" = "N/A" ]; then
      nvm install
    elif [ "$nvmrc_node_version" != "$(nvm version)" ]; then
      nvm use
    fi
  elif [ -n "$(PWD=$OLDPWD nvm_find_nvmrc)" ] && [ "$(nvm version)" != "$(nvm version default)" ]; then
    echo "Reverting to nvm default version"
    nvm use default
  fi
}
add-zsh-hook chpwd load-nvmrc
load-nvmrc
