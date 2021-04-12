#!/bin/bash
pipcmd=pip3
pythoncmd=python3

#check python3
if ! command -v $pythoncmd &> /dev/null; then
    echo -e "\e[91m[getkeys] Instalando python...\e[39m"
    sudo apt install python3
fi


#check pip3
if ! command -v $pipcmd &> /dev/null; then
    echo -e "\e[91m[getkeys] Instalando pip3\e[39m"
    sudo apt install pip3
fi

#check pip dependencies
if ! $pipcmd list --disable-pip-version-check | grep -F requests &> /dev/null; then
    echo -e "\e[91m[getkeys] Instalando bitwarden\e[39m"
    $pipcmd install -r requirements.txt
fi
