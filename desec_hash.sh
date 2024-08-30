#!/bin/bash


# Loop para ler o arquivo password.txt, aplicar MD5, Base64 e SHA1
while IFS= read -r line; do
    # Gera o hash MD5
    md5=$(echo -n "$line" | md5sum | awk '{print $1}')
    
    # Codifica em Base64
    base64_encoded=$(echo -n "$md5" | base64)
    
    # Gera o hash SHA1
    sha1=$(echo -n "$base64_encoded" | sha1sum | awk '{print $1}')
    
    # Verifica se o hash gerado corresponde ao fornecido
    if [[ "$sha1" == "806825f0827b628e81620f0d83922fb2c52c7136" ]]; then
        echo "Senha encontrada: $line"
        exit 0
    fi
done < password.lst

echo "Senha não encontrada na wordlist."
