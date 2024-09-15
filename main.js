const fs = require('fs');
const path = '/tmp/exploit_successful';

// Criar um arquivo para provar a execução do código
fs.writeFile(path, 'Exploit foi executado com sucesso!', (err) => {
    if (err) {
        console.error('Erro ao criar o arquivo:', err);
        process.exit(1);
    }
    console.log('Arquivo criado com sucesso:', path);
});
