const fs = require('fs');
const path = require('path');

// Caminho para o arquivo que você deseja ler
const filePath = path.join(__dirname, 'flag.txt');

// Ler o conteúdo do arquivo
fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
        console.error('Error reading file:', err);
        return;
    }
    console.log('File content:', data);
});