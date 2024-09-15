const { exec } = require('child_process');
exec('whoami', (err, stdout, stderr) => {
    if (err) {
        console.error(`Error: ${err.message}`);
        return;
    }
    console.log(`User: ${stdout}`);
});
