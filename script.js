const bcrypt = require('bcrypt');

async function generateHashedPasswords() {
  const users = ['adminpassword', 'agentpassword', 'userpassword'];

  for (const pass of users) {
    const hash = await bcrypt.hash(pass, 10);
    console.log(`Password: ${pass} => Hash: ${hash}`);
  }
}

generateHashedPasswords();
