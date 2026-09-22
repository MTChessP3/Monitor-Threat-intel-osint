const fs = require('fs');
let content = fs.readFileSync('src/app/page.tsx', 'utf8');
const lines = content.split('\n');

// Check lines 410-650 for remaining division patterns
for (let i = 410; i < 650; i++) {
  const line = lines[i];
  if (line.includes('/') && line.includes('${')) {
    console.log((i+1).toString().padStart(5), ':', line.trim().slice(0, 200));
  }
}