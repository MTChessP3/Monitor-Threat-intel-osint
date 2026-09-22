const fs = require('fs');
let content = fs.readFileSync('src/app/page.tsx', 'utf8');
const lines = content.split('\n');

// Check the generatePrintableReport function (around line 260)
for (let i = 260; i < 500; i++) {
  const line = lines[i];
  if (line.includes('`') && line.includes('/')) {
    console.log((i+1).toString().padStart(5), ':', line.trim().slice(0, 200));
  }
}