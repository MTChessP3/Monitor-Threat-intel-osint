const fs = require('fs');
let content = fs.readFileSync('src/app/page.tsx', 'utf8');
const lines = content.split('\n');

// Check lines 4047-4095 for template literals
for (let i = 4046; i < 4095; i++) {
  if (lines[i].includes('`')) {
    console.log((i+1).toString().padStart(5), ':', lines[i].trim().slice(0, 200));
  }
}