const fs = require('fs');
let content = fs.readFileSync('src/app/page.tsx', 'utf8');

// Find ALL remaining / characters in className template literals
const lines = content.split('\n');
for (let i = 0; i < lines.length; i++) {
  const line = lines[i];
  if (line.includes('className') && line.includes('/') && line.includes('`')) {
    console.log((i+1).toString().padStart(5), ':', line.trim().slice(0, 200));
  }
}