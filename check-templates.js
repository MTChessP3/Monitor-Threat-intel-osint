const fs = require('fs');
let content = fs.readFileSync('src/app/page.tsx', 'utf8');

// Look for template literals with /
const lines = content.split('\n');
let inTemplate = false;
for (let i = 0; i < lines.length; i++) {
  const line = lines[i];
  const backticks = (line.match(/`/g) || []).length;
  if (backticks % 2 === 1) {
    inTemplate = !inTemplate;
  }
  if (inTemplate && line.includes('/')) {
    console.log((i+1).toString().padStart(5), ':', line.trim().slice(0, 200));
  }
}