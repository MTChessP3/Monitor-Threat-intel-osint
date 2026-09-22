const fs = require('fs');
let content = fs.readFileSync('src/app/page.tsx', 'utf8');
const lines = content.split('\n');

let inTemplate = false;
for (let i = 0; i < lines.length; i++) {
  const line = lines[i];
  const backticks = (line.match(/`/g) || []).length;
  if (backticks % 2 === 1) {
    inTemplate = !inTemplate;
  }
  if (!inTemplate && line.includes('/')) {
    // Check if it looks like division
    if (line.match(/[a-zA-Z0-9_)]\s*\/\s*[a-zA-Z0-9_(]/)) {
      console.log((i+1).toString().padStart(5), ':', line.trim().slice(0, 200));
    }
  }
}