const fs = require('fs');
let content = fs.readFileSync('src/app/page.tsx', 'utf8');
const lines = content.split('\n');

// Find all className template literals
for (let i = 0; i < lines.length; i++) {
  const line = lines[i];
  if (line.includes('className={`')) {
    // Check for any / in the template literal
    const backticks = (line.match(/`/g) || []).length;
    if (backticks > 0 && line.includes('/')) {
      console.log((i+1).toString().padStart(5), ':', line.trim().slice(0, 200));
    }
  }
}