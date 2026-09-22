const fs = require('fs');
let content = fs.readFileSync('src/app/page.tsx', 'utf8');
const lines = content.split('\n');

// Fix division-like patterns in template literals within generatePrintableReport function
// (roughly lines 262-1015)
// Pattern: ${something}/${something} -> ${something + '/' + something}

// We'll only process lines in the generatePrintableReport function
// which is roughly between lines 262 and 1015

for (let i = 261; i < 1015; i++) {
  const line = lines[i];
  if (line.includes('`') && line.includes('/')) {
    // Replace ${...}/${...} with ${... + '/' + ...}
    // This regex matches ${...}/${...} where ... doesn't contain }
    let newLine = line.replace(
      /\$\{([^}]+)\}\/\$\{([^}]+)\}/g,
      '${$1 + \'/\' + $2}'
    );
    
    // Also handle ${...}/number patterns
    newLine = newLine.replace(
      /\$\{([^}]+)\}\/(\d+)/g,
      '${$1 + \'/$2\'}'
    );
    
    if (newLine !== line) {
      lines[i] = newLine;
      console.log(`Fixed line ${i+1}: ${newLine.trim().slice(0, 150)}`);
    }
  }
}

fs.writeFileSync('src/app/page.tsx', lines.join('\n'));
console.log('Fixed division patterns in printable report');