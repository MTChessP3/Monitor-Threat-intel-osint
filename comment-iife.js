const fs = require('fs');
let content = fs.readFileSync('src/app/page.tsx', 'utf8');
const lines = content.split('\n');

// Find and comment out the IIFE at lines 4047-4095
// The IIFE starts with {(() => { and ends with })()}

let inIIFE = false;
let startLine = -1;
let braceCount = 0;
let parenCount = 0;

for (let i = 0; i < lines.length; i++) {
  const line = lines[i];
  
  // Look for the start of the IIFE: {(() => {
  if (!inIIFE && line.includes('{(() => {')) {
    inIIFE = true;
    startLine = i;
    // Count braces and parens
    for (const ch of line) {
      if (ch === '{') braceCount++;
      else if (ch === '}') braceCount--;
      else if (ch === '(') parenCount++;
      else if (ch === ')') parenCount--;
    }
    continue;
  }
  
  if (inIIFE) {
    for (const ch of lines[i]) {
      if (ch === '{') braceCount++;
      else if (ch === '}') braceCount--;
      else if (ch === '(') parenCount++;
      else if (ch === ')') parenCount--;
    }
    
    // The IIFE ends when both braceCount and parenCount return to 0
    // The pattern is {(() => { ... })()}
    // So we need braceCount === 1 (for the outer {) and parenCount === 0 (for the (() => {})())
    if (braceCount === 1 && parenCount === 0) {
      // Check if this line ends the IIFE
      if (lines[i].includes('})()}')) {
        // Comment out the entire IIFE
        for (let j = startLine; j <= i; j++) {
          lines[j] = '// ' + lines[j];
        }
        console.log(`Commented out IIFE (lines ${startLine+1}-${i+1})`);
        break;
      }
    }
  }
}

fs.writeFileSync('src/app/page.tsx', lines.join('\n'));
console.log('Commented out IIFE');