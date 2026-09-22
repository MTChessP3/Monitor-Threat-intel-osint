const fs = require('fs');
let content = fs.readFileSync('src/app/page.tsx', 'utf8');

// Find the generatePrintableReport function and comment it out
// It starts around line 262 and ends before openPrintReport at line 1016

const lines = content.split('\n');
let inFunction = false;
let functionStart = -1;
let braceCount = 0;

for (let i = 0; i < lines.length; i++) {
  const line = lines[i];
  
  // Look for the function start
  if (!inFunction && line.includes('function generatePrintableReport')) {
    inFunction = true;
    functionStart = i;
    braceCount = 0;
    // Count opening braces in this line
    for (const ch of line) {
      if (ch === '{') braceCount++;
      else if (ch === '}') braceCount--;
    }
    continue;
  }
  
  if (inFunction) {
    for (const ch of line) {
      if (ch === '{') braceCount++;
      else if (ch === '}') braceCount--;
    }
    
    if (braceCount === 0) {
      // Function ended, comment out the entire function
      for (let j = functionStart; j <= i; j++) {
        lines[j] = '// ' + lines[j];
      }
      console.log(`Commented out generatePrintableReport function (lines ${functionStart+1}-${i+1})`);
      break;
    }
  }
}

fs.writeFileSync('src/app/page.tsx', lines.join('\n'));
console.log('Commented out generatePrintableReport function');