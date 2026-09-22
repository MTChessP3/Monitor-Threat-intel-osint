const fs = require('fs');
let content = fs.readFileSync('src/app/page.tsx', 'utf8');

// Fix division-like patterns in template literals within generatePrintableReport function
// More comprehensive regex to catch ${...}/${...} and ${...}/N patterns

// Fix ${...}/${...} patterns
content = content.replace(
  /\$\{([^}]+)\}\s*\/\s*\$\{([^}]+)\}/g,
  '${$1 + \'/\' + $2}'
);

// Fix ${...}/number patterns
content = content.replace(
  /\$\{([^}]+)\}\s*\/\s*(\d+)/g,
  '${$1 + \'/$2\'}'
);

// Fix number/${...} patterns
content = content.replace(
  /(\d+)\s*\/\s*\$\{([^}]+)\}/g,
  '${$1 + \'/\' + $2}'
);

fs.writeFileSync('src/app/page.tsx', content);
console.log('Fixed all division patterns in printable report');