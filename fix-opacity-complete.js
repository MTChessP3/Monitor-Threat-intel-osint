const fs = require('fs');
let content = fs.readFileSync('src/app/page.tsx', 'utf8');

// Fix 1: Static opacity patterns like bg-red-500/20, border-blue-400/30, etc.
// Pattern: color-name-NUM/NUM (but not when it's a variable like ${color})
content = content.replace(
  /(bg|border|text|from|to|hover:bg|hover:border|focus:bg|focus:border|hover:text)-([a-z]+)-(\d+)\/(\d+)/g,
  '$1-$2-$3_$4'
);

// Fix 2: Dynamic color patterns like hover:border-${color}-500/50
// These have ${color} variable inside template literal
content = content.replace(
  /(hover:border|hover:bg|hover:text|focus:border|focus:bg|focus:text)-\$\{color\}-(\d+)\/(\d+)/g,
  '$1-${color}-$2_$3'
);

// Fix 3: Other static patterns with opacity in className
content = content.replace(
  /(bg|border|text)-([a-z]+)-(\d+)\/(\d+)(?=[^a-zA-Z0-9_])/g,
  '$1-$2-$3_$4'
);

fs.writeFileSync('src/app/page.tsx', content);
console.log('Fixed all opacity syntax patterns');