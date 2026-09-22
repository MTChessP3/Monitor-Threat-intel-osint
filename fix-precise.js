const fs = require('fs');
let content = fs.readFileSync('src/app/page.tsx', 'utf8');

// First, fix dynamic color patterns: hover:border-${color}-500/50 -> hover:border-${color}-500_50
// The key is to NOT consume the ${color} part
content = content.replace(
  /(hover:border|hover:bg|hover:text|focus:border|focus:bg|focus:text)-\$\{color\}-(\d+)\/(\d+)/g,
  '$1-${color}-$2_$3'
);

// Then fix static patterns: bg-red-500/20 -> bg-red-500_20
// Match color-name-NUM/NUM where color-name is a known tailwind color
const tailwindColors = [
  'slate', 'gray', 'zinc', 'neutral', 'stone',
  'red', 'orange', 'amber', 'yellow', 'lime',
  'green', 'emerald', 'teal', 'cyan', 'sky',
  'blue', 'indigo', 'violet', 'purple', 'fuchsia',
  'pink', 'rose'
];

const colorPattern = tailwindColors.join('|');
const staticRegex = new RegExp(`(bg|border|text|from|to|hover:bg|hover:border|focus:bg|focus:border|hover:text|focus:text|dark:bg|dark:border|dark:text)-(${colorPattern})-(\\d+)\\/(\\d+)`, 'g');

content = content.replace(staticRegex, '$1-$2-$3_$4');

fs.writeFileSync('src/app/page.tsx', content);
console.log('Fixed all opacity syntax');