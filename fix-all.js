const fs = require('fs');
let content = fs.readFileSync('src/app/page.tsx', 'utf8');

// Fix all Tailwind opacity syntax in JSX template literals (className={`...`})
// This regex matches patterns like bg-red-500/20, border-blue-400/30, text-green-600/10, etc.
// within backtick template literals used in className

// First, let's fix the static patterns
const patterns = [
  // bg-color-NUM/NUM
  /(bg|border|text|from|to|hover:bg|hover:border|focus:bg|focus:border|hover:text|focus:text|dark:bg|dark:border|dark:text)-([a-z]+)-(\d+)\/(\d+)/g,
  // bg-${color}-NUM/NUM (dynamic)
  /(bg|border|text|hover:bg|hover:border|hover:text|focus:bg|focus:border|focus:text)-\$\{color\}-(\d+)\/(\d+)/g,
];

let totalReplacements = 0;
for (const pattern of patterns) {
  content = content.replace(pattern, (match, prefix, color, num1, num2) => {
    totalReplacements++;
    return `${prefix}-${color}-${num1}_${num2}`;
  });
}

console.log(`Total replacements: ${totalReplacements}`);

fs.writeFileSync('src/app/page.tsx', content);
console.log('Fixed all opacity syntax');