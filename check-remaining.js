const fs = require('fs');
let content = fs.readFileSync('src/app/page.tsx', 'utf8');

// Check for any remaining opacity patterns
const staticRegex = /(bg|border|text|from|to|hover:bg|hover:border|focus:bg|focus:border|hover:text|focus:text|dark:bg|dark:border|dark:text)-([a-z]+)-(\d+)\/(\d+)/g;
const matches = content.match(staticRegex);
if (matches) {
  console.log('Remaining static patterns:', matches.length);
  console.log([...new Set(matches)].slice(0, 20));
} else {
  console.log('No static patterns found');
}

// Check dynamic patterns
const dynamicRegex = /(hover:border|hover:bg|hover:text|focus:border|focus:bg|focus:text)-\${color}-(\d+)\/(\d+)/g;
const dynamicMatches = content.match(dynamicRegex);
if (dynamicMatches) {
  console.log('Remaining dynamic patterns:', dynamicMatches.length);
  console.log(dynamicMatches);
} else {
  console.log('No dynamic patterns found');
}