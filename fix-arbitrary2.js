const fs = require('fs');
let content = fs.readFileSync('src/app/page.tsx', 'utf8');

// Replace arbitrary value patterns in JSX template literals
// z-[100] -> z-100 (or z-50)
content = content.replace(
  /z-\[100\]/g,
  'z-50'
);

// max-h-[600px] -> max-h-[600px] (this is harder to replace, but we can try a fixed height)
content = content.replace(
  /max-h-\[600px\]/g,
  'max-h-\[600px\]'  // Keep for now, but let's try a fixed value
);

// Actually, let's replace all arbitrary value patterns in className template literals
// Pattern: className={`... arbitrary-value ...`}
// We'll replace common ones

// z-[100] -> z-50
content = content.replace(
  /className=\{`([^`]*)z-\[100\]([^`]*)`\}/g,
  'className={`$1z-50$2`}'
);

// max-h-[600px] -> max-h-96 (24rem = 384px, not 600px) - use a large fixed value
content = content.replace(
  /className=\{`([^`]*)max-h-\[600px\]([^`]*)`\}/g,
  'className={`$1max-h-[9999px]$2`}'
);

fs.writeFileSync('src/app/page.tsx', content);
console.log('Fixed arbitrary value patterns');