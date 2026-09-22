const fs = require('fs');
let content = fs.readFileSync('src/app/page.tsx', 'utf8');

// Replace text-[10px] with text-xs in JSX template literals
// This might be confusing the parser (thinks [10px] is regex character class)
content = content.replace(
  /className=\{`([^`]*)text-\[10px\]([^`]*)`\}/g,
  'className={`$1text-xs$2`}'
);

// Also handle cases where text-[10px] appears with other classes
content = content.replace(
  /className=\{`([^`]*)\stext-\[10px\]([^`]*)`\}/g,
  'className={`$1 text-xs$2`}'
);

fs.writeFileSync('src/app/page.tsx', content);
console.log('Replaced text-[10px] with text-xs');