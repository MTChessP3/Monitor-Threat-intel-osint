const fs = require('fs');
let content = fs.readFileSync('src/app/page.tsx', 'utf8');

// Replace arrow function IIFE with regular function IIFE
// {(() => { ... })()} -> {(function() { ... })()}
content = content.replace(
  /\{\(\(\) => \{/g,
  '{(function() {'
);

content = content.replace(
  /\}\)\(\}\)/g,
  '})()}'
);

fs.writeFileSync('src/app/page.tsx', content);
console.log('Replaced arrow function IIFE with regular function IIFE');