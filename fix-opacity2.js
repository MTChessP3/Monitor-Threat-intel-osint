const fs = require('fs');
let content = fs.readFileSync('src/app/page.tsx', 'utf8');

// Fix all Tailwind opacity syntax patterns that use / in className template literals
// Pattern: bg-color-NUM/NUM, border-color-NUM/NUM, text-color-NUM/NUM, from-color-NUM/NUM, to-color-NUM/NUM, etc.
// This matches patterns like: bg-red-500/20, border-blue-400/30, text-green-600/10, from-cyan-500/10, to-blue-500/10, bg-black/70

// More comprehensive regex to match Tailwind color with opacity in template literals
content = content.replace(
  /([a-z-]+)-(\d+)\/(\d+)(?=(['"`\s>}]))/g,
  '$1-$2_$3'
);

fs.writeFileSync('src/app/page.tsx', content);
console.log('Fixed opacity syntax');