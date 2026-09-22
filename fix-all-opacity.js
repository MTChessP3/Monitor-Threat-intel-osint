const fs = require('fs');
let content = fs.readFileSync('src/app/page.tsx', 'utf8');

// Comprehensive fix for all Tailwind opacity syntax patterns
// Pattern: color-NUM/NUM (e.g., bg-red-500/20, border-blue-400/30, text-green-600/10, from-cyan-500/10, to-blue-500/10, bg-black/70, etc.)
content = content.replace(/([a-z-]+)-(\d+)\/(\d+)/g, '$1-$2_$3');

fs.writeFileSync('src/app/page.tsx', content);
console.log('Fixed all opacity syntax');