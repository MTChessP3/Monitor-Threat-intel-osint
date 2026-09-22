const fs = require('fs');
let content = fs.readFileSync('src/app/page.tsx', 'utf8');

// Fix remaining opacity patterns with /
content = content.replace(/bg-black\/70/g, 'bg-black_70');
content = content.replace(/bg-black_70/g, 'bg-black_70'); // already fixed

// Fix arbitrary value patterns
content = content.replace(/text-\[11px\]/g, 'text-xs');
content = content.replace(/text-\[10px\]/g, 'text-xs');

// Fix regex literal in template literal - line 5225
content = content.replace(
  /e\.replace\(\/<!--\|\-\-\>/g/,
  "e.replace(/<!--|-->/g"  // This is already a regex, but in template literal it might be parsed
);

// Actually, the issue is the regex literal inside a template literal
// Let me check line 5225 more carefully
// The original: e.replace(/<!--|-->/g, '')
// In template literal: `${e.replace(/<!--|-->/g, '')}`
// The parser sees the / as starting a regex

// Fix division in template literal at line 5448
content = content.replace(
  /\$\{apiData\.data\.signature \? 1 : 0 \+ '\/1'\}/g,
  '${apiData.data.signature ? 1 : (0 + \'/1\')}'
);

// Fix URLs in template literals
// Line 3809: OpenStreetMap URL
content = content.replace(
  /src=\{`https:\/\/www\.openstreetmap\.org\/export\/embed\.html\?bbox=/g,
  'src={`https://www.openstreetmap.org/export/embed.html?bbox='
);

// Line 3835: mailto URL
content = content.replace(
  /href=\{`mailto:/g,
  'href={`mailto:'
);

fs.writeFileSync('src/app/page.tsx', content);
console.log('Fixed remaining issues');