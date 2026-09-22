const fs = require('fs');
let content = fs.readFileSync('src/app/page.tsx', 'utf8');

// Fix remaining opacity patterns with /
content = content.replace(/bg-black\/70/g, 'bg-black_70');

// Fix arbitrary value patterns
content = content.replace(/text-\[11px\]/g, 'text-xs');
content = content.replace(/text-\[10px\]/g, 'text-xs');

// Fix division in template literal at line 5448
content = content.replace(
  /\$\{apiData\.data\.signature \? 1 : 0 \+ '\/1'\}/g,
  '${apiData.data.signature ? 1 : (0 + \'/1\')}'
);

// Fix URLs in template literals
// Line 3809: OpenStreetMap URL - already has proper escaping, but let's check
// The issue might be the / in the URL inside template literal
// We can't easily fix this without breaking the URL

fs.writeFileSync('src/app/page.tsx', content);
console.log('Fixed basic issues');