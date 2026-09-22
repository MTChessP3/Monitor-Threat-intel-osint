const fs = require('fs');
let content = fs.readFileSync('src/app/page.tsx', 'utf8');

// Replace opacity syntax in className template literals only
content = content.replace(/(bg|border|text)-([a-z]+)-(\d+)\/(\d+)/g, '$1-$2-$3_$4');
content = content.replace(/(hover|focus):(bg|border|text)-([a-z]+)-(\d+)\/(\d+)/g, '$1:$2-$3-$4_$5');

fs.writeFileSync('src/app/page.tsx', content);
console.log('Fixed opacity syntax');