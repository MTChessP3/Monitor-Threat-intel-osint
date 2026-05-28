const http = require('http');
const ZAI = require('z-ai-web-dev-sdk').default;

let zai;

async function init() {
  zai = await ZAI.create();
  console.log('[AI-Backend] SDK ready');
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', c => data += c);
    req.on('end', () => {
      try { resolve(JSON.parse(data)); }
      catch(e) { reject(e); }
    });
  });
}

function jsonRes(res, code, data) {
  res.writeHead(code, {'Content-Type':'application/json','Access-Control-Allow-Origin':'*','Access-Control-Allow-Methods':'POST,OPTIONS','Access-Control-Allow-Headers':'Content-Type'});
  res.end(JSON.stringify(data));
}

const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {'Access-Control-Allow-Origin':'*','Access-Control-Allow-Methods':'POST,OPTIONS','Access-Control-Allow-Headers':'Content-Type'});
    res.end();
    return;
  }

  if (req.method === 'GET' && req.url === '/health') {
    return jsonRes(res, 200, {status:'ok'});
  }

  if (req.method !== 'POST') {
    return jsonRes(res, 404, {error:'Not found'});
  }

  try {
    const body = await parseBody(req);

    if (req.url === '/api/search') {
      const result = await zai.functions.invoke('web_search', {query:body.query, num:body.num||5});
      return jsonRes(res, 200, {ok:true, results:result});
    }

    if (req.url === '/api/chat') {
      const completion = await zai.chat.completions.create({messages:body.messages});
      return jsonRes(res, 200, {ok:true, content:completion.choices?.[0]?.message?.content||''});
    }

    if (req.url === '/api/analyze') {
      const collectedData = [];
      const errors = [];
      const urls = body.urls || [];
      const searchQueries = body.searchQueries || [];

      // Build queries
      const allQ = [];
      if (searchQueries.length > 0) allQ.push(...searchQueries.slice(0,2));
      if (urls.length > 0) {
        for (let i = 0; i < Math.min(urls.length, 3); i++) {
          try { allQ.push('site:'+new URL(urls[i]).hostname+' seguridad amenazas'); }
          catch { allQ.push(urls[i]); }
        }
      }
      if (allQ.length === 0) allQ.push('amenazas seguridad VIP protección 2026');
      const queries = allQ.slice(0,3);
      console.log('[AI] Queries:', queries.length);

      for (let i = 0; i < queries.length; i++) {
        try {
          const r = await zai.functions.invoke('web_search', {query:queries[i], num:5});
          if (r && Array.isArray(r)) {
            collectedData.push('Busqueda: "'+queries[i]+'"\n'+r.map(x=>'['+(x.name||'')+'] '+(x.snippet||'')+' ('+(x.url||'')+')').join('\n'));
          }
        } catch(e) { errors.push(queries[i]); }
        if (i < queries.length-1) await new Promise(r=>setTimeout(r,1500));
      }

      if (collectedData.length === 0) return jsonRes(res,500,{error:'No data collected'});
      if (errors.length > 0) collectedData.push('Errors: '+errors.join('; '));

      const prompt = 'Analiza informacion de inteligencia VIP y responde SOLO JSON: {threats:[{title,description,severity,category}],overallRiskLevel,summary,recommendations,sources:[{title,url,relevance}]}\n\n'+collectedData.join('\n---\n');
      const completion = await zai.chat.completions.create({messages:[{role:'system',content:'JSON valido. Analista inteligencia VIP.'},{role:'user',content:prompt}]});
      const text = completion.choices?.[0]?.message?.content || '';
      try { const m = text.match(/\{[\s\S]*\}/); if(m) return jsonRes(res,200,JSON.parse(m[0])); } catch{}
      return jsonRes(res,200,{threats:[{title:'Análisis',description:text.substring(0,500),severity:'medio',category:'seguridad'}],overallRiskLevel:'medio',summary:text.substring(0,300),recommendations:['Monitoreo'],sources:[]});
    }

    if (req.url === '/api/generate-report') {
      const {templateContent, analysis} = body;
      const prompt = 'Genera informe ejecutivo VIP en Markdown.\n\nPLANTILLA:\n'+(templateContent||'Estructura estándar')+'\n\nANÁLISIS:\nRiesgo: '+analysis.overallRiskLevel+'\nResumen: '+analysis.summary+'\nAmenazas: '+analysis.threats.map(t=>'['+t.severity+'] '+t.title+': '+t.description).join('\n')+'\nRecomendaciones: '+analysis.recommendations.join('\n')+'\n\nInforme completo en Markdown, español.';
      const completion = await zai.chat.completions.create({messages:[{role:'system',content:'Redactor informes ejecutivos VIP. Markdown español.'},{role:'user',content:prompt}]});
      return jsonRes(res,200,{ok:true,content:completion.choices?.[0]?.message?.content||'Error'});
    }

    if (req.url === '/api/update-report') {
      const {existingContent, additionalUrls, additionalNews, additionalContext} = body;
      const collected = [];
      if (additionalUrls?.length) {
        for (const url of additionalUrls) {
          if (!url.trim()) continue;
          try {
            let sq; try{sq='site:'+new URL(url).hostname+' seguridad';}catch{sq=url;}
            const r = await zai.functions.invoke('web_search',{query:sq,num:3});
            if(r&&Array.isArray(r)) collected.push('Fuente: '+url+'\n'+r.map(x=>'['+(x.name||'')+'] '+(x.snippet||'')).join('\n'));
          } catch{collected.push('Error: '+url);}
          await new Promise(r=>setTimeout(r,1500));
        }
      }
      if(additionalNews?.trim()) collected.push('Noticias:\n'+additionalNews);
      if(additionalContext?.trim()) collected.push('Contexto:\n'+additionalContext);
      if(collected.length===0) return jsonRes(res,200,{ok:true,content:existingContent});

      const prompt = 'Actualiza informe VIP con nueva info.\n\nINFORME:\n'+existingContent+'\n\nNUEVA INFO:\n'+collected.join('\n---\n')+'\n\nMantén formato. [ACTUALIZADO]. Markdown español.';
      const completion = await zai.chat.completions.create({messages:[{role:'system',content:'Actualizas informes VIP. Markdown español.'},{role:'user',content:prompt}]});
      return jsonRes(res,200,{ok:true,content:completion.choices?.[0]?.message?.content||existingContent});
    }

    jsonRes(res,404,{error:'Not found'});
  } catch(err) {
    console.error('[AI] Error:', err.message);
    jsonRes(res,500,{error:err.message});
  }
});

init().then(()=>{
  server.listen(3001,'0.0.0.0',()=>console.log('[AI-Backend] Running on :3001'));
}).catch(e=>{console.error(e);process.exit(1);});

process.on('uncaughtException',e=>console.error('[AI] Uncaught:',e));
process.on('unhandledRejection',e=>console.error('[AI] Unhandled:',e));
