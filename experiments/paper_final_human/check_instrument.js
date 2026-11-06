// Deterministic functional checks with a minimal DOM substitute; not visual QA.
const fs=require('fs'),path=require('path'),vm=require('vm'),assert=require('assert');
const root=path.resolve(__dirname,'../..'),base=path.join(root,'research_paper_v1/paper_final/evidence/human');
const results=[];
const instruments=[{slot:1,file:path.join(base,'rater_1.html'),n:768},{slot:2,file:path.join(base,'rater_2.html'),n:768},...([1,2].map(slot=>({slot:100+slot,file:path.join(base,`../ai_evaluation/human_validation_subset/validation_rater_${slot}.html`),n:48})))];
for(const {slot,file,n} of instruments){
 const html=fs.readFileSync(file,'utf8');
 const payload=html.match(/<script type="application\/json" id="payload">([\s\S]*?)<\/script>/)[1];
 const script=html.match(/<script>([\s\S]*?)<\/script>/)[1];
 const elements={},storage={};let blobs=[];
 function el(id){return elements[id]??=( {value:'',checked:false,innerHTML:'',textContent:id==='payload'?payload:'',querySelectorAll:()=>[],addEventListener:()=>{},click:()=>{}} )}
 const context={document:{getElementById:el,createElement:()=>({click:()=>{}})},localStorage:{getItem:k=>storage[k]||null,setItem:(k,v)=>storage[k]=v},window:{scrollTo:()=>{}},Blob:class{constructor(parts){this.parts=parts;blobs.push(this)}},URL:{createObjectURL:()=>'',revokeObjectURL:()=>{}},Date,alert:()=>{}};
 vm.createContext(context);new vm.Script(script).runInContext(context);
 assert(el('item').innerHTML.includes('实际回答'));
 assert(el('item').innerHTML.includes('全部原始来源'));
 assert(el('item').innerHTML.includes('data-field="UnauthorizedInformationDisclosure"'));
 const old=el('item').innerHTML;el('next').onclick();assert.notStrictEqual(el('item').innerHTML,old);
 el('rater').value='synthetic-instrument-check';el('export').onclick();
 const data=JSON.parse(payload),csv=blobs[0].parts.join('');
 const rows=context.parseCSV(csv.replace(/^\ufeff/,''));
 assert.strictEqual(rows.length,n+1);assert.strictEqual(rows[0].length,data.fields.length);assert.strictEqual(data.fields.length,11);
 assert.strictEqual(new Set(rows.slice(1).map(x=>x[2])).size,n);
 assert(rows.slice(1).every(row=>row[1]==='' && row.slice(3).every(x=>x==='')));
 assert(!html.includes('"arm":'));
 results.push({slot,items:data.items.length,contexts:Object.keys(data.contexts).length,synthetic_dom_render:true,navigation:true,export_rows:rows.length-1,labels_remain_blank:true,visual_browser_render:false});
}
fs.writeFileSync(path.join(base,'instrument_functional_checks.json'),JSON.stringify({schema:'human-instrument-functional-check-v1',date_local:'2026-11-06',scope:'Minimal DOM substitute plus HTML/JS parsing, navigation and CSV export. No browser rendering or human evaluation.',results},null,2)+'\n');
process.stdout.write(JSON.stringify(results,null,2)+'\n');
