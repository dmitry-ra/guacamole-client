/* Licensed under the Apache License, Version 2.0. See LICENSE. */
'use strict';
// Controlled CDP-only regression: no service, credentials or external endpoint.
const fs = require('node:fs');
const assert = require('node:assert/strict');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const {spawn, execFileSync} = require('node:child_process');
const root = path.resolve(__dirname, '../../..');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
(async () => {
 const lock = JSON.parse(fs.readFileSync(path.join(root,'guacamole/src/main/frontend/package-lock.json')));
 const angularSpec = lock.packages['node_modules/angular'];
 const response = await fetch(angularSpec.resolved);
 if (!response.ok) throw new Error('Angular fixture input fetch failed');
 const archive = Buffer.from(await response.arrayBuffer());
 if ('sha512-'+crypto.createHash('sha512').update(archive).digest('base64')!==angularSpec.integrity)
  throw new Error('Angular fixture input digest mismatch');
 const angularSource = execFileSync('tar',['-xzOf','-','package/angular.js'],{input:archive,maxBuffer:5000000}).toString();
 const profile = fs.mkdtempSync(path.join(os.tmpdir(),'portal-controlled-cdp-'));
 const chrome=spawn('/usr/bin/google-chrome',['--headless','--disable-gpu','--no-first-run','--disable-background-networking','--disable-extensions','--remote-debugging-address=127.0.0.1','--remote-debugging-port=0','--user-data-dir='+profile,'about:blank'],{detached:true,stdio:'ignore'});
 let socket;
 try {
  const portfile=path.join(profile,'DevToolsActivePort');
  for(let i=0;i<100&&!fs.existsSync(portfile);i++)await delay(100);
  const port=Number(fs.readFileSync(portfile,'utf8').split('\n')[0]);
  const target=await(await fetch('http://127.0.0.1:'+port+'/json/new?about:blank',{method:'PUT'})).json();
  socket=new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolve,reject)=>{socket.onopen=resolve;socket.onerror=reject;});
  let sequence=0;const pending=new Map();
  socket.onmessage=e=>{const message=JSON.parse(e.data);if(pending.has(message.id)){pending.get(message.id)(message);pending.delete(message.id);}};
  const rpc=(method,params={})=>new Promise((resolve,reject)=>{const id=++sequence;const timer=setTimeout(()=>{pending.delete(id);reject(new Error('Controlled CDP timeout'));},15000);pending.set(id,r=>{clearTimeout(timer);if(r.error)reject(new Error(r.error.message));else resolve(r.result);});socket.send(JSON.stringify({id,method,params}));});
  const evaluate=expression=>rpc('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:false});
  const zero=await evaluate('(()=>{let v=document.createElement("canvas");v.width=0;v.height=0;return v.getContext("2d").getImageData(0,0,v.width,v.height).data})()');
  console.log(JSON.stringify({probe:'zero_canvas',exceptionClass:zero.exceptionDetails?.exception?.className,exceptionText:zero.exceptionDetails?.text}));
  assert.equal(zero.exceptionDetails?.exception?.className,'DOMException');
  const pixelsExpression=execFileSync('python3',['-c','import sys;sys.path.insert(0,"deploy/appliance/tools");import test_rdp;print(test_rdp.marker_pixels_expression("window.syntheticClient"))'],{cwd:root}).toString().trim();
  await evaluate('window.syntheticCanvas=document.createElement("canvas");syntheticCanvas.width=0;syntheticCanvas.height=0;window.syntheticClient={client:{getDisplay:()=>({flatten:()=>syntheticCanvas})},clientState:{connectionState:"CONNECTED",statusCode:0}};true');
  const guarded=await evaluate(pixelsExpression);
  assert.equal(guarded.exceptionDetails,undefined);
  assert.equal(guarded.result.value.nonblack,0);
  assert.equal(guarded.result.value.width,0);
  await evaluate('syntheticCanvas.width=200;syntheticCanvas.height=100;var paint=syntheticCanvas.getContext("2d");paint.fillStyle="rgb(0,100,0)";paint.fillRect(0,0,100,100);paint.fillStyle="rgb(0,0,128)";paint.fillRect(100,0,100,100);true');
  const painted=await evaluate(pixelsExpression);
  assert.equal(painted.exceptionDetails,undefined);
  assert.equal(painted.result.value.green,10000);assert.equal(painted.result.value.navy,10000);assert.equal(painted.result.value.nonblack,20000);
  console.log(JSON.stringify({probe:'guarded_canvas',empty:guarded.result.value,painted:painted.result.value}));
  await rpc('Runtime.evaluate',{expression:angularSource});
  const setup=`angular.module('navigation',[])
   .factory('formService',function(){return{insertFieldElement:angular.noop};})
   .factory('userPageService',function(){return{getHomePage:angular.noop};})
   .factory('authenticationService',function(){return{getAvailableDataSources:function(){return['postgresql'];}};})
   .factory('connectionGroupService',['$q',function(q){return{getConnectionGroupTree:function(){return q.resolve({childConnections:[]});}};}])
   .value('ConnectionGroup',{ROOT_IDENTIFIER:'ROOT'})
   .value('ClientIdentifier',{}).value('PageDefinition',function(){});
   angular.module('index',['navigation']).config(['$locationProvider',function(p){p.hashPrefix('');}]);`;
  await rpc('Runtime.evaluate',{expression:setup});
  await rpc('Runtime.evaluate',{expression:fs.readFileSync(path.join(root,'deploy/appliance/web/target-selection.js'),'utf8')});
  const boot=await evaluate('angular.bootstrap(document.documentElement,["index"]);true');
  if(boot.exceptionDetails)throw new Error('Controlled Angular bootstrap failed');
  const expression=execFileSync('python3',['-c','import sys;sys.path.insert(0,"deploy/appliance/tools");import test_image;print(test_image.invalid_target_expression("angular.element(document.documentElement).injector()"))'],{cwd:root}).toString().trim();
  const probe=await evaluate(expression);
  console.log(JSON.stringify({probe:'invalid_target_expression',exceptionClass:probe.exceptionDetails?.exception?.className,exceptionText:probe.exceptionDetails?.text,resultType:probe.result?.type,resultSubtype:probe.result?.subtype}));
  await delay(100);
  const status=await evaluate('({fatal:window.fixtureFatal,settled:window.fixtureSettled})');
  console.log(JSON.stringify({probe:'invalid_target_state',value:status.result?.value}));
  assert.equal(probe.exceptionDetails,undefined);assert.equal(status.result.value.fatal,true);assert.equal(status.result.value.settled,false);
  const readiness=execFileSync('python3',['-c','import sys;sys.path.insert(0,"deploy/appliance/tools");import test_image;print(test_image.reloaded_home_expression())'],{cwd:root}).toString().trim();
  await evaluate('location.hash="#/";document.body.innerHTML="<div class=home></div>";window.fixtureBeforeReload=true;true');
  const stale=await evaluate('location.hash==="#/" && !!document.querySelector(".home")');
  const rejectedOld=await evaluate(readiness);
  assert.equal(stale.result.value,true);assert.equal(rejectedOld.result.value,false);
  await rpc('Page.reload');
  for(let i=0;i<100;i++){const replacement=await evaluate('window.fixtureBeforeReload!==true && document.readyState==="complete"');if(replacement.result?.value)break;await delay(20);}
  const rejectedUnready=await evaluate(readiness);
  assert.equal(rejectedUnready.exceptionDetails,undefined);assert.equal(rejectedUnready.result.value,false);
  await rpc('Runtime.evaluate',{expression:angularSource});
  await evaluate('angular.module("ready",[]);angular.bootstrap(document.documentElement,["ready"]);location.hash="#/";document.body.innerHTML="<div class=home></div>";true');
  const ready=await evaluate(readiness);
  assert.equal(ready.exceptionDetails,undefined);assert.equal(ready.result.value,true);
  console.log(JSON.stringify({probe:'reload_readiness',oldCheckAdmittedStale:stale.result.value,rejectsOldDocument:rejectedOld.result.value===false,rejectsMissingAngular:rejectedUnready.result.value===false,admitsReplacementReady:ready.result.value}));

 } finally {
  if(socket)socket.close();
  try{process.kill(-chrome.pid,'SIGTERM');}catch(e){if(e.code!=='ESRCH')throw e;}
  await delay(400);
  try{process.kill(-chrome.pid,'SIGKILL');}catch(e){if(e.code!=='ESRCH')throw e;}
  fs.rmSync(profile,{recursive:true,force:true});
 }
})().catch(e=>{console.error(e.message);process.exitCode=1;});
