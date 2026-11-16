/* Licensed under the Apache License, Version 2.0. See LICENSE. */
'use strict';
// Real Chromium Clipboard API and BlobWriter; synthetic pixels and stream only.
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const http = require('node:http');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const {spawn} = require('node:child_process');
const root = path.resolve(__dirname, '../../..');
const build = path.resolve(process.argv[2] || '');
const output = path.resolve(process.argv[3] || '');
if (!process.argv[2] || !process.argv[3] || process.getuid() === 0)
    throw new Error('Provide native client build and new evidence directory as an ordinary user');
fs.mkdirSync(output, {mode: 0o700});
const frontend = 'guacamole/src/main/frontend/src/app/';
const names = ['clipboard/types/ClipboardData.js', 'clipboard/services/clipboardService.js',
    'client/types/ManagedClient.js'];
const sources = names.map(name => fs.readFileSync(path.join(root, frontend, name), 'utf8'));
const hashes = Object.fromEntries(names.map((name, index) => [name,
    crypto.createHash('sha256').update(sources[index]).digest('hex')]));
for (const name of names)
    assert.equal(fs.readFileSync(path.join(build, 'source', frontend, name), 'utf8'),
        fs.readFileSync(path.join(root, frontend, name), 'utf8'));
const common = fs.readFileSync(path.join(build,
    'source/guacamole/target/guacamole-1.6.1/guacamole-common-js/all.min.js'), 'utf8');
const setup = `window.registry={};
window.angular={noop(){},module(){return{factory(name,definition){registry[name]=definition.at(-1);}}}};
window.q={resolve:v=>Promise.resolve(v),defer(){let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b});return{resolve,reject,promise}}};
window.services={$q:q,$window:window,$rootScope:{$broadcast(){}},sessionStorageFactory:{create(value){return replacement=>replacement===undefined?value:(value=replacement)}}};
window.injector={get(name){return services[name]||function SyntheticBoundary(){}}};`;
const page = '<!doctype html><title>Synthetic clipboard acceptance</title><body><button id="focus">Focus</button></body>';
let httpRequests=0;
const server = http.createServer((request, response) => {
    httpRequests++;
    response.writeHead(request.url === '/' ? 200 : 404, {'Content-Type':'text/html'});
    response.end(request.url === '/' ? page : '');
});
const delay = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));
const receipt = {passed:false, sources:hashes,
    scope:'actual Chromium clipboard API and FileReader/BlobWriter with synthetic stream boundary; no RDP/JDBC/Windows claim'};
let chrome, socket, profile;
(async () => {
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const origin = 'http://127.0.0.1:' + server.address().port;
    profile = fs.mkdtempSync(path.join(os.tmpdir(), 'guac-image-clipboard-'));
    const diagnostics=fs.openSync(path.join(output,'chrome.stderr'),'wx',0o600);
    chrome = spawn('/usr/bin/google-chrome', ['--headless', '--disable-gpu', '--no-first-run',
        '--password-store=basic',
        '--disable-background-networking', '--disable-extensions', '--remote-debugging-address=127.0.0.1',
        '--remote-debugging-port=0', '--user-data-dir='+profile, 'about:blank'],
        {detached:true, stdio:['ignore','ignore',diagnostics]});
    fs.closeSync(diagnostics);
    const portfile = path.join(profile, 'DevToolsActivePort');
    for (let i=0; i<100 && !fs.existsSync(portfile); i++) await delay(100);
    const port = Number(fs.readFileSync(portfile, 'utf8').split('\n')[0]);
    const target = await (await fetch('http://127.0.0.1:'+port+'/json/new?about:blank', {method:'PUT'})).json();
    socket = new WebSocket(target.webSocketDebuggerUrl);
    await new Promise((resolve, reject) => {socket.onopen=resolve;socket.onerror=reject;});
    let sequence=0;
    const pending = new Map();
    socket.onmessage = event => {
        const message=JSON.parse(event.data);
        receipt.cdpMessages=(receipt.cdpMessages||0)+1;
        if (pending.has(message.id)) {pending.get(message.id)(message);pending.delete(message.id);}
    };
    const rpc = (method, params={}) => new Promise((resolve, reject) => {
        const id=++sequence;
        const timer=setTimeout(() => {pending.delete(id);receipt.rpcTimeoutMethod=method;reject(new Error('CDP deadline exceeded'));},15000);
        pending.set(id, response => {clearTimeout(timer);if(response.error){
            receipt.rpcError={method,code:response.error.code,message:response.error.message};
            reject(new Error('CDP request failed'));
        }else resolve(response.result);});
        socket.send(JSON.stringify({id,method,params}));
    });
    const evaluate = async expression => {
        const value=await rpc('Runtime.evaluate', {expression,awaitPromise:true,returnByValue:true,userGesture:true});
        if (value.exceptionDetails) {
            receipt.browserExceptionClass=value.exceptionDetails.exception?.className;
            receipt.browserExceptionDescription=value.exceptionDetails.exception?.description?.slice(0,500);
            throw new Error('Synthetic browser evaluation failed');
        }
        return value.result.value;
    };
    receipt.phase='permissions';
    await rpc('Page.enable');
    await rpc('Runtime.enable');
    await rpc('Browser.grantPermissions', {origin, permissions:['clipboardReadWrite','clipboardSanitizedWrite']});
    receipt.phase='navigation';
    await rpc('Page.navigate', {url:origin});
    for (let i=0; i<100; i++) {
        if (await evaluate('document.readyState==="complete" && location.origin==='+JSON.stringify(origin))) break;
        await delay(20);
    }
    await rpc('Page.bringToFront');
    receipt.phase='modules';
    await evaluate(common+'\n'+setup+'\n'+sources[0]+'\nservices.ClipboardData=registry.ClipboardData();\n'
        +sources[1]+'\nservices.clipboardService=registry.clipboardService(injector);\n'+sources[2]
        +'\nwindow.ManagedClient=registry.ManagedClient(services.$rootScope,injector);true');
    receipt.phase='clipboard';
    receipt.browser = await evaluate(`(async()=>{
        const canvas=document.createElement('canvas');canvas.width=64;canvas.height=48;
        const context=canvas.getContext('2d');const pixels=context.createImageData(64,48);
        for(let y=0;y<48;y++)for(let x=0;x<64;x++){
            const at=(y*64+x)*4;pixels.data.set([(x*13+91)%256,(y*17+91)%256,(x+y+91)%256,255],at);
        }
        context.putImageData(pixels,0,0);
        const image=await new Promise(resolve=>canvas.toBlob(resolve,'image/png'));
        await navigator.clipboard.write([new ClipboardItem({'image/png':image})]);
        const data=await services.clipboardService.getClipboard();
        if(data.type!=='image/png')throw new Error('PNG not read');
        const decoded=await createImageBitmap(data.data);context.clearRect(0,0,64,48);context.drawImage(decoded,0,0);
        const actual=context.getImageData(0,0,64,48).data;
        if(!actual.every((value,index)=>value===pixels.data[index]))throw new Error('Pixel mismatch');
        const chunks=[];let ended=false;const expected=new Uint8Array(await data.data.arrayBuffer());
        const stream={sendBlob(chunk){chunks.push(Uint8Array.from(atob(chunk),value=>value.charCodeAt(0)));queueMicrotask(()=>stream.onack(new Guacamole.Status(0,'accepted')))},sendEnd(){ended=true}};
        const client={id:'synthetic-client',protocol:'rdp',client:{createClipboardStream(type){if(type!=='image/png')throw new Error('Bad type');return stream}}};
        if(!await ManagedClient.setClipboard(client,data)||!ended)throw new Error('Incomplete stream');
        const sent=new Uint8Array(chunks.reduce((total,chunk)=>total+chunk.length,0));let offset=0;
        for(const chunk of chunks){sent.set(chunk,offset);offset+=chunk.length}
        if(sent.length!==expected.length||!sent.every((value,index)=>value===expected[index]))throw new Error('Byte mismatch');
        await navigator.clipboard.writeText('synthetic text');
        const text=await services.clipboardService.getClipboard();
        if(text.type!=='text/plain'||text.data!=='synthetic text')throw new Error('Text regression');
        return{pngPixelsExact:true,clipboardPngBytes:expected.length,blobChunks:chunks.length,blobBytesExact:true,streamEnded:true,text:true};
    })()`);
    receipt.passed=true;receipt.phase='complete';
})().catch(error => {receipt.failureClass=error.constructor.name;process.exitCode=1;})
.finally(async () => {
    if (socket) socket.close();
    if (chrome) {
        try {process.kill(-chrome.pid,'SIGTERM');} catch(error) {if(error.code!=='ESRCH')throw error;}
        for(let i=0;i<50 && chrome.exitCode===null;i++)await delay(100);
        if(chrome.exitCode===null)throw new Error('Own Chromium cleanup unconfirmed');
    }
    await new Promise(resolve => server.close(resolve));
    if(profile)fs.rmSync(profile,{recursive:true});
    receipt.cleanupVerified=true;
    receipt.httpRequests=httpRequests;
    fs.writeFileSync(path.join(output,'receipt.json'),JSON.stringify(receipt,null,2)+'\n',{flag:'wx',mode:0o600});
    console.log(JSON.stringify(receipt));
});
