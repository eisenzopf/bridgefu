// Credentials enter on stdin; logs contain only phases and audio measurements.
import fs from 'node:fs';
import { chromium } from 'playwright';
const settings = JSON.parse(fs.readFileSync(0, 'utf8'));
process.umask(0o077);
const browser = await chromium.launch({headless:true,args:['--use-fake-ui-for-media-stream','--use-fake-device-for-media-stream',`--use-file-for-fake-audio-capture=${settings.audio}`,'--autoplay-policy=no-user-gesture-required']});
const context=await browser.newContext({permissions:['microphone']});
await context.addInitScript(()=>{
  const Original=window.RTCPeerConnection;
  window.__testPeers=[];window.__testAudio={frames:0,dtmfFrames:0};
  window.RTCPeerConnection=class extends Original {
    constructor(...a){super(...a);window.__testPeers.push(this);this.addEventListener('track',e=>{
      if(e.track.kind!=='audio')return;
      const ctx=new AudioContext();const src=ctx.createMediaStreamSource(new MediaStream([e.track]));const an=ctx.createAnalyser();an.fftSize=4096;src.connect(an);ctx.resume();
      setInterval(()=>{const data=new Float32Array(an.frequencyBinCount);an.getFloatFrequencyData(data);const peak=(hz)=>{let k=Math.round(hz/(ctx.sampleRate/an.fftSize));return Math.max(...data.slice(k-2,k+3));};window.__testAudio.frames++;if(peak(770)>-42&&peak(1336)>-42)window.__testAudio.dtmfFrames++;},20);
    });}
  };
});
const page=await context.newPage();
try {
 await page.goto(settings.url,{waitUntil:'domcontentloaded'});
 const u=page.locator('input[autocomplete="username"],input[name*="username" i],input[type="email"],input[type="text"]').first();await u.fill(settings.username);
 const pw=page.locator('input[type="password"]').first();if(!await pw.isVisible())await page.getByRole('button',{name:/Next|Continue/i}).first().click();await pw.fill(settings.password);await page.getByRole('button',{name:/Sign in|Log in|Login/i}).first().click();
 console.log('Login submitted');
 for(let i=0;i<180;i++){
   await page.waitForTimeout(1000);
   let texts=[];for(const frame of page.frames()){try{texts.push(await frame.locator('body').innerText({timeout:1000}));}catch{}}
   fs.writeFileSync(settings.output+'.ui',texts.join('\n')); // PRIVATE troubleshooting only.
   if(texts.some(t=>/Offline|Available|After contact work/i.test(t))){fs.writeFileSync(settings.output+'.ready','ready');console.log('Agent workspace ready');break;}
 }
 for(let i=0;i<360;i++){
  await page.waitForTimeout(1000);
  const all=[];
  for(const frame of page.frames())try{all.push(await frame.evaluate(async()=>{const a=window.__testAudio||{};let incoming=0,outgoing=0;for(const p of window.__testPeers||[]){for(const s of (await p.getStats()).values()){if(s.type==='inbound-rtp'&&s.kind==='audio')incoming+=s.packetsReceived||0;if(s.type==='outbound-rtp'&&s.kind==='audio')outgoing+=s.packetsSent||0;}}return {...a,incoming,outgoing};}));}catch{}
  const r=all.reduce((a,b)=>({incoming:a.incoming+b.incoming,outgoing:a.outgoing+b.outgoing,dtmfFrames:a.dtmfFrames+(b.dtmfFrames||0)}),{incoming:0,outgoing:0,dtmfFrames:0});fs.writeFileSync(settings.output,JSON.stringify(r));
  if(fs.existsSync(settings.output+'.stop'))break;
 }
} finally {await browser.close();}
