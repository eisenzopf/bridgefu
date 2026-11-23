"""Deterministic 1080p motion design, using existing Bridgefu graphics.
Usage: python3 media/explainer/render.py [--preview]
Requires Pillow, numpy and ffmpeg. Voice generation is a separate explicit step.
"""
from pathlib import Path
from functools import lru_cache
import json, math, os, subprocess, sys, textwrap, wave
import numpy as np
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parents[1]
W, H, FPS = 1920, 1080, 30
FFMPEG = os.environ.get('FFMPEG_EXE', 'ffmpeg')
ORANGE = '#ff531e'; AMBER = '#ffb13c'; WHITE = '#f3f4f2'; MUTED = '#9babae'; SILVER = '#b9c5c9'
FONT = '/System/Library/Fonts/Avenir Next.ttc'
MONO = '/System/Library/Fonts/Menlo.ttc'
@lru_cache(None)
def font(size, bold=False, mono=False):
    return ImageFont.truetype(MONO if mono else FONT, size, index=0 if mono else (0 if bold else 7))
def ease(x):
    x=max(0,min(1,x)); return 1-(1-x)**3
def rgba(c,a=255):
    if isinstance(c,tuple): return c[:3]+(int(a),)
    c=c.lstrip('#'); return tuple(int(c[n:n+2],16) for n in (0,2,4))+(int(a),)
def text(im,xy,s,size=36,color=WHITE,bold=False,anchor='la',mono=False):
    ImageDraw.Draw(im).text(xy,s,font=font(size,bold,mono),fill=color,anchor=anchor,spacing=12)
def rounded(im,box,fill='#101b20',outline='#2c3a3e',radius=28,width=2):
    ImageDraw.Draw(im).rounded_rectangle(box,radius=radius,fill=fill,outline=outline,width=width)
def line(im,pts,color='#3c494e',width=4):
    ImageDraw.Draw(im).line(pts,fill=color,width=width,joint='curve')
def pill(im,x,y,label,color=ORANGE,size=25):
    f=font(size,True); tw=ImageDraw.Draw(im).textlength(label,font=f)
    rounded(im,(x,y,x+tw+40,y+50),fill='#182025',outline=color,radius=25)
    text(im,(x+20,y+10),label,size,color,True)
    return tw+40

y,x=np.mgrid[0:H,0:W]
g=np.exp(-((x-1600)**2/(850**2)+(y-180)**2/(650**2)))
g2=np.exp(-((x-350)**2/(900**2)+(y-900)**2/(650**2)))
a=np.zeros((H,W,3),dtype=np.uint8)
for c,v in enumerate((7,13,17)): a[:,:,c]=np.clip(v+g*(15,8,3)[c]+g2*(2,8,10)[c],0,255)
BG=Image.fromarray(a)
d=ImageDraw.Draw(BG)
for gx in range(0,W,80): d.line([(gx,0),(gx,H)],fill=(19,27,31),width=1)
for gy in range(0,H,80): d.line([(0,gy),(W,gy)],fill=(19,27,31),width=1)
logo=Image.open(REPO/'bridgefu-square.png').convert('RGBA')
banner=Image.open(REPO/'bridgefu-banner.png').convert('RGBA')
@lru_cache(None)
def logo_size(size): return logo.resize((size,size),Image.Resampling.LANCZOS)

def brand(im):
    im.alpha_composite(logo_size(58),(92,55))
    text(im,(166,67),'Bridgefu',29,WHITE,True)
    text(im,(1828,75),'DEVELOPER OVERVIEW',20,MUTED,anchor='ra')

def title(im,kicker,headline,sub=None):
    text(im,(110,185),kicker,24,ORANGE,True)
    text(im,(106,231),headline,70,WHITE,True)
    if sub: text(im,(110,332),sub,29,MUTED)

def footer(im,n):
    text(im,(110,1003),'CONNECT ANYTHING.',18,MUTED,True)
    text(im,(1810,1003),f'{n+1:02d} / 06',18,MUTED,anchor='ra')

def card(im,cx,cy,label,sub='',width=340,icon=None,accent=ORANGE):
    x=cx-width/2; y=cy-97
    rounded(im,(x,y,x+width,y+194),fill='#101b21',outline='#344249')
    line(im,[(x+30,y),(x+width-30,y)],accent,3)
    text(im,(cx,cy-28),label,38,WHITE,True,anchor='mm')
    if sub: text(im,(cx,cy+29),sub,25,MUTED,anchor='mm')

def particles(im,pts,t,color=ORANGE,count=4,reverse=False):
    lengths=[math.dist(a,b) for a,b in zip(pts,pts[1:])]; total=sum(lengths)
    line(im,pts,'#38484c',4)
    d=ImageDraw.Draw(im)
    for k in range(count):
        v=((t*.22+k/count)%1); v=1-v if reverse else v
        dist=v*total
        for j,length in enumerate(lengths):
            if dist<=length:
                q=dist/length; px=pts[j][0]+q*(pts[j+1][0]-pts[j][0]); py=pts[j][1]+q*(pts[j+1][1]-pts[j][1]); break
            dist-=length
        d.ellipse((px-13,py-13,px+13,py+13),fill='#41342b' if color != SILVER else '#34434a')
        d.ellipse((px-6,py-6,px+6,py+6),fill=color)

def reveal(im,fn,p,dx=0,dy=30):
    layer=Image.new('RGBA',(W,H)); fn(layer)
    p=ease(p)
    layer.putalpha(layer.getchannel('A').point(lambda a:int(a*p)))
    im.alpha_composite(layer,(int(dx*(1-p)),int(dy*(1-p))))

def wavebars(im,x,y,t,color,scale=1,n=19):
    d=ImageDraw.Draw(im)
    for j in range(n):
        amp=(12+30*(.5+.5*math.sin(j*.63+t*4)))*scale
        px=x+j*13
        d.rounded_rectangle((px,y-amp,px+5,y+amp),radius=2,fill=color)

def scene(i,t,dur):
    im=BG.copy().convert('RGBA'); brand(im); footer(im,i)
    if i==0:
        title(im,'THE INTEGRATION CHALLENGE','Different protocols. One conversation.')
        specs=[(370,'Browser','WebRTC',ORANGE),(960,'Phone system','SIP',AMBER),(1550,'AI assistant','Voice + context',SILVER)]
        for j,(cx,lab,sub,col) in enumerate(specs):
            reveal(im,lambda z,cx=cx,lab=lab,sub=sub,col=col:card(z,cx,575,lab,sub,420,accent=col),(t-.4-j*.5)/.8)
        for j,cx in enumerate((370,960,1550)):
            wavebars(im,cx-122,765,t+j,specs[j][3],.75)
        reveal(im,lambda z:text(z,(960,888),'Make the handoff feel like one continuous call.',33,MUTED,anchor='mm'),(t-2)/1)
    elif i==1:
        title(im,'THE BRIDGEFU MODEL','Two call legs. One bridge.','A Rust media gateway built on rvoip.')
        particles(im,[(535,580),(800,580)],t,ORANGE)
        particles(im,[(1120,580),(1385,580)],t,SILVER,reverse=True)
        particles(im,[(535,625),(800,625)],t,SILVER,reverse=True)
        particles(im,[(1120,625),(1385,625)],t,ORANGE)
        reveal(im,lambda z:card(z,340,600,'Source leg','SIP or WebRTC',390),(t-.2)/.7)
        reveal(im,lambda z:card(z,1580,600,'Destination leg','A different stack',390,accent=SILVER),(t-.5)/.7)
        im.alpha_composite(logo_size(280),(820,458))
        for j,(xpos,lab,col) in enumerate([(500,'Bidirectional audio',ORANGE),(880,'DTMF',AMBER),(1100,'Allowlisted context',SILVER)]):
            reveal(im,lambda z,xpos=xpos,lab=lab,col=col:pill(z,xpos,828,lab,col),(t-1.5-j*.3)/.7)
    elif i==2:
        title(im,'PROTOCOL + MEDIA ADAPTATION','Keep your stack. Cross the boundary.','Bridgefu terminates each side and converts codecs when needed.')
        rounded(im,(150,453,700,814),outline='#465256')
        rounded(im,(1220,453,1770,814),outline='#60402f')
        text(im,(425,510),'WebRTC',43,WHITE,True,anchor='mm'); pill(im,365,560,'Opus',SILVER)
        text(im,(1495,510),'SIP',43,WHITE,True,anchor='mm'); pill(im,1420,560,'G.711',ORANGE)
        wavebars(im,305,707,t,SILVER,1.1); wavebars(im,1375,707,t+.4,ORANGE,1.1)
        particles(im,[(700,655),(1220,655)],t,ORANGE,5)
        im.alpha_composite(logo_size(180),(870,552))
        text(im,(960,793),'Decode / convert / encode',27,MUTED,anchor='mm')
        reveal(im,lambda z:text(z,(960,909),'Audio, keypad tones, and permitted context cross together.',31,WHITE,anchor='mm'),(t-1)/.8)
    elif i==3:
        title(im,'REFERENCE WORKFLOW','From AI assistant to human agent.','Vapi SIP transfer / Amazon Connect')
        particles(im,[(520,530),(765,530)],t,ORANGE,3)
        particles(im,[(1035,530),(1280,530)],t,ORANGE,3)
        card(im,340,530,'Vapi','SIP transfer',360)
        im.alpha_composite(logo_size(240),(780,410))
        card(im,1510,530,'Amazon Connect','WebRTC audio',460,accent=SILVER)
        text(im,(640,477),'SIP',21,MUTED,anchor='mm'); text(im,(1155,477),'WebRTC',21,MUTED,anchor='mm')
        reveal(im,lambda z:pill(z,1300,675,'Correlation ID',AMBER),(t-1)/.7)
        if t>1.5:
            particles(im,[(1510,627),(1510,790),(1110,790)],t,AMBER,3,False)
            particles(im,[(730,790),(430,790)],t,AMBER,3,False)
        reveal(im,lambda z:card(z,920,815,'Context lookup','Lambda + DynamoDB',430,accent=AMBER),(t-2)/.7)
        reveal(im,lambda z:card(z,350,815,'Agent screen pop','Call-linked context',390,accent=AMBER),(t-2.7)/.7)
    elif i==4:
        title(im,'START BUILDING','From configuration to a local call.','Named routes. Declarative recipes. An encrypted local demo.')
        for j,(xpos,label) in enumerate([(125,'01  Define a route'),(700,'02  Choose a recipe'),(1290,'03  Run the demo')]):
            reveal(im,lambda z,xpos=xpos,label=label:pill(z,xpos,425,label,ORANGE,27),(t-.3-j*.25)/.6)
        rounded(im,(120,535,1800,867),fill='#070e12',outline='#344349',radius=23)
        for j,col in enumerate(['#ff6057','#ffbd2e','#28c840']): ImageDraw.Draw(im).ellipse((148+j*28,561,161+j*28,574),fill=col)
        text(im,(960,565),'LOCAL TERMINAL',18,MUTED,anchor='mm')
        lines=['cargo run --locked --example native-sip-webrtc -- \\', '  --settings examples/sip-to-webrtc/settings.example.json']
        for j,s in enumerate(lines):
            count=int(len(s)*ease((t-.6-j*.7)/1.7))
            text(im,(164,628+j*57),s[:count],31,WHITE,mono=True)
        reveal(im,lambda z:text(z,(164,783),'SIPS / SRTP    <->    Bridgefu    <->    WebRTC',29,ORANGE,mono=True),(t-2.5)/.7)
        text(im,(960,924),'No cloud account needed for the local demo.',29,MUTED,anchor='mm')
    else:
        scale=1+.025*ease(t/dur); bw=int(1600*scale); bh=int(bw*banner.height/banner.width)
        asset=banner.resize((bw,bh),Image.Resampling.LANCZOS)
        im.alpha_composite(asset,((W-bw)//2,325))
        reveal(im,lambda z:text(z,(960,773),'Start with the local demos.',47,WHITE,True,anchor='mm'),t/.8)
        reveal(im,lambda z:text(z,(960,850),'github.com/eisenzopf/bridgefu',33,ORANGE,anchor='mm',mono=True),(t-.5)/.8)
        text(im,(960,971),'AI-generated narration · OpenAI Marin',19,MUTED,anchor='mm')
    return im.convert('RGB')

clips=json.loads((ROOT/'timing.json').read_text())
# Keep the complete film below one minute, preserving all narration.
raw=sum(c['duration'] for c in clips)
speed=max(1,raw/54.0)
start=.3
for c in clips:
    c['start']=start; c['length']=c['duration']/speed+.32; start+=c['length']
TOTAL=start+.8

def frame(t):
    idx=max([i for i,c in enumerate(clips) if t>=c['start']] or [0]); c=clips[idx]
    local=max(0,t-c['start']); im=scene(idx,local,c['length'])
    if idx>0 and local<.36:
        prev=clips[idx-1]
        im=Image.blend(scene(idx-1,prev['length']+local,prev['length']),im,ease(local/.36))
    if t<.3: im=Image.blend(Image.new('RGB',(W,H),'#070d11'),im,ease(t/.3))
    return im

def timestamp(seconds):
    ms=round(seconds*1000); h,ms=divmod(ms,3600000); m,ms=divmod(ms,60000); s,ms=divmod(ms,1000)
    return f'{h:02}:{m:02}:{s:02},{ms:03}'

if __name__=='__main__':
    (ROOT/'timeline.json').write_text(json.dumps({'duration':TOTAL,'speed':speed,'clips':clips},indent=2)+'\n')
    if '--preview' in sys.argv:
        thumbs=[]
        for i,c in enumerate(clips):
            img=frame(c['start']+min(4,c['length']*.65)); img.save(ROOT/f'scene-{i+1}.png')
            thumbs.append(img.resize((640,360),Image.Resampling.LANCZOS))
        contact=Image.new('RGB',(1280,1080))
        for i,img in enumerate(thumbs): contact.paste(img,((i%2)*640,(i//2)*360))
        contact.save(ROOT/'storyboard.jpg',quality=92)
        print('Preview ready; total duration:',TOTAL); sys.exit()
    # Normalize each clip before concatenating, inserting short breathing spaces.
    arrays=[np.zeros(round(.3*24000),dtype=np.int16)]
    for c in clips:
        data=subprocess.check_output([FFMPEG,'-v','error','-i',str(ROOT/f"voice-{c['scene']}.wav"),'-af',f'atempo={speed},loudnorm=I=-17:TP=-2:LRA=7','-f','s16le','-ar','24000','-ac','1','-'])
        pcm=np.frombuffer(data,dtype='<i2')
        expected=round(c['duration']/speed*24000)
        pcm=np.pad(pcm,(0,max(0,expected-len(pcm))))[:expected]
        arrays.extend([pcm,np.zeros(round(.32*24000),dtype=np.int16)])
    arrays.append(np.zeros(round(.8*24000),dtype=np.int16))
    with wave.open(str(ROOT/'narration.wav'),'wb') as out:
        out.setnchannels(1); out.setsampwidth(2); out.setframerate(24000); out.writeframes(np.concatenate(arrays).tobytes())
    subs=[]
    for i,c in enumerate(clips):
        clean=c['text'].replace('Web R T C','WebRTC').replace('S I P','SIP').replace('A I','AI').replace('I D','ID').replace('r-voip','rvoip')
        subs.append(f"{i+1}\n{timestamp(c['start'])} --> {timestamp(c['start']+c['duration']/speed)}\n"+'\n'.join(textwrap.wrap(clean,70))+'\n')
    (ROOT/'captions.srt').write_text('\n'.join(subs))
    target=ROOT/'bridgefu-explainer.mp4'
    cmd=[FFMPEG,'-y','-v','warning','-f','rawvideo','-pix_fmt','rgb24','-s',f'{W}x{H}','-r',str(FPS),'-i','-','-i',str(ROOT/'narration.wav'),'-i',str(ROOT/'captions.srt'),'-map','0:v','-map','1:a','-map','2:s','-c:v','libx264','-preset','fast','-crf','18','-pix_fmt','yuv420p','-c:a','aac','-b:a','192k','-c:s','mov_text','-metadata:s:s:0','language=eng','-metadata','title=Bridgefu — Connect anything','-movflags','+faststart','-t',str(TOTAL),str(target)]
    process=subprocess.Popen(cmd,stdin=subprocess.PIPE)
    for n in range(math.ceil(TOTAL*FPS)):
        process.stdin.write(frame(n/FPS).tobytes())
        if n%(FPS*5)==0: print(f'Rendered {n/FPS:.0f}s / {TOTAL:.1f}s',flush=True)
    process.stdin.close()
    if process.wait()!=0: raise RuntimeError('FFmpeg render failed')
    print('Saved',target,flush=True)
