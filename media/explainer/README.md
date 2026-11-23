# Bridgefu developer explainer

`bridgefu-explainer.mp4` is a 51.12-second, 1920×1080, 30 fps film with H.264 video, AAC narration, and an optional English caption track. `captions.srt` is also supplied separately.

The film reuses the repository's existing `bridgefu-square.png` and `bridgefu-banner.png`. Its animated diagrams follow the README, product overview, architecture, and SIP-to-WebRTC local demo. The Amazon Connect scene is labeled as a reference workflow rather than a blanket release-readiness claim.

Narration uses OpenAI `gpt-4o-mini-tts`, voice `marin`. The end card discloses AI-generated narration. Original voice clips and the normalized composite are retained. No background music is included.

## Rebuild

Requirements: Python 3, Pillow, numpy, requests, soundfile, FFmpeg with libx264, and the macOS Avenir Next and Menlo fonts. Set `FFMPEG_EXE` to a standalone FFmpeg binary if the system installation is unavailable. The export in this folder used imageio-ffmpeg's bundled binary.

```sh
# Only needed when generating new speech; reads OPENAI_API_KEY from the environment.
python3 media/explainer/generate_voice.py

# Inspect six representative frames without rendering the movie.
python3 media/explainer/render.py --preview

# Render with existing voice clips; no API call.
python3 media/explainer/render.py
```

`narration.json` contains the script. `render.py` defines the diagrams, transitions, timing, captions, and export. Delete the corresponding `voice-N.wav` before regenerating an edited narration segment. The generation script caches existing audio.

The Speech API models used for this one-off export are scheduled to shut down on January 6, 2027 according to the OpenAI documentation checked during production. A future speech regeneration may require updating the API integration. Existing audio and video exports do not depend on the API.

Voice documentation: https://developers.openai.com/api/docs/guides/text-to-speech
