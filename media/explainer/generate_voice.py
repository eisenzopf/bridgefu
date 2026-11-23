"""Generate the requested OpenAI narration; credentials stay in the environment."""
import concurrent.futures
import json
import os
from pathlib import Path
import soundfile
import requests

ROOT = Path(__file__).resolve().parent
SCRIPT = json.loads((ROOT / "narration.json").read_text())

def generate(item):
    i, text = item
    output = ROOT / f"voice-{i}.wav"
    if not output.exists():
        response = requests.post(
            "https://api.openai.com/v1/audio/speech",
            headers={"Authorization": "Bearer " + os.environ["OPENAI_API_KEY"]},
            json={
                "model": "gpt-4o-mini-tts", "voice": "marin",
                "input": text, "response_format": "wav",
                "instructions": "Narrate a polished developer product film. Warm, confident, intelligent, conversational American English. Crisp articulation and a brisk but unhurried pace, around 165 words per minute. Subtle enthusiasm, no sales hype. Brief natural pauses. Pronounce Bridgefu as bridge foo, Vapi as vap-ee, and r-voip as are voyp. Speak only the supplied words. Keep the same consistent voice throughout.",
            }, timeout=120,
        )
        response.raise_for_status()
        output.write_bytes(response.content)
    duration = soundfile.info(output).duration
    return {"scene": i, "text": text, "duration": duration}

if __name__ == "__main__":
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        clips = list(executor.map(generate, enumerate(SCRIPT)))
    (ROOT / "timing.json").write_text(json.dumps(clips, indent=2) + "\n")
    print(json.dumps(clips, indent=2))
    print("Total spoken seconds:", sum(c["duration"] for c in clips))
