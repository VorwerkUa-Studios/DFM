"""
Decod FFmpeg Media Converter:
Automates audio and video transcoding, extraction, and compression via system FFmpeg.
Crucial for game modding:
- Converting extracted game sounds (OGG, WAV, FLAC, MP3, OPUS).
- Extracting audio tracks from game cutscenes and videos.
- Converting animation frames to GIF/WebM.
"""

import os
import subprocess
import json
from typing import Dict, Any, Optional

class MediaConverter:
    def __init__(self, ffmpeg_bin: str = "ffmpeg", ffprobe_bin: str = "ffprobe"):
        self.ffmpeg_bin = ffmpeg_bin
        self.ffprobe_bin = ffprobe_bin

    def inspect_media(self, file_path: str) -> Dict[str, Any]:
        """Inspect streams, codecs, duration, and bitrate using ffprobe."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Media file not found: {file_path}")

        cmd = [
            self.ffprobe_bin,
            "-v", "quiet",
            "-print_format", "json",
            "-show_format",
            "-show_streams",
            file_path
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0:
            return json.loads(res.stdout)
        return {"error": res.stderr}

    def convert_media(self, input_path: str, output_path: str, extra_args: list = None) -> Dict[str, Any]:
        """Convert any audio or video file to another format via FFmpeg."""
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"Input file not found: {input_path}")

        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        cmd = [self.ffmpeg_bin, "-y", "-i", input_path]
        if extra_args:
            cmd.extend(extra_args)
        cmd.append(output_path)

        res = subprocess.run(cmd, capture_output=True, text=True)
        return {
            "success": res.returncode == 0,
            "input": input_path,
            "output": output_path,
            "stdout": res.stdout,
            "stderr": res.stderr[-500:] if res.stderr else ""  # last 500 chars of log
        }

    def extract_audio(self, video_path: str, output_audio_path: str, audio_codec: str = "copy") -> Dict[str, Any]:
        """Extract soundtrack/audio from a video or cutscene."""
        return self.convert_media(video_path, output_audio_path, ["-vn", "-c:a", audio_codec])

if __name__ == "__main__":
    import sys
    print("MediaConverter ready.")
