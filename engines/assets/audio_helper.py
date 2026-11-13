"""
Decod Pure-Python MIDI Music Composer:
Allows AI agents to compose musical tracks, melodies, chiptunes, and ambient soundscapes.
Generates standard .mid (Type 0 / Type 1) files with zero external dependencies.
"""

import os
import struct
from typing import List, Dict, Any

NOTE_NAMES = {
    "C": 0, "C#": 1, "Db": 1, "D": 2, "D#": 3, "Eb": 3,
    "E": 4, "F": 5, "F#": 6, "Gb": 6, "G": 7, "G#": 8,
    "Ab": 8, "A": 9, "A#": 10, "Bb": 10, "B": 11
}

def note_to_midi_number(note_str: str) -> int:
    """Convert note string like 'C4', 'F#5', 'Bb3' into MIDI number (0-127)."""
    note_str = note_str.strip()
    if note_str.isdigit():
        return int(note_str)

    name = note_str[:-1]
    octave = int(note_str[-1])
    semitone = NOTE_NAMES.get(name, 0)
    return (octave + 1) * 12 + semitone

def write_varlen(val: int) -> bytes:
    """Encode variable-length quantity for MIDI delta-time."""
    buf = bytearray()
    buf.append(val & 0x7F)
    val >>= 7
    while val > 0:
        buf.append((val & 0x7F) | 0x80)
        val >>= 7
    buf.reverse()
    return bytes(buf)

class MidiComposer:
    def __init__(self, bpm: int = 120, ticks_per_beat: int = 480):
        self.bpm = bpm
        self.ticks_per_beat = ticks_per_beat
        self.events = bytearray()

    def set_tempo(self, bpm: int):
        self.bpm = bpm
        us_per_beat = int(60_000_000 / bpm)
        self.events.extend(write_varlen(0))
        self.events.extend(b"\xFF\x51\x03" + struct.pack(">I", us_per_beat)[1:])

    def set_instrument(self, program: int, channel: int = 0):
        """Set General MIDI instrument (0=Acoustic Grand Piano, 25=Steel Guitar, 80=Lead Synth, etc.)."""
        self.events.extend(write_varlen(0))
        self.events.extend(bytes([0xC0 | (channel & 0x0F), program & 0x7F]))

    def add_notes(self, notes_list: List[Dict[str, Any]], channel: int = 0):
        """
        Add a sequence of notes.
        Each note: {"note": "C4", "duration": 1.0, "velocity": 90, "rest_after": 0.0}
        duration 1.0 = 1 beat (quarter note).
        """
        for item in notes_list:
            note_val = note_to_midi_number(item["note"])
            duration_beats = float(item.get("duration", 1.0))
            velocity = int(item.get("velocity", 90))
            rest_beats = float(item.get("rest_after", 0.0))

            duration_ticks = int(duration_beats * self.ticks_per_beat)
            rest_ticks = int(rest_beats * self.ticks_per_beat)

            # Note On with delta-time 0
            self.events.extend(write_varlen(0))
            self.events.extend(bytes([0x90 | (channel & 0x0F), note_val, velocity]))

            # Note Off after duration_ticks
            self.events.extend(write_varlen(duration_ticks))
            self.events.extend(bytes([0x80 | (channel & 0x0F), note_val, 0]))

            # If there's rest after note, pad next delta-time (handled by next note or end)
            if rest_ticks > 0:
                self.events.extend(write_varlen(rest_ticks))
                self.events.extend(b"\x90\x00\x00")  # Dummy silent event to advance clock

    def save(self, output_path: str) -> str:
        """Compile and save standard Type 0 MIDI file."""
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

        # End of Track meta-event
        track_data = bytearray(self.events)
        track_data.extend(write_varlen(0))
        track_data.extend(b"\xFF\x2F\x00")

        # Header chunk: Type 0, 1 track
        header = b"MThd" + struct.pack(">IHHH", 6, 0, 1, self.ticks_per_beat)
        track_chunk = b"MTrk" + struct.pack(">I", len(track_data)) + bytes(track_data)

        with open(output_path, "wb") as f:
            f.write(header + track_chunk)

        return output_path

if __name__ == "__main__":
    composer = MidiComposer(bpm=130)
    composer.set_tempo(130)
    composer.set_instrument(80)  # Synth Lead
    # Simple melody test
    sample_melody = [
        {"note": "E4", "duration": 0.5},
        {"note": "G4", "duration": 0.5},
        {"note": "A4", "duration": 1.0},
        {"note": "B4", "duration": 0.5},
        {"note": "A4", "duration": 0.5},
        {"note": "G4", "duration": 1.0}
    ]
    composer.add_notes(sample_melody)
    out = composer.save("sample_melody.mid")
    print(f"Generated MIDI: {out}")
