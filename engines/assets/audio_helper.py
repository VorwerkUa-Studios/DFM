"""
Decod Pure-Python MIDI Music Composer v2:
  - Multi-track (Type 1 MIDI)
  - Chord support (notes played simultaneously)
  - Named scales & chord progressions
  - Percussion track (channel 10, GM drum map)
  - Ambient / generative mode (random walk on scale)
  - Arpeggio helper
  - Zero external dependencies
"""

import os
import struct
import random
from typing import List, Dict, Any, Optional

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

NOTE_NAMES = {
    "C": 0, "C#": 1, "Db": 1, "D": 2, "D#": 3, "Eb": 3,
    "E": 4, "F": 5, "F#": 6, "Gb": 6, "G": 7, "G#": 8,
    "Ab": 8, "A": 9, "A#": 10, "Bb": 10, "B": 11,
}

# General MIDI instrument numbers (program 0-127)
GM_INSTRUMENTS = {
    "piano": 0, "acoustic_grand": 0, "electric_piano": 4,
    "harpsichord": 6, "celesta": 8, "glockenspiel": 9,
    "music_box": 10, "vibraphone": 11, "marimba": 12, "xylophone": 13,
    "guitar": 25, "steel_guitar": 25, "electric_guitar": 27,
    "nylon_guitar": 24, "bass_guitar": 33, "electric_bass": 34,
    "violin": 40, "viola": 41, "cello": 42, "contrabass": 43,
    "strings": 48, "choir": 52, "trumpet": 56, "trombone": 57,
    "tuba": 58, "french_horn": 60, "brass": 61, "saxophone": 65,
    "flute": 73, "recorder": 74, "pan_flute": 75, "blown_bottle": 76,
    "ocarina": 79, "synth_lead": 80, "square_lead": 80, "saw_lead": 81,
    "calliope": 82, "chiff": 83, "synth_pad": 88, "new_age_pad": 88,
    "warm_pad": 89, "polysynth": 90, "choir_pad": 91, "space_pad": 94,
    "rain": 96, "soundtrack": 97, "crystal": 98, "atmosphere": 99,
    "brightness": 100, "goblins": 101, "echoes": 102, "sci_fi": 103,
    "sitar": 104, "banjo": 105, "shamisen": 106, "koto": 107, "kalimba": 108,
    "bagpipe": 109, "fiddle": 110, "shanai": 111,
    "tinkle_bell": 112, "agogo": 113, "steel_drums": 114,
    "woodblock": 115, "taiko": 116, "synth_drum": 118,
    "reverse_cymbal": 119, "guitar_fret": 120, "breath_noise": 121,
    "seashore": 122, "bird_tweet": 123, "telephone": 124,
    "helicopter": 125, "applause": 126, "gunshot": 127,
}

# GM Drum map (channel 10, note numbers)
GM_DRUMS = {
    "kick": 36, "snare": 38, "hihat_closed": 42, "hihat_open": 46,
    "clap": 39, "crash": 49, "ride": 51, "tom_hi": 50,
    "tom_mid": 48, "tom_lo": 45, "cowbell": 56, "tambourine": 54,
    "shaker": 70, "claves": 75,
}

# Scale intervals (semitones from root)
SCALES = {
    "major":           [0, 2, 4, 5, 7, 9, 11],
    "minor":           [0, 2, 3, 5, 7, 8, 10],
    "harmonic_minor":  [0, 2, 3, 5, 7, 8, 11],
    "pentatonic":      [0, 2, 4, 7, 9],
    "pentatonic_minor":[0, 3, 5, 7, 10],
    "blues":           [0, 3, 5, 6, 7, 10],
    "dorian":          [0, 2, 3, 5, 7, 9, 10],
    "phrygian":        [0, 1, 3, 5, 7, 8, 10],
    "lydian":          [0, 2, 4, 6, 7, 9, 11],
    "mixolydian":      [0, 2, 4, 5, 7, 9, 10],
    "locrian":         [0, 1, 3, 5, 6, 8, 10],
    "chromatic":       list(range(12)),
    "whole_tone":      [0, 2, 4, 6, 8, 10],
    "diminished":      [0, 2, 3, 5, 6, 8, 9, 11],
}

# Chord intervals relative to root
CHORD_TYPES = {
    "maj":  [0, 4, 7],
    "min":  [0, 3, 7],
    "dim":  [0, 3, 6],
    "aug":  [0, 4, 8],
    "sus2": [0, 2, 7],
    "sus4": [0, 5, 7],
    "maj7": [0, 4, 7, 11],
    "min7": [0, 3, 7, 10],
    "dom7": [0, 4, 7, 10],
    "dim7": [0, 3, 6, 9],
    "add9": [0, 4, 7, 14],
    "power":[0, 7],
}

# ─────────────────────────────────────────────────────────────────────────────
# Low-level MIDI helpers
# ─────────────────────────────────────────────────────────────────────────────

def _varlen(val: int) -> bytes:
    buf = bytearray()
    buf.append(val & 0x7F)
    val >>= 7
    while val > 0:
        buf.append((val & 0x7F) | 0x80)
        val >>= 7
    buf.reverse()
    return bytes(buf)


def note_to_midi(note_str: str) -> int:
    """Convert 'C4', 'F#5', 'Bb3' or bare integer string to MIDI note number."""
    note_str = note_str.strip()
    if note_str.isdigit():
        return int(note_str)
    name = note_str[:-1]
    octave = int(note_str[-1])
    return (octave + 1) * 12 + NOTE_NAMES.get(name, 0)


def scale_notes(root: str, octave: int, scale: str = "major", num_octaves: int = 1) -> List[int]:
    """Return MIDI note numbers for a scale."""
    root_midi = (octave + 1) * 12 + NOTE_NAMES.get(root, 0)
    intervals = SCALES.get(scale, SCALES["major"])
    notes = []
    for o in range(num_octaves):
        for i in intervals:
            n = root_midi + o * 12 + i
            if 0 <= n <= 127:
                notes.append(n)
    return notes


def chord_notes(root: str, octave: int, chord_type: str = "maj") -> List[int]:
    """Return MIDI note numbers for a chord."""
    root_midi = (octave + 1) * 12 + NOTE_NAMES.get(root, 0)
    intervals = CHORD_TYPES.get(chord_type, CHORD_TYPES["maj"])
    return [root_midi + i for i in intervals if 0 <= root_midi + i <= 127]


# ─────────────────────────────────────────────────────────────────────────────
# Track builder
# ─────────────────────────────────────────────────────────────────────────────

class MidiTrack:
    """
    Represents a single MIDI track.
    Uses an absolute tick cursor — no need to manage delta times manually.
    """

    def __init__(self, name: str = "", channel: int = 0, ticks_per_beat: int = 480):
        self._channel = channel & 0x0F
        self._tpb = ticks_per_beat
        self._cursor = 0  # current tick position
        self._events: List[tuple] = []  # (tick, bytes)
        self.name = name

    def _add(self, tick: int, data: bytes):
        self._events.append((tick, data))

    # ── Setup ────────────────────────────────────────────────────────────────

    def set_name(self, name: str):
        encoded = name.encode("utf-8")
        self._add(0, b"\xFF\x03" + _varlen(len(encoded)) + encoded)

    def set_tempo(self, bpm: int):
        us = int(60_000_000 / bpm)
        self._add(0, b"\xFF\x51\x03" + struct.pack(">I", us)[1:])

    def set_instrument(self, instrument, channel: Optional[int] = None):
        ch = (channel if channel is not None else self._channel) & 0x0F
        if isinstance(instrument, str):
            program = GM_INSTRUMENTS.get(instrument.lower(), 0)
        else:
            program = int(instrument)
        self._add(self._cursor, bytes([0xC0 | ch, program & 0x7F]))

    def set_volume(self, volume: int = 100, channel: Optional[int] = None):
        """CC 7 — channel volume (0-127)."""
        ch = (channel if channel is not None else self._channel) & 0x0F
        self._add(self._cursor, bytes([0xB0 | ch, 7, min(127, volume)]))

    def set_reverb(self, amount: int = 40, channel: Optional[int] = None):
        """CC 91 — reverb send."""
        ch = (channel if channel is not None else self._channel) & 0x0F
        self._add(self._cursor, bytes([0xB0 | ch, 91, min(127, amount)]))

    # ── Note writing ─────────────────────────────────────────────────────────

    def note(self, note_midi: int, duration_beats: float = 1.0,
             velocity: int = 90, channel: Optional[int] = None):
        """Add a single note at current cursor position."""
        ch = (channel if channel is not None else self._channel) & 0x0F
        dur_ticks = int(duration_beats * self._tpb)
        self._add(self._cursor, bytes([0x90 | ch, note_midi & 0x7F, velocity & 0x7F]))
        self._add(self._cursor + dur_ticks, bytes([0x80 | ch, note_midi & 0x7F, 0]))
        self._cursor += dur_ticks

    def rest(self, duration_beats: float = 1.0):
        """Advance cursor without playing anything."""
        self._cursor += int(duration_beats * self._tpb)

    def chord(self, notes: List[int], duration_beats: float = 1.0,
              velocity: int = 85, channel: Optional[int] = None):
        """Play multiple notes simultaneously."""
        ch = (channel if channel is not None else self._channel) & 0x0F
        dur_ticks = int(duration_beats * self._tpb)
        for n in notes:
            self._add(self._cursor, bytes([0x90 | ch, n & 0x7F, velocity & 0x7F]))
            self._add(self._cursor + dur_ticks, bytes([0x80 | ch, n & 0x7F, 0]))
        self._cursor += dur_ticks

    def arpeggio(self, notes: List[int], note_duration: float = 0.25,
                 repeat: int = 1, velocity: int = 80, channel: Optional[int] = None):
        """Play notes in sequence (arpeggio) for 'repeat' loops."""
        for _ in range(repeat):
            for n in notes:
                self.note(n, note_duration, velocity, channel)

    def drum_hit(self, drum: str, velocity: int = 100):
        """Add a single drum hit on channel 10 (percussion)."""
        note_num = GM_DRUMS.get(drum.lower(), 36)
        self._add(self._cursor, bytes([0x99, note_num, velocity]))
        self._add(self._cursor + self._tpb // 8, bytes([0x89, note_num, 0]))
        self._cursor += self._tpb // 4  # advance by 1/4 beat

    def drum_pattern(self, pattern: Dict[str, str], bars: int = 4):
        """
        Play a drum pattern for N bars.
        pattern = {"kick": "X...X...X...X...", "snare": "....X.......X...", "hihat_closed": "X.X.X.X.X.X.X.X."}
        'X' = hit, '.' = rest. Each char = 1/16th note.
        """
        ticks_per_16th = self._tpb // 4
        # Find max length
        max_len = max(len(v) for v in pattern.values()) if pattern else 0
        total_ticks = max_len * bars * ticks_per_16th

        # Build hit schedule
        schedule: Dict[int, List[tuple]] = {}
        for drum_name, hits in pattern.items():
            note_num = GM_DRUMS.get(drum_name.lower(), 36)
            for bar in range(bars):
                for step, ch in enumerate(hits):
                    if ch.upper() == "X":
                        tick = self._cursor + bar * max_len * ticks_per_16th + step * ticks_per_16th
                        schedule.setdefault(tick, []).append((note_num, 100))
                        off_tick = tick + ticks_per_16th // 2
                        schedule.setdefault(off_tick, []).append((-note_num, 0))  # negative = note off

        for tick in sorted(schedule):
            for note_num, vel in schedule[tick]:
                if note_num > 0:
                    self._add(tick, bytes([0x99, note_num, vel]))
                else:
                    self._add(tick, bytes([0x89, -note_num, 0]))

        self._cursor += total_ticks

    # ── High-level generators ─────────────────────────────────────────────────

    def add_melody(self, notes_list: List[Dict[str, Any]], channel: Optional[int] = None):
        """
        Add a melody from a list of dicts:
        {"note": "C4", "duration": 1.0, "velocity": 90, "rest_after": 0.0}
        or {"chord": ["C4","E4","G4"], "duration": 2.0}
        """
        for item in notes_list:
            if "chord" in item:
                midis = [note_to_midi(n) for n in item["chord"]]
                self.chord(midis, item.get("duration", 1.0),
                           item.get("velocity", 85), channel)
            elif "note" in item:
                self.note(note_to_midi(item["note"]),
                          item.get("duration", 1.0),
                          item.get("velocity", 90), channel)
            if item.get("rest_after", 0) > 0:
                self.rest(item["rest_after"])

    def generate_ambient(self, root: str = "A", octave: int = 3,
                         scale: str = "pentatonic_minor", bars: int = 8,
                         density: float = 0.4, velocity_range=(40, 70),
                         seed: Optional[int] = None):
        """
        Generate a generative ambient melody using random walk on a scale.
        density: 0.0–1.0, probability of playing vs rest per 1/4 note step.
        """
        rng = random.Random(seed)
        notes = scale_notes(root, octave, scale, num_octaves=2)
        steps = bars * 4  # quarter note steps
        idx = len(notes) // 2

        for _ in range(steps):
            if rng.random() < density:
                # Random walk: move ±1-2 steps
                idx = max(0, min(len(notes) - 1, idx + rng.randint(-2, 2)))
                vel = rng.randint(*velocity_range)
                dur = rng.choice([0.5, 0.5, 1.0, 1.5, 2.0])
                self.note(notes[idx], dur, vel)
            else:
                self.rest(1.0)

    def generate_chord_progression(self, progression: List[Dict], bars_each: int = 2):
        """
        Play chord progression.
        progression = [
          {"root": "C", "octave": 3, "type": "maj"},
          {"root": "A", "octave": 3, "type": "min"},
          ...
        ]
        """
        for chord_def in progression:
            notes = chord_notes(
                chord_def["root"],
                chord_def.get("octave", 3),
                chord_def.get("type", "maj"),
            )
            self.chord(notes, bars_each * 4, chord_def.get("velocity", 70))

    # ── Serialise ─────────────────────────────────────────────────────────────

    def compile(self) -> bytes:
        """Compile track to raw MIDI track chunk bytes."""
        # Sort events by tick
        sorted_events = sorted(self._events, key=lambda e: e[0])

        track_data = bytearray()
        prev_tick = 0
        for tick, data in sorted_events:
            delta = tick - prev_tick
            track_data.extend(_varlen(delta))
            track_data.extend(data)
            prev_tick = tick

        # End of track
        track_data.extend(b"\x00\xFF\x2F\x00")
        return b"MTrk" + struct.pack(">I", len(track_data)) + bytes(track_data)


# ─────────────────────────────────────────────────────────────────────────────
# Multi-track composer
# ─────────────────────────────────────────────────────────────────────────────

class MidiComposer:
    """
    Multi-track MIDI composer (Type 1).
    Usage:
        c = MidiComposer(bpm=120)
        melody = c.add_track("Melody", channel=0, instrument="synth_lead")
        bass   = c.add_track("Bass",   channel=1, instrument="electric_bass")
        drums  = c.add_track("Drums",  channel=9)
        melody.add_melody([...])
        bass.generate_chord_progression([...])
        drums.drum_pattern({"kick": "X...X...", "snare": "....X..."})
        c.save("output.mid")
    """

    def __init__(self, bpm: int = 120, ticks_per_beat: int = 480):
        self.bpm = bpm
        self.ticks_per_beat = ticks_per_beat
        self._tracks: List[MidiTrack] = []
        # Tempo track (track 0 in Type 1)
        self._tempo_track = MidiTrack("Tempo", ticks_per_beat=ticks_per_beat)
        self._tempo_track.set_tempo(bpm)

    def add_track(self, name: str = "", channel: int = 0,
                  instrument=None, volume: int = 100, reverb: int = 20) -> MidiTrack:
        t = MidiTrack(name, channel, self.ticks_per_beat)
        t.set_name(name)
        if instrument is not None:
            t.set_instrument(instrument)
        t.set_volume(volume)
        if reverb:
            t.set_reverb(reverb)
        self._tracks.append(t)
        return t

    def save(self, output_path: str) -> str:
        """Compile and save a Type 1 MIDI file."""
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        all_tracks = [self._tempo_track] + self._tracks
        num_tracks = len(all_tracks)

        header = b"MThd" + struct.pack(">IHHH", 6, 1, num_tracks, self.ticks_per_beat)
        body = b"".join(t.compile() for t in all_tracks)

        with open(output_path, "wb") as f:
            f.write(header + body)

        return output_path

    # ── Convenience factories ─────────────────────────────────────────────────

    @classmethod
    def stalk_ambient(cls, output_path: str, seed: int = 42) -> str:
        """Generate a STALKER-style dark ambient track."""
        c = cls(bpm=60, ticks_per_beat=480)
        pad  = c.add_track("Pad",    channel=0, instrument="new_age_pad",   volume=55, reverb=80)
        lead = c.add_track("Lead",   channel=1, instrument="atmosphere",    volume=45, reverb=90)
        bass = c.add_track("Bass",   channel=2, instrument="contrabass",    volume=60, reverb=30)
        drm  = c.add_track("Perc",   channel=9, volume=70)

        pad.generate_chord_progression([
            {"root": "A", "octave": 2, "type": "min", "velocity": 50},
            {"root": "F", "octave": 2, "type": "maj", "velocity": 45},
            {"root": "G", "octave": 2, "type": "min", "velocity": 50},
            {"root": "E", "octave": 2, "type": "min", "velocity": 40},
        ], bars_each=4)

        lead.generate_ambient("A", 3, "pentatonic_minor", bars=16,
                              density=0.3, velocity_range=(30, 55), seed=seed)

        bass.add_melody([
            {"note": "A2", "duration": 4.0, "velocity": 55},
            {"note": "F2", "duration": 4.0, "velocity": 50},
            {"note": "G2", "duration": 4.0, "velocity": 55},
            {"note": "E2", "duration": 4.0, "velocity": 45},
        ])

        drm.drum_pattern({
            "kick":   "X...............X...............",
            "shaker": "....X.......X.......X.......X...",
        }, bars=4)

        return c.save(output_path)

    @classmethod
    def minecraft_chiptune(cls, output_path: str) -> str:
        """Generate a cheerful Minecraft-style chiptune."""
        c = cls(bpm=140, ticks_per_beat=480)
        mel  = c.add_track("Melody", channel=0, instrument="glockenspiel", volume=90)
        bass = c.add_track("Bass",   channel=1, instrument="electric_bass",volume=75)
        drm  = c.add_track("Drums",  channel=9, volume=80)

        # C major pentatonic melody
        mel.add_melody([
            {"note": "E5", "duration": 0.5}, {"note": "G5", "duration": 0.5},
            {"note": "A5", "duration": 1.0}, {"note": "G5", "duration": 0.5},
            {"note": "E5", "duration": 0.5}, {"note": "C5", "duration": 1.0},
            {"note": "D5", "duration": 0.5}, {"note": "E5", "duration": 0.5},
            {"note": "G5", "duration": 1.5}, {"note": "A5", "duration": 0.5},
            {"note": "G5", "duration": 1.0}, {"note": "E5", "duration": 1.0},
        ])

        bass.add_melody([
            {"note": "C3", "duration": 2.0}, {"note": "F3", "duration": 2.0},
            {"note": "G3", "duration": 2.0}, {"note": "C3", "duration": 2.0},
        ])

        drm.drum_pattern({
            "kick":          "X...X...X...X...",
            "snare":         "....X.......X...",
            "hihat_closed":  "X.X.X.X.X.X.X.X.",
        }, bars=2)

        return c.save(output_path)


# ─────────────────────────────────────────────────────────────────────────────
# Public API (called by MCP server)
# ─────────────────────────────────────────────────────────────────────────────

def compose_midi(
    output_path: str,
    bpm: int = 120,
    tracks: Optional[List[Dict]] = None,
    preset: Optional[str] = None,
    seed: int = 42,
) -> dict:
    """
    Compose a MIDI file from track definitions or a preset.

    preset: "stalk_ambient" | "minecraft_chiptune"

    tracks: list of track dicts:
    {
      "name": "Melody",
      "channel": 0,
      "instrument": "synth_lead",   # GM name or number
      "volume": 90,
      "reverb": 30,
      "melody": [...],              # list of note dicts
      "chord_progression": [...],   # list of chord dicts
      "ambient": {"root":"A","octave":3,"scale":"pentatonic_minor","bars":8},
      "drum_pattern": {"kick":"X...X...","snare":"....X..."},
      "drum_bars": 4,
      "arpeggio": {"notes":["C4","E4","G4"],"note_duration":0.25,"repeat":4}
    }
    """
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    if preset == "stalk_ambient":
        path = MidiComposer.stalk_ambient(output_path, seed=seed)
        return {"path": path, "preset": preset, "bpm": 60}

    if preset == "minecraft_chiptune":
        path = MidiComposer.minecraft_chiptune(output_path)
        return {"path": path, "preset": preset, "bpm": 140}

    composer = MidiComposer(bpm=bpm)
    tracks = tracks or []

    for td in tracks:
        t = composer.add_track(
            name=td.get("name", "Track"),
            channel=td.get("channel", 0),
            instrument=td.get("instrument"),
            volume=td.get("volume", 100),
            reverb=td.get("reverb", 20),
        )
        if "melody" in td:
            t.add_melody(td["melody"], td.get("channel"))
        if "chord_progression" in td:
            t.generate_chord_progression(td["chord_progression"], td.get("bars_each", 2))
        if "ambient" in td:
            a = td["ambient"]
            t.generate_ambient(
                root=a.get("root", "A"), octave=a.get("octave", 3),
                scale=a.get("scale", "pentatonic_minor"), bars=a.get("bars", 8),
                density=a.get("density", 0.4), seed=seed,
            )
        if "arpeggio" in td:
            ar = td["arpeggio"]
            midis = [note_to_midi(n) for n in ar.get("notes", [])]
            t.arpeggio(midis, ar.get("note_duration", 0.25), ar.get("repeat", 1))
        if "drum_pattern" in td:
            t.drum_pattern(td["drum_pattern"], td.get("drum_bars", 4))

    path = composer.save(output_path)
    return {
        "path": path,
        "bpm": bpm,
        "tracks": len(tracks),
        "hint": "Open with any MIDI player (VLC, Windows Media Player) or DAW",
    }


# ─────────────────────────────────────────────────────────────────────────────
# Self-test
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import pathlib
    out_dir = pathlib.Path("output")
    out_dir.mkdir(exist_ok=True)

    path1 = MidiComposer.stalk_ambient(str(out_dir / "stalk_ambient.mid"))
    print(f"✓ STALKER ambient: {path1}")

    path2 = MidiComposer.minecraft_chiptune(str(out_dir / "mc_chiptune.mid"))
    print(f"✓ Minecraft chiptune: {path2}")
