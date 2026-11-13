# Decod — Universal Headless Reverse Engineering Engine

**Decod** — це кросплатформний (Windows / Linux) headless-інструментарій для зворотного інжинірингу, динамічного аналізу, дампу процесів, патчингу, конвертації медіа (FFmpeg) та розпакування ігрових асетів.

Розроблений спеціально як бекенд та MCP-сервер для **[Mnemosyne](file:///C:/Users/knyaz/Desktop/Mnemosyne)** та агентів на базі **Claude Code / FreeLLMAPI**.

---

## Архітектура системи

```
       ┌────────────────────────────────────────────────────────┐
       │             Mnemosyne (Rust Host Application)          │
       │       Керує сесіями Claude Code через FreeLLMAPI       │
       └───────────────────────────┬────────────────────────────┘
                                   │ JSON-RPC (MCP)
                                   ▼
       ┌────────────────────────────────────────────────────────┐
       │             Decod MCP Server (30 Інструментів)         │
       └─────┬─────────────────────┼──────────────────────┬─────┘
             │                     │                      │
             ▼                     ▼                      ▼
    [ ДИНАМІКА & СТЕЛС ]    [ СТАТИКА & ДЕКОМПІЛЯЦІЯ ]    [ АСЕТИ, МЕДІА & РУШІЇ ]
    - Frida Runner (x86/64) - Headless C Decompiler       - FFmpeg Audio/Video
    - Anti-Anti-Debug       - Capstone Disassembler       - MIDI Music Composer
    - libstealth (Linux)    - LIEF Process Dumper (Scylla)- 3D Models (OBJ, Minecraft)
    - Byte Patcher (.bak)   - SigScan & String Extractor  - Game Localization Helper
                            - C++ / Rust Demangler        - UE5, Unity, Godot, Source
```

---

## Повний список інструментів MCP-сервера (30 інструментів)

### 1. Медіа, Музика та 3D-Моделі:
* `convert_media_file(input, output)` — конвертація аудіо/відео через системний FFmpeg (OGG, WAV, MP3, MP4, WebM тощо).
* `extract_audio_from_video(video, output_audio)` — витягування звукових доріжок із катсцен або трейлерів гри.
* `inspect_media_file(file_path)` — перегляд бітрейту, кодеків, частоти дискретизації через ffprobe.
* `compose_midi_music(bpm, instrument, notes, output_path)` — генерація повноцінних `.mid` файлів мелодій за нотами ШІ.
* `inspect_3d_model(model_path)` — аналіз Wavefront OBJ файлів (вершини, полігони, матеріали, Bounding Box).
* `create_minecraft_block_model(name, texture)` — створення валідних 3D JSON-моделей блоків для Minecraft.

### 2. Локалізація та Переклад ігор:
* `extract_game_strings(file_path)` — витягування текстових рядків із мовних файлів гри (JSON/CSV).
* `save_game_translation(translated_dict, output_path)` — збереження перекладених текстів у формат гри (наприклад, `uk_ua.json`).

### 3. Декомпіляція, Дизасемблювання та Патчинг:
* `decompile_function_to_c(binary_path, function_or_address)` — відновлює C-псевдокод функцій зі змінними та циклами.
* `disassemble_dll_function(dll_path, function_or_address)` — покроковий розбір машинного коду на асемблер через Capstone.
* `inspect_dll(dll_path)` — аналіз архітектури (x86/x64), експорту, імпорту та .NET CLR заголовків.
* `patch_binary_bytes(file_path, offset, hex_bytes)` — безпечний патчинг бінарників з автоматичним створенням `.bak`.
* `demangle_cpp_symbol(symbol)` — відновлює зашифровані C++ / Rust імена функцій у читабельні сигнатури.

### 4. Пошук сигнатур та Рядків:
* `search_binary_strings(binary_path, query)` — миттєвий пошук ASCII та Unicode UTF-16 рядків із прив'язкою до офсетів та RVA.
* `scan_aob_pattern(binary_path, pattern)` — пошук сигнатур Array of Bytes з масками `??` для знаходження функцій після оновлень ігор.

### 5. Ігрові рушії та Формати:
* `detect_game_engine(game_dir)` — автоматичне визначення рушія (UE5, Unity, Godot, Source, Spore).
* `unpack_ue_pak(pak_path, output_dir, aes_key)` — розпакування архівів S.T.A.L.K.E.R. 2 / UE5 (через `repak.exe`).
* `list_ue_pak(pak_path, aes_key)` — перегляд списку файлів у паку без розпакування.
* `convert_ue_save_to_json(sav_path, json_out_path)` — конвертація сейвів UE5 у JSON (через `uesave.exe`).
* `convert_json_to_ue_save(json_in_path, sav_out_path)` — збірка модифікованого JSON назад у `.sav`.
* `unpack_jar_package(jar_path, output_dir)` — розпакування Java JAR/APK (Minecraft, моди, Android).
* `read_minecraft_nbt(nbt_path)` — парсинг збережень світів, чанків та гравців Minecraft у JSON.
* `unpack_electron_asar(asar_path, output_dir)` — витягування 100% вихідного коду (JS/HTML/CSS) з Discord, VS Code, Obsidian.
* `unpack_godot_pck(pck_path, output_dir)` — розпакування пакетів Godot Engine 3/4.
* `unpack_source_vpk(vpk_path, output_dir)` — розпакування Valve Source VPK (Half-Life, Portal, CS).
* `unpack_dbpf_package(package_path, output_dir)` — розпакування архівів Spore та The Sims.
* `inspect_unity_game(game_dir)` — діагностика Unity (Mono vs IL2CPP).

### 6. Динаміка та Пам'ять:
* `dump_process(pid, output_path)` — зняття дампу пам'яті та реконструкція заголовків бінарника (LIEF).
* `inject_frida_stealth(target)` — інжекція Frida з анти-анти-дебагом.
* `list_processes(filter_name)` — огляд запущених процесів системи.

---

## Встановлення залежностей

```bash
pip install -r requirements.txt
```
