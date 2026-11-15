# Decod (DFM) — Universal Headless Reverse Engineering & Modding Engine
# 🛠 Універсальний RE-рушій та MCP-сервер

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)](https://www.python.org/)
[![MCP](https://img.shields.io/badge/MCP-JSON--RPC%202.0-purple.svg)](#)
[![Tools](https://img.shields.io/badge/Tools-46%20Active-orange.svg)](#)

[**Mnemosyne Desktop Host**](https://github.com/VorwerkUa2/Mnemosyne) | [**Повний посібник / Complete Guide**](https://github.com/VorwerkUa2/Mnemosyne/blob/main/SETUP_GUIDE.md)

[**🇺🇦 Українська версія**](#-українська-версія) | [**🇬🇧 English Version**](#-english-version)

---

## 🇺🇦 Українська версія

**Decod (DFM)** — це кросплатформний (Windows / Linux) headless-інструментарій для зворотного інжинірингу, динамічного аналізу пам'яті, дампу процесів (Scylla), дизасемблювання, патчингу, конвертації медіа (FFmpeg), інструментів розробки та модингу ігор Unreal Engine 5.

Decod функціонує як незалежний **Model Context Protocol (MCP)** сервер через `stdio` (JSON-RPC 2.0) для підключення до **[Mnemosyne](https://github.com/VorwerkUa2/Mnemosyne)** та **Claude Code CLI**.

### ⚡ Швидке встановлення залежностей

Запустіть універсальний інсталятор у терміналі папки Decod:
```bash
python setup_decod.py --install-all
```
Скрипт автоматично:
- Встановить Python-пакети (`frida`, `lief`, `capstone`, `psutil`, `rich`, `pydantic`, `pyright`).
- Перевірить та встановить `rust-analyzer` через `rustup`.
- Завантажить портативні бінарники `repak` та `uesave` у папку `Decod/bin/`.
- Збілдить бібліотеку захисту від анти-відлагодження `libstealth.so` на Linux.

Перевірка статусу компонентів у JSON:
```bash
python setup_decod.py --status
```

---

### 🛠 Повний каталог 46 інструментів MCP

#### 1. ⚡ Code Intelligence та Економія токенів (4 інструменти)
- `inspect_code_structure(file_path)`: Regex AST аналіз класів, методів, функцій і типів для Rust, Python, C/C++, C#, Go, Lua. Дозволяє вивчити структуру файлу без зчитування тисяч рядків.
- `extract_function_definition(file_path, symbol_name)`: Хірургічне вилучення тіла однієї функції за її іменем. Економить до 85% контексту.
- `check_code_diagnostics(project_or_file)`: Запуск миттєвої перевірки компілятором (`cargo check`, `py_compile`, `pyright`).
- `run_git_summary(repo_path)`: Компактне резюме стану гілки, змінених файлів та diffstat без зайвих токенів.

#### 2. 🔍 Статичний аналіз, Дизасемблювання та Декомпіляція (7 інструментів)
- `decompile_function_to_c(binary_path, function_or_address)`: Відновлення C-псевдокоду функцій із аналізом змінних та викликів.
- `disassemble_dll_function(dll_path, function_or_address)`: Покроковий асемблерний аналіз x86/x64 інструкцій через Capstone.
- `inspect_dll(dll_path)`: Детальний розбір заголовків PE/ELF/Mach-O, архітектури, таблиць імпорту/експорту та CLR.
- `patch_binary_bytes(file_path, offset, hex_bytes)`: Безпечний байт-патчинг бінарників з автоматичним бекапом (`.bak`).
- `demangle_cpp_symbol(symbol)`: Відновлення зашифрованих C++ та Rust імен функцій у читабельний вигляд.
- `search_binary_strings(binary_path, query)`: Пошук ASCII та Unicode UTF-16 рядків із прив'язкою до офсетів і RVA.
- `scan_aob_pattern(binary_path, pattern)`: Пошук сигнатур Array of Bytes із масками `??` для знаходження функцій після оновлень ігор.

#### 3. 🧠 Динаміка, Пам'ять та Frida Hooking (6 інструментів)
- `inject_frida_script(target_process, script_code)`: Динамічне впровадження хуків у пам'ять процесу в реальному часі.
- `trace_function_calls(target_process, function_pattern)`: Трасування викликів нативних функцій процесу з аргументами.
- `dump_process_memory_scylla(process_name_or_pid, output_path)`: Повний дамп образу процесу з пам'яті з відновленням таблиць секцій та IAT.
- `scan_process_pattern(process_name_or_pid, aob_pattern)`: Пошук сигнатур безпосередньо у віртуальній пам'яті запущеного процесу.
- `read_process_memory_slice(process_name_or_pid, address, size)`: Безпечне читання зрізу віртуальної пам'яті.
- `write_process_memory_slice(process_name_or_pid, address, hex_data)`: Запис даних у пам'ять процесу.

#### 4. 🎮 Unreal Engine 5 Модинг та Асети (5 інструментів)
- `detect_game_engine(game_dir)`: Автоматичне визначення рушія гри (UE5, Unity, Godot, Source).
- `unpack_ue_pak(pak_path, output_dir, aes_key)`: Розпакування ігрових контейнерів UE5 PAK (через `repak`).
- `pack_ue_pak(input_dir, output_pak, version, aes_key)`: Створення нових PAK-модів для ігор.
- `unpack_ue_utoc(utoc_path, output_dir, aes_key)`: Робота з IoStore контейнерами UE5 (UTOC / UCAS).
- `read_ue_savefile(sav_path)` / `patch_ue_savefile(...)`: Десеріалізація та редагування збережень UE5 (через `uesave`).

#### 5. 🎵 Мультимедіа, FFmpeg та 3D Моделі (6 інструментів)
- `convert_media_file(input, output)`: Конвертація аудіо/відео файлів через системний FFmpeg (OGG, WAV, MP3, MP4, WebM тощо).
- `extract_audio_from_video(video, output_audio)`: Витягування аудіодоріжок із відеофайлів.
- `inspect_media_file(file_path)`: Аналіз бітрейту, кодеків та параметрів через `ffprobe`.
- `compose_midi_music(bpm, instrument, notes, output_path)`: Програмна композиція повноцінних `.mid` файлів.
- `inspect_3d_model(model_path)`: Аналіз геометрії Wavefront OBJ 3D-моделей (вершини, полігони, матеріали).
- `create_minecraft_block_model(name, texture)`: Генерація валідних JSON-моделей блоків для Minecraft.

#### 6. 🌐 Локалізація та Переклад (2 інструменти)
- `extract_game_strings(file_path)`: Парсинг локалізаційних рядків із мовних файлів ігор (JSON/CSV).
- `save_game_translation(translated_dict, output_path)`: Збереження перекладених рядків у цільовий мовний файл.

---

## 🇬🇧 English Version

**Decod (DFM)** is a cross-platform (Windows / Linux) headless reverse engineering, dynamic memory analysis, process dumping (Scylla), disassembly, binary patching, multimedia conversion (FFmpeg), and Unreal Engine 5 modding toolkit.

Decod operates as an independent **Model Context Protocol (MCP)** server over `stdio` (JSON-RPC 2.0) designed to connect seamlessly with **[Mnemosyne](https://github.com/VorwerkUa2/Mnemosyne)** and **Claude Code CLI**.

### ⚡ Quick Dependency Setup

Run the universal installer in the Decod folder:
```bash
python setup_decod.py --install-all
```
The script will automatically:
- Install Python dependencies (`frida`, `lief`, `capstone`, `psutil`, `rich`, `pydantic`, `pyright`).
- Verify and install `rust-analyzer` via `rustup`.
- Download portable `repak` and `uesave` binaries into `Decod/bin/`.
- Compile the anti-anti-debugging library `libstealth.so` on Linux.

Check component status in JSON format:
```bash
python setup_decod.py --status
```

---

### 🛠 Complete 46 MCP Tools Catalog

#### 1. ⚡ Code Intelligence & Token Optimization (4 tools)
- `inspect_code_structure(file_path)`: Regex AST symbol outline (classes, methods, functions, types) for Rust, Python, C/C++, C#, Go, Lua without reading entire thousand-line files into model context.
- `extract_function_definition(file_path, symbol_name)`: Surgical extraction of targeted function bodies, saving up to 85% context tokens.
- `check_code_diagnostics(project_or_file)`: Runs compiler and syntax checks (`cargo check`, `py_compile`, `pyright`).
- `run_git_summary(repo_path)`: Token-compact git branch status, modified files, and diffstat summary.

#### 2. 🔍 Static Analysis, Disassembly & Decompilation (7 tools)
- `decompile_function_to_c(binary_path, function_or_address)`: Recovers C pseudocode with variable and control-flow reconstruction.
- `disassemble_dll_function(dll_path, function_or_address)`: Instruction-by-instruction x86/x64 disassembly via Capstone.
- `inspect_dll(dll_path)`: Analyzes PE/ELF/Mach-O headers, architecture, import/export tables, and .NET CLR metadata.
- `patch_binary_bytes(file_path, offset, hex_bytes)`: Safe binary byte patching with automated `.bak` backup generation.
- `demangle_cpp_symbol(symbol)`: Demangles mangled C++ and Rust function signatures into human-readable prototypes.
- `search_binary_strings(binary_path, query)`: Fast search for ASCII and Unicode UTF-16 strings linked to offsets and RVAs.
- `scan_aob_pattern(binary_path, pattern)`: Array-of-Bytes wildcard signature scanning with `??` mask support for locating functions after game updates.

#### 3. 🧠 Dynamics, Memory & Frida Hooking (6 tools)
- `inject_frida_script(target_process, script_code)`: Dynamically injects live runtime hooks into target processes.
- `trace_function_calls(target_process, function_pattern)`: Traces native function calls with argument inspection.
- `dump_process_memory_scylla(process_name_or_pid, output_path)`: Full process image dump from memory with Section Table and Import Address Table (IAT) reconstruction.
- `scan_process_pattern(process_name_or_pid, aob_pattern)`: Scans for binary byte patterns directly in active process virtual memory.
- `read_process_memory_slice(process_name_or_pid, address, size)`: Safe reading of virtual memory slices.
- `write_process_memory_slice(process_name_or_pid, address, hex_data)`: Writes byte sequences into target process memory.

#### 4. 🎮 Unreal Engine 5 Modding & Assets (5 tools)
- `detect_game_engine(game_dir)`: Identifies game engines automatically (UE5, Unity, Godot, Source).
- `unpack_ue_pak(pak_path, output_dir, aes_key)`: Unpacks Unreal Engine PAK containers (powered by `repak`).
- `pack_ue_pak(input_dir, output_pak, version, aes_key)`: Builds new PAK game mods.
- `unpack_ue_utoc(utoc_path, output_dir, aes_key)`: Handles UE5 IoStore containers (UTOC / UCAS).
- `read_ue_savefile(sav_path)` / `patch_ue_savefile(...)`: Deserializes and edits UE GVAS savefiles (via `uesave`).

#### 5. 🎵 Multimedia, FFmpeg & 3D Models (6 tools)
- `convert_media_file(input, output)`: Converts audio/video formats using system FFmpeg (OGG, WAV, MP3, MP4, WebM).
- `extract_audio_from_video(video, output_audio)`: Extracts audio streams from video files and cutscenes.
- `inspect_media_file(file_path)`: Analyzes bitrates, codecs, and container metadata via `ffprobe`.
- `compose_midi_music(bpm, instrument, notes, output_path)`: Programmatically composes valid `.mid` music files.
- `inspect_3d_model(model_path)`: Parses Wavefront OBJ 3D model geometry (vertices, faces, materials, bounding box).
- `create_minecraft_block_model(name, texture)`: Generates valid Minecraft JSON block models.

#### 6. 🌐 Game Localization (2 tools)
- `extract_game_strings(file_path)`: Parses localization strings from game text files (JSON/CSV).
- `save_game_translation(translated_dict, output_path)`: Saves translated strings into game-compatible formats.

---

## 🚀 Running MCP Server Directly / Запуск сервера напряму

```bash
python core/mcp_server.py
```
The server handles JSON-RPC 2.0 requests over standard input/output (`stdio`).
Сервер обробляє JSON-RPC 2.0 запити через стандартні потоки `stdin/stdout`.
