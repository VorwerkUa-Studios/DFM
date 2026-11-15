# Decod — Universal Headless Reverse Engineering & Modding Engine
# 🛠 Дзеркальний RE-рушій та MCP-сервер

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)](https://www.python.org/)
[![MCP](https://img.shields.io/badge/MCP-JSON--RPC%202.0-purple.svg)](#)
[![Tools](https://img.shields.io/badge/Tools-46%20Active-orange.svg)](#)

[**Mnemosyne Desktop Host**](https://github.com/VorwerkUa2/Mnemosyne) | [**Посібник користувача**](https://github.com/VorwerkUa2/Mnemosyne/blob/main/SETUP_GUIDE.md)

---

## Огляд

**Decod (DFM)** — це кросплатформний (Windows / Linux) headless-інструментарій для зворотного інжинірингу, динамічного аналізу пам'яті, дампу процесів (Scylla), дизасемблювання, патчингу, конвертації медіа (FFmpeg), інструментів розробки та модингу Unreal Engine 5.

Decod функціонує як незалежний **Model Context Protocol (MCP)** сервер через `stdio` (JSON-RPC 2.0) для підключення до **[Mnemosyne](https://github.com/VorwerkUa2/Mnemosyne)** та **Claude Code CLI**.

---

## Швидке встановлення залежностей

Запустіть універсальний інсталятор:
```bash
python setup_decod.py --install-all
```
Скрипт автоматично:
- Встановить Python-пакети (`frida`, `lief`, `capstone`, `psutil`, `rich`, `pydantic`, `pyright`).
- Перевірить або встановить `rust-analyzer` через `rustup`.
- Завантажить портативні бінарники `repak` та `uesave` у `Decod/bin/`.
- Збілдить бібліотеку захисту від анти-відлагодження `libstealth.so` на Linux.

Перевірка статусу компонентів:
```bash
python setup_decod.py --status
```

---

## Повний каталог 46 інструментів MCP

### 1. ⚡ Code Intelligence & Token Optimization (4 інструменти)
- `inspect_code_structure(file_path)`: Regex AST аналіз класів, методів, функцій і типів для Rust, Python, C/C++, C#, Go, Lua. Дозволяє вивчити структуру файлу без зчитування тисяч рядків.
- `extract_function_definition(file_path, symbol_name)`: Хірургічне вилучення тіла однієї функції за її іменем. Економить до 85% контексту.
- `check_code_diagnostics(project_or_file)`: Запуск миттєвої перевірки компілятором (`cargo check`, `py_compile`, `pyright`).
- `run_git_summary(repo_path)`: Компактне резюме стану гілки, змінених файлів та diffstat без зайвих токенів.

### 2. 🔍 Статичний аналіз, Дизасемблювання та Декомпіляція (7 інструментів)
- `decompile_function_to_c(binary_path, function_or_address)`: Відновлення C-псевдокоду функцій із аналізом змінних та викликів.
- `disassemble_dll_function(dll_path, function_or_address)`: Покроковий асемблерний аналіз x86/x64 інструкцій через Capstone.
- `inspect_dll(dll_path)`: Детальний розбір заголовків PE/ELF, архітектури, таблиць імпорту/експорту та CLR.
- `patch_binary_bytes(file_path, offset, hex_bytes)`: Безпечний байт-патчинг бінарників з автоматичним бекапом (`.bak`).
- `demangle_cpp_symbol(symbol)`: Відновлення зашифрованих C++ та Rust імен функцій у читабельний вигляд.
- `search_binary_strings(binary_path, query)`: Пошук ASCII та Unicode UTF-16 рядків із прив'язкою до офсетів і RVA.
- `scan_aob_pattern(binary_path, pattern)`: Пошук сигнатур Array of Bytes із масками `??` для знаходження функцій після оновлень ігор.

### 3. 🧠 Динаміка, Пам'ять та Frida Hooking (6 інструментів)
- `inject_frida_script(target_process, script_code)`: Динамічне впровадження хуків у пам'ять процесу в реальному часі.
- `trace_function_calls(target_process, function_pattern)`: Трасування викликів нативних функцій процесу з аргументами.
- `dump_process_memory_scylla(process_name_or_pid, output_path)`: Повний дамп образу процесу з пам'яті з відновленням таблиць секцій та IAT.
- `scan_process_pattern(process_name_or_pid, aob_pattern)`: Пошук сигнатур безпосередньо у віртуальній пам'яті запущеного процесу.
- `read_process_memory_slice(process_name_or_pid, address, size)`: Безпечне читання зрізу віртуальної пам'яті.
- `write_process_memory_slice(process_name_or_pid, address, hex_data)`: Запис даних у пам'ять процесу.

### 4. 🎮 Unreal Engine 5 Модинг та Асети (5 інструментів)
- `detect_game_engine(game_dir)`: Автоматичне визначення рушія гри (UE5, Unity, Godot, Source).
- `unpack_ue_pak(pak_path, output_dir, aes_key)`: Розпакування ігрових контейнерів UE5 PAK (через `repak`).
- `pack_ue_pak(input_dir, output_pak, version, aes_key)`: Створення нових PAK-модів для ігор.
- `unpack_ue_utoc(utoc_path, output_dir, aes_key)`: Робота з IoStore контейнерами UE5 (UTOC / UCAS).
- `read_ue_savefile(sav_path)` / `patch_ue_savefile(...)`: Десеріалізація та редагування збережень UE5 (через `uesave`).

### 5. 🎵 Мультимедіа, FFmpeg та 3D Моделі (6 інструментів)
- `convert_media_file(input, output)`: Конвертація аудіо/відео файлів через системний FFmpeg (OGG, WAV, MP3, MP4, WebM тощо).
- `extract_audio_from_video(video, output_audio)`: Витягування аудіодоріжок із відеофайлів.
- `inspect_media_file(file_path)`: Аналіз бітрейту, кодеків та параметрів через `ffprobe`.
- `compose_midi_music(bpm, instrument, notes, output_path)`: Програмна композиція повноцінних `.mid` файлів.
- `inspect_3d_model(model_path)`: Аналіз геометрії Wavefront OBJ 3D-моделей (вершини, полігони, матеріали).
- `create_minecraft_block_model(name, texture)`: Генерація валідних JSON-моделей блоків для Minecraft.

### 6. 🌐 Локалізація та Переклад (2 інструменти)
- `extract_game_strings(file_path)`: Парсинг локалізаційних рядків із мовних файлів ігор (JSON/CSV).
- `save_game_translation(translated_dict, output_path)`: Збереження перекладених рядків у цільовий мовний файл.

---

## Запуск MCP-сервера напряму

```bash
python core/mcp_server.py
```
Сервер починає обробку JSON-RPC 2.0 запитів через `stdin/stdout`.
