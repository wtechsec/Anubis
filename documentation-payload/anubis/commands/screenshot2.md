+++
title = "screenshot2"
chapter = false
weight = 100
hidden = false
+++

## Summary

Captures the full virtual screen on Windows and sends the image to Mythic as a PNG file. Implemented entirely with **pure ctypes** — no `pywin32` or `Pillow` required on the target.

- **Platform**: Windows only
- **Needs Admin**: No
- **MITRE ATT&CK**: T1113 — Screen Capture
- **Dependencies**: None (stdlib + ctypes only)
- **Version**: 1.0
- **Author**: @wtechsec

### Arguments

None.

## Usage

```
screenshot2
```

## Technique Detail

```
1. GetSystemMetrics(SM_CXVIRTUALSCREEN / SM_CYVIRTUALSCREEN)
   → full virtual desktop dimensions (multi-monitor aware)

2. GetWindowDC(GetDesktopWindow()) → screen device context

3. CreateCompatibleDC + CreateCompatibleBitmap + BitBlt(SRCCOPY)
   → copy screen pixels to off-screen bitmap

4. GetDIBits → read pixel data (BGRA) into ctypes buffer

5. Pure Python PNG encoder (zlib + struct):
   - Convert BGRA → RGB per scanline
   - Build PNG header, IHDR, IDAT (zlib-compressed), IEND chunks

6. Chunked upload to Mythic (download protocol, is_screenshot: true)
   → appears in Mythic Screenshots tab
```

## MITRE ATT&CK Mapping

- **T1113** — Screen Capture

## Notes

- Captures the entire virtual desktop (all monitors combined).
- PNG encoding uses only Python stdlib (`zlib`, `struct`) — no Pillow or external image library.
- GDI capture uses only standard Windows DLLs (`user32.dll`, `gdi32.dll`) — no pywin32.
- Transfer is chunked (default 51200 bytes/chunk); can be stopped with `jobkill`.
- Result appears in Mythic's **Screenshots** tab (not just Files).

---

## Resumo em Português (PT-BR)

Captura a tela completa no Windows e envia para o Mythic como PNG. Implementado inteiramente com **ctypes puro** — sem dependências externas (`pywin32` ou `Pillow`) no target.

### Fluxo
1. Obtém dimensões da tela virtual via `GetSystemMetrics` (suporte a múltiplos monitores)
2. Captura pixels via `BitBlt`/`GetDIBits` com `user32.dll`/`gdi32.dll` direto
3. Converte BGRA→RGB e codifica PNG internamente com `zlib`+`struct` (sem Pillow)
4. Envia em chunks para o Mythic com flag `is_screenshot: true`

O resultado aparece na aba **Screenshots** do Mythic.
