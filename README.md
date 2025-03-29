# RCFS-Engine
Tool for understanding and extracting RCFS Engine archive files from "1953 - KGB Unleashed" AKA "Phobos 1953"

Contributions to clean the code, improve the tool, or add new tools fully accepted and appreciated.

The file `filenames.txt` is critical for operation as filenames are not stored inside RCFS archives but are required for file decryption.
If this file is missing or a filename hash does not match any record in this file the output will instead show the filename hash and crypted data and will skip extraction of the resource.

## Desired Changes
* File stream extraction without intermediary array or with only small strip buffer array. TOC doesn't need to be streamed.
* RCFS DAT file creation (In theory the game, after loading all 0 record DAT files, should pass all file reads to extracted file paths allowing for easy modding.)
* Move archive file logic to own class

## File Format
Note: All hashes are prefixed with a `DWORD` string length.
All strings are capitalized and path separators are backslashes (\\).
All values are little endian.

*This structure has not been double checked, please refer to code and if errors found fix the below structures*

### RCFS Dat File
```js
0x000 DWORD Magic = 'RCFS'
0x004 DWORD Version = 1 // not checked
0x008 QWORD Unknown // not used, might be vestigial from SFFS FileCount
// -- Start AES encryption 1
// Key  = SHA256 of archive filename
// IV   = MD5 of archive filename
// Mode = CBC (XOR cascades)
0x010 DWORD RecordCount // Can read as unsigned QWORD, count of records
0x014 DWORD Pad
0x018 DWORD Size // Can read as unsigned QWORD, whole archive file's size
0x01C DWORD Pad
0x020 STRCT Record[]
// -- End AES encryption 1
```

### Record Structure
```js
0x000 BYTE FilenameMD5[16] // MD5 of filename, need pre-knowledge of filenames to match
// Start AES encryption 2 (nested)
// Key  = SHA256 of reversed record filename
// IV   = {0}
// Mode = ECB (Only 1 block so no XOR to cascade)
// Pad  = None
0x010 DWORD Offset // Can read as unsigned QWORD, offset of file contents start
0x014 DWORD Pad
0x018 DWORD Length // Can read as unsigned QWORD, length of file contents
0x01C DWORD Pad
// -- End AES encryption 2
```

### File Data
* Align read the nearest AES block size (16 byte) boundary
* Read full length of file up to next boundary + 1 extra block
* Remove alignment padding for decrypted data
* XOR each AES block (16 bytes) by file offset as a 16 byte number (or rather simply the first QWORD of the block)
```js
// Start AES encryption 2 (not nested)
// Key  = SHA256 of reversed record filename
// IV   = {0} ( manually XOR the file offset for each block)
// Mode = ECB
// Pad  = None
0x000 BYTE Data[]
// -- End AES encryption 2
```