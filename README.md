# General info
This ESP32 (esp-idf) library provides an integration with RC522 module. It's forked from [here](https://github.com/abobija/esp-idf-rc522). Some inspiration was taken from [Arduino rfid library](https://github.com/miguelbalboa/rfid). 

## What works?
- get UID (4, 7, or 10 bytes) from the tag
- determine type of tag - only for some MIFARE and NTAG tags
- dump MIFARE classic (1K / 4K) content alongside with access bits
- dump NTAG213/NTAG215/NTAG216 content
- writing to Mifare Classic tag

## What does not work / not implemented?
- detect card using IRQ ping (instead of active polling) - all my attempts to make it work failed
- operations with Value blocks (decrement / increment / restore / transfer / ...)
- no proper collision handling (it treated as any other error) 

## Other notes
- for NTAG / Mifare it uses "default" password only - but it's easy to change it

## References
- [MFRC522 datasheet](https://www.nxp.com/docs/en/data-sheet/MFRC522.pdf)
- [Mifare Classic 1K datasheet](https://www.mouser.com/datasheet/2/302/MF1S503x-89574.pdf)
- [Mifare Classic 4K datasheet](https://www.mouser.com/datasheet/2/302/MF1S703x-91210.pdf)
- [Mifare Ultralight datasheet](https://www.mouser.com/datasheet/2/302/MF0ICU1-51926.pdf)
- [Mifare type identification procedure](https://www.nxp.com/docs/en/application-note/AN10833.pdf)
- [NTAG213/215/216 datasheet](https://www.mouser.com/datasheet/2/302/NTAG213_215_216-1127325.pdf)

## ESP32 connection
| ESP32    | RC522 | Comment |
|----------|-------|---------|
| IO22     | SDA   |         |
| IO19     | SCK   |         |
| IO23     | MOSI  |         |
| IO25     | MISO  |         |
| IO33     | IRQ   | (not used / does not work)        |
| GND      | GND   |         |
| 3v3      | 3v3   |         |

# Author
Denis Elkin [linkedin](https://www.linkedin.com/in/denis-elkin-4b31a71a/)

Forked from [abobija](https://github.com/abobija/esp-idf-rc522)

# License
[MIT](LICENSE)